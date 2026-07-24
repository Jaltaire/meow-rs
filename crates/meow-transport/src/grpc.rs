//! gRPC (gun) transport layer.
//!
//! Implements the "gun" protocol used by VLESS/VMess over gRPC:
//! a minimal gRPC-over-HTTP/2 framing that wraps each payload in a single
//! proto field-1 length-delimited bytes message, then applies the standard
//! gRPC 5-byte length-prefix framing.
//!
//! # Wire format
//!
//! For each write of `payload` bytes:
//! ```text
//! gRPC frame header (5 bytes):
//!   byte[0]     = 0x00          — no compression (always; compressed=true rejected)
//!   bytes[1..5] = BE32(inner_len) — big-endian length of the inner protobuf message
//! Inner protobuf message (inner_len bytes):
//!   0x0A              — proto field 1, wire type 2 (length-delimited bytes)
//!   uleb128(payload_len) — varint-encoded byte count of payload
//!   payload           — the raw application-layer bytes
//! ```
//!
//! upstream: transport/gun/gun.go (xray-core)
//! No tonic, no prost — framing is hand-rolled per ADR-0001 §3.
//!
//! # HTTP/2 request headers
//!
//! `:method: POST`
//! `:path: /{service_name}/Tun`  (NOT `/Send` or `/Recv` — upstream uses `Tun`)
//! `content-type: application/grpc`
//! `te: trailers`

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{Result, Stream, Transport, TransportError};

// ─── Public types ─────────────────────────────────────────────────────────────

/// Configuration for the gRPC (gun) transport layer.
#[derive(Debug, Clone)]
pub struct GrpcConfig {
    /// gRPC service name — used to build the `:path` pseudo-header as
    /// `/{service_name}/Tun`.
    ///
    /// upstream: `grpc-service-name` YAML key; default `"GunService"`.
    pub service_name: String,

    /// HTTP/2 `:authority` pseudo-header value (i.e. the virtual host).
    ///
    /// Upstream hard-codes `"localhost"` when no explicit authority is configured.
    /// We expose it as a configurable field so VLESS / VMess adapters can pass the
    /// outbound server name here instead of leaving it as "localhost".
    ///
    /// task #70: pre-VLESS hardening — must be set before gRPC-over-VLESS lands.
    pub authority: String,

    pub secure: bool,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            service_name: "GunService".into(),
            authority: "localhost".into(),
            secure: false,
        }
    }
}

// ─── GrpcLayer ────────────────────────────────────────────────────────────────

/// Transport layer that wraps an inner stream with gRPC (gun) framing over HTTP/2.
pub struct GrpcLayer {
    config: GrpcConfig,
}

impl GrpcLayer {
    /// Create a `GrpcLayer` from the given configuration.
    pub fn new(config: GrpcConfig) -> Self {
        Self { config }
    }
}

fn build_request(config: &GrpcConfig) -> Result<http::Request<()>> {
    let path = format!("/{}/Tun", config.service_name);
    let scheme = if config.secure { "https" } else { "http" };
    http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("{scheme}://{}{}", config.authority, path))
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header(http::header::USER_AGENT, "grpc-rust/meow-transport")
        .header("te", "trailers")
        .body(())
        .map_err(|error| TransportError::Config(format!("grpc: invalid request config: {error}")))
}

#[async_trait]
impl Transport for GrpcLayer {
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        // Build and validate the request before opening the h2 connection.
        // Invalid service names or authorities are configuration errors, not
        // transport-handshake failures.
        let request = build_request(&self.config)?;

        // Perform the HTTP/2 client handshake over the inner stream.
        let (mut h2, conn) = h2::client::handshake(inner)
            .await
            .map_err(|e| TransportError::Grpc(e.to_string()))?;

        // Drive the connection in a background task.  The connection future
        // must be polled continuously to process h2 control frames (SETTINGS,
        // WINDOW_UPDATE, PING, etc.).
        tokio::spawn(async move {
            let _ = conn.await;
        });

        // Open the h2 stream.  `end_of_stream = false` — we will stream data.
        let (response_future, send_stream) = h2
            .send_request(request, false)
            .map_err(|e| TransportError::Grpc(e.to_string()))?;

        Ok(Box::new(GunStream::new(send_stream, response_future)))
    }
}

// ─── Gun framing (pure functions) ────────────────────────────────────────────

/// Encode `payload` into a gun gRPC frame.
///
/// Wire format: `[0x00][BE32(inner_len)][0x0A][uleb128(payload.len())][payload]`
///
/// upstream: `transport/gun/gun.go` — `WriteBytes` / `sendData`
pub fn encode_gun_frame(payload: &[u8]) -> Vec<u8> {
    let varint = encode_varint(payload.len() as u64);
    // inner = [0x0A] + varint(payload_len) + payload
    let inner_len = 1 + varint.len() + payload.len();
    let mut buf = Vec::with_capacity(5 + inner_len);
    // gRPC 5-byte frame header
    buf.push(0x00); // no compression
    let n = inner_len as u32;
    buf.push((n >> 24) as u8);
    buf.push((n >> 16) as u8);
    buf.push((n >> 8) as u8);
    buf.push(n as u8);
    // inner protobuf message
    buf.push(0x0A); // field 1, wire type 2 (length-delimited bytes)
    buf.extend_from_slice(&varint);
    buf.extend_from_slice(payload);
    buf
}

/// Decode a complete gun gRPC frame, returning the payload bytes slice.
///
/// `frame` must be a slice containing exactly one complete frame
/// (5-byte header + inner).  Returns `Err` if malformed.
///
/// upstream: `transport/gun/gun.go` — `ReadBytes` / `recvData`
pub fn decode_gun_frame(frame: &[u8]) -> std::result::Result<&[u8], TransportError> {
    if frame.len() < 5 {
        return Err(TransportError::Grpc(
            "frame too short for 5-byte header".into(),
        ));
    }
    if frame[0] != 0x00 {
        return Err(TransportError::Grpc(format!(
            "grpc: compressed messages not supported (compression flag = {:#04x})",
            frame[0]
        )));
    }
    let inner_len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
    if frame.len() < 5 + inner_len {
        return Err(TransportError::Grpc(format!(
            "grpc: frame body truncated (need {} bytes, have {})",
            5 + inner_len,
            frame.len()
        )));
    }
    let inner = &frame[5..5 + inner_len];
    if inner.is_empty() || inner[0] != 0x0A {
        return Err(TransportError::Grpc(format!(
            "grpc: expected proto field tag 0x0A at inner[0], got {:#04x}",
            inner.first().copied().unwrap_or(0)
        )));
    }
    let (payload_len, varint_consumed) =
        decode_varint(&inner[1..]).map_err(TransportError::Grpc)?;
    let payload_start = 1 + varint_consumed;
    let payload_len: usize = payload_len.try_into().map_err(|_| {
        TransportError::Grpc(format!(
            "grpc: payload length {payload_len} does not fit in usize"
        ))
    })?;
    let payload_end = payload_start.checked_add(payload_len).ok_or_else(|| {
        TransportError::Grpc(format!(
            "grpc: payload length overflow (start {payload_start}, len {payload_len})"
        ))
    })?;
    if inner.len() < payload_end {
        return Err(TransportError::Grpc(format!(
            "grpc: payload truncated in inner (need {} bytes, have {})",
            payload_end,
            inner.len()
        )));
    }
    Ok(&inner[payload_start..payload_end])
}

/// Encode `n` as an unsigned LEB-128 (protobuf varint).
fn encode_varint(mut n: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4);
    loop {
        let mut byte = (n & 0x7F) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80; // more bytes follow
        }
        buf.push(byte);
        if n == 0 {
            break;
        }
    }
    buf
}

/// Decode an unsigned LEB-128 varint from `src`.
/// Returns `(value, bytes_consumed)` or `Err` on overflow / truncation.
fn decode_varint(src: &[u8]) -> std::result::Result<(u64, usize), String> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in src.iter().enumerate() {
        if shift >= 64 {
            return Err("grpc varint overflow".into());
        }
        value |= ((byte & 0x7F) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    Err("grpc varint truncated".into())
}

// ─── GunStream ────────────────────────────────────────────────────────────────

/// Maximum accepted gun-frame inner length (16 MiB).
///
/// `inner_len` arrives on the wire as an attacker-controlled BE32 (up to
/// ~4 GiB) and [`GunStream::poll_read`] buffers a frame in `pending_frame`
/// until it is complete. Without this cap a malicious/compromised upstream can
/// declare a giant frame and trickle bytes to drive unbounded heap growth — a
/// memory-exhaustion DoS (h2 flow-control does not bound it because every chunk
/// eagerly releases receive-window capacity). 16 MiB sits far above any
/// realistic relay frame while bounding worst-case in-flight buffering per
/// connection. Mirrors the WebSocket `max_frame_size` cap in `ws.rs`.
const MAX_GUN_FRAME_LEN: usize = 16 * 1024 * 1024;

/// A bidirectional gRPC-framed stream over a single h2 request/response pair.
struct GunStream {
    send: h2::SendStream<Bytes>,
    response: Option<h2::client::ResponseFuture>,
    recv: Option<h2::RecvStream>,
    data_finished: bool,
    read_finished: bool,
    /// Decoded payload bytes from the most-recently parsed gun frame.
    read_buf: Bytes,
    /// Raw h2 DATA bytes accumulating across multiple `poll_data` calls until
    /// a complete gun frame (5-byte header + inner) is assembled.
    pending_frame: Vec<u8>,
    /// Pre-encoded gun frame stashed while we wait for send capacity.
    /// Set on the first `poll_write` call for a given buf; cleared when
    /// `send_data` succeeds.  This ensures `reserve_capacity` is called
    /// exactly once per logical write.
    pending_write: Option<Bytes>,
}

impl GunStream {
    fn new(send: h2::SendStream<Bytes>, response: h2::client::ResponseFuture) -> Self {
        Self {
            send,
            response: Some(response),
            recv: None,
            data_finished: false,
            read_finished: false,
            read_buf: Bytes::new(),
            pending_frame: Vec::new(),
            pending_write: None,
        }
    }
}

fn grpc_status_error(headers: &http::HeaderMap) -> io::Result<()> {
    let Some(value) = headers.get("grpc-status") else {
        return Ok(());
    };
    let status = value.to_str().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("grpc: invalid grpc-status header: {error}"),
        )
    })?;
    if status == "0" {
        return Ok(());
    }
    let message = headers
        .get("grpc-message")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("The server did not provide a gRPC error message.");
    Err(io::Error::other(format!(
        "grpc: server returned status {status}. {message}"
    )))
}

impl AsyncRead for GunStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            if this.read_finished {
                return Poll::Ready(Ok(()));
            }

            if this.recv.is_none() {
                let response = this
                    .response
                    .as_mut()
                    .expect("The gRPC response future must exist until it resolves.");
                match Pin::new(response).poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        this.response = None;
                        this.read_finished = true;
                        return Poll::Ready(Err(io::Error::other(error)));
                    }
                    Poll::Ready(Ok(response)) => {
                        this.response = None;
                        if !response.status().is_success() {
                            this.read_finished = true;
                            return Poll::Ready(Err(io::Error::other(format!(
                                "grpc: server returned HTTP status {}.",
                                response.status()
                            ))));
                        }
                        if let Err(error) = grpc_status_error(response.headers()) {
                            this.read_finished = true;
                            return Poll::Ready(Err(error));
                        }
                        this.read_finished = response.headers().contains_key("grpc-status");
                        this.recv = Some(response.into_body());
                        continue;
                    }
                }
            }

            // ── Drain any decoded payload from the current frame ──────────────
            if !this.read_buf.is_empty() {
                let n = this.read_buf.len().min(buf.remaining());
                buf.put_slice(&this.read_buf[..n]);
                let _ = this.read_buf.split_to(n);
                return Poll::Ready(Ok(()));
            }

            // ── Check if pending_frame contains a complete gun frame ───────────
            if this.pending_frame.len() >= 5 {
                let inner_len = u32::from_be_bytes([
                    this.pending_frame[1],
                    this.pending_frame[2],
                    this.pending_frame[3],
                    this.pending_frame[4],
                ]) as usize;
                // Reject oversize frames up front (DoS guard). Checked on
                // `inner_len` itself — not `5 + inner_len` — to avoid usize
                // overflow on 32-bit targets where `5 + u32::MAX` would wrap.
                if inner_len > MAX_GUN_FRAME_LEN {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "grpc: frame inner_len {inner_len} exceeds cap {MAX_GUN_FRAME_LEN}"
                        ),
                    )));
                }
                let frame_len = 5 + inner_len;

                if this.pending_frame.len() >= frame_len {
                    // Drain exactly one frame.
                    let frame: Vec<u8> = this.pending_frame.drain(..frame_len).collect();
                    match decode_gun_frame(&frame) {
                        Ok(payload) => {
                            this.read_buf = Bytes::copy_from_slice(payload);
                            continue; // loop → drain read_buf
                        }
                        Err(e) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                e.to_string(),
                            )));
                        }
                    }
                }

                // Incomplete frame, but the gun header already told us the
                // full length: reserve it once instead of letting the
                // extend_from_slice below regrow the Vec repeatedly for
                // large frames (bounded by MAX_GUN_FRAME_LEN).
                this.pending_frame
                    .reserve(frame_len - this.pending_frame.len());
            }

            let recv = this
                .recv
                .as_mut()
                .expect("The gRPC response stream must exist after the response resolves.");
            if this.data_finished {
                if !this.pending_frame.is_empty() {
                    this.read_finished = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "grpc: the server closed with {} bytes of an incomplete frame.",
                            this.pending_frame.len()
                        ),
                    )));
                }
                return match recv.poll_trailers(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        this.read_finished = true;
                        Poll::Ready(Err(io::Error::other(error)))
                    }
                    Poll::Ready(Ok(Some(trailers))) => match grpc_status_error(&trailers) {
                        Ok(()) => {
                            this.read_finished = true;
                            Poll::Ready(Ok(()))
                        }
                        Err(error) => {
                            this.read_finished = true;
                            Poll::Ready(Err(error))
                        }
                    },
                    Poll::Ready(Ok(None)) => {
                        this.read_finished = true;
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "grpc: the server closed the stream without trailers.",
                        )))
                    }
                };
            }

            // ── Need more bytes from the h2 DATA stream ───────────────────────
            match recv.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    this.data_finished = true;
                }
                Poll::Ready(Some(Err(error))) => {
                    this.read_finished = true;
                    return Poll::Ready(Err(io::Error::other(error)));
                }
                Poll::Ready(Some(Ok(bytes))) => {
                    // Release flow-control window back to the sender.
                    let _ = recv.flow_control().release_capacity(bytes.len());
                    this.pending_frame.extend_from_slice(&bytes);
                    // loop → re-check pending_frame for a complete frame
                }
            }
        }
    }
}

impl AsyncWrite for GunStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // Encode buf into a gun frame exactly once per logical write.
        // If pending_write is already set, a previous poll returned Pending;
        // capacity has been reserved — don't encode or reserve again.
        if this.pending_write.is_none() {
            let encoded = Bytes::from(encode_gun_frame(buf));
            this.send.reserve_capacity(encoded.len());
            this.pending_write = Some(encoded);
        }

        // Wait for the h2 send window to open.
        match this.send.poll_capacity(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                this.pending_write = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "grpc: h2 send stream closed",
                )))
            }
            Poll::Ready(Some(Err(e))) => {
                this.pending_write = None;
                Poll::Ready(Err(io::Error::other(e)))
            }
            Poll::Ready(Some(Ok(_capacity))) => {
                // Capacity granted — send the frame.
                let encoded = this.pending_write.take().expect("set above");
                this.send
                    .send_data(encoded, false)
                    .map_err(io::Error::other)?;
                Poll::Ready(Ok(buf.len()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // h2 DATA frames are pushed into the h2 connection immediately on
        // send_data; there is no write-side buffer to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Send empty DATA+EOS to signal end of the request stream.
        this.send
            .send_data(Bytes::new(), true)
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(()))
    }
}

impl Unpin for GunStream {}

#[cfg(test)]
mod tests {
    use super::{GrpcConfig, build_request, grpc_status_error};

    #[test]
    fn request_matches_plaintext_and_secure_grpc_metadata() {
        let plaintext = build_request(&GrpcConfig {
            service_name: String::new(),
            authority: "127.0.0.1:8080".into(),
            secure: false,
        })
        .expect("The plaintext gRPC request should be valid.");
        assert_eq!(plaintext.uri().scheme_str(), Some("http"));
        assert_eq!(
            plaintext.uri().authority().map(|value| value.as_str()),
            Some("127.0.0.1:8080")
        );
        assert_eq!(plaintext.uri().path(), "//Tun");
        assert_eq!(
            plaintext
                .headers()
                .get(http::header::USER_AGENT)
                .and_then(|value| value.to_str().ok()),
            Some("grpc-rust/meow-transport")
        );

        let secure = build_request(&GrpcConfig {
            secure: true,
            ..GrpcConfig::default()
        })
        .expect("The secure gRPC request should be valid.");
        assert_eq!(secure.uri().scheme_str(), Some("https"));
        assert_eq!(secure.uri().path(), "/GunService/Tun");
    }

    #[test]
    fn grpc_status_accepts_absent_and_success_statuses() {
        let absent = http::HeaderMap::new();
        grpc_status_error(&absent).expect("An absent initial gRPC status should be accepted.");

        let mut success = http::HeaderMap::new();
        success.insert("grpc-status", http::HeaderValue::from_static("0"));
        grpc_status_error(&success).expect("A successful gRPC status should be accepted.");
    }

    #[test]
    fn grpc_status_reports_server_messages_and_invalid_values() {
        let mut with_message = http::HeaderMap::new();
        with_message.insert("grpc-status", http::HeaderValue::from_static("12"));
        with_message.insert(
            "grpc-message",
            http::HeaderValue::from_static("The method is unavailable."),
        );
        let error = grpc_status_error(&with_message)
            .expect_err("A nonzero gRPC status should be rejected.");
        assert!(error.to_string().contains("The method is unavailable."));

        let mut without_message = http::HeaderMap::new();
        without_message.insert("grpc-status", http::HeaderValue::from_static("13"));
        let error = grpc_status_error(&without_message)
            .expect_err("A nonzero gRPC status should be rejected.");
        assert!(
            error
                .to_string()
                .contains("The server did not provide a gRPC error message.")
        );

        let mut invalid = http::HeaderMap::new();
        invalid.insert(
            "grpc-status",
            http::HeaderValue::from_bytes(&[0xff])
                .expect("The invalid text header value should still be representable."),
        );
        let error =
            grpc_status_error(&invalid).expect_err("An invalid gRPC status should be rejected.");
        assert!(error.to_string().contains("invalid grpc-status header"));
    }
}
