//! Integration tests for the gRPC (gun) transport layer.
//!
//! All tests require `--features grpc` (enforced via `required-features` in
//! Cargo.toml).
//!
//! # Test plan coverage
//!
//! | ID | Description |
//! |----|-------------|
//! | A  | `grpc_framing_matches_upstream` — byte-for-byte wire format comparison with a hand-rolled reference encoder |
//! | B  | `grpc_service_name_in_path` — `:path` must be `/{service_name}/Tun` |
//! | C  | `grpc_content_type_header` — request must carry `content-type: application/grpc` |
//! | D  | `grpc_round_trip` — 4 MiB loopback echo through a real h2 server |

mod support;

use std::time::Duration;

use bytes::Bytes;
use meow_transport::Transport;
use meow_transport::TransportError;
use meow_transport::grpc::{GrpcConfig, GrpcLayer, decode_gun_frame, encode_gun_frame};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use support::loopback::spawn_grpc_server;

#[derive(Clone, Copy)]
enum TerminalResponse {
    HttpFailure,
    InitialFailure,
    InitialSuccess,
    TrailerFailure,
    MissingTrailers,
    TruncatedFrame,
}

async fn spawn_terminal_server(response: TerminalResponse) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("The terminal gRPC server should bind.");
    let address = listener
        .local_addr()
        .expect("The terminal gRPC server should have an address.");
    tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("The terminal gRPC server should accept a connection.");
        let mut connection = h2::server::handshake(stream)
            .await
            .expect("The terminal gRPC HTTP/2 handshake should succeed.");
        let (_, mut sender) = connection
            .accept()
            .await
            .expect("The terminal gRPC request should arrive.")
            .expect("The terminal gRPC request should be valid.");
        tokio::spawn(async move { while connection.accept().await.is_some() {} });

        match response {
            TerminalResponse::HttpFailure => {
                let response = http::Response::builder()
                    .status(421)
                    .body(())
                    .expect("The HTTP failure response should be valid.");
                sender
                    .send_response(response, true)
                    .expect("The HTTP failure response should be sent.");
            }
            TerminalResponse::InitialFailure | TerminalResponse::InitialSuccess => {
                let status = match response {
                    TerminalResponse::InitialFailure => "12",
                    TerminalResponse::InitialSuccess => "0",
                    _ => unreachable!(),
                };
                let response = http::Response::builder()
                    .status(200)
                    .header("grpc-status", status)
                    .header("grpc-message", "The initial status ended the request.")
                    .body(())
                    .expect("The initial gRPC status response should be valid.");
                sender
                    .send_response(response, true)
                    .expect("The initial gRPC status response should be sent.");
            }
            TerminalResponse::TrailerFailure => {
                let response = http::Response::builder()
                    .status(200)
                    .body(())
                    .expect("The trailer failure response should be valid.");
                let mut body = sender
                    .send_response(response, false)
                    .expect("The trailer failure response should be sent.");
                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", http::HeaderValue::from_static("13"));
                trailers.insert(
                    "grpc-message",
                    http::HeaderValue::from_static("The trailer ended the request."),
                );
                body.send_trailers(trailers)
                    .expect("The failure trailers should be sent.");
            }
            TerminalResponse::MissingTrailers | TerminalResponse::TruncatedFrame => {
                let http_response = http::Response::builder()
                    .status(200)
                    .body(())
                    .expect("The incomplete gRPC response should be valid.");
                let mut body = sender
                    .send_response(http_response, false)
                    .expect("The incomplete gRPC response should be sent.");
                let data = match response {
                    TerminalResponse::MissingTrailers => Bytes::new(),
                    TerminalResponse::TruncatedFrame => Bytes::from_static(&[0x00, 0x00]),
                    _ => unreachable!(),
                };
                body.send_data(data, true)
                    .expect("The incomplete gRPC body should be sent.");
            }
        }
    });
    address
}

async fn terminal_stream(response: TerminalResponse) -> Box<dyn meow_transport::Stream> {
    let address = spawn_terminal_server(response).await;
    let tcp = tokio::net::TcpStream::connect(address)
        .await
        .expect("The terminal gRPC client should connect.");
    GrpcLayer::new(GrpcConfig::default())
        .connect(Box::new(tcp))
        .await
        .expect("The gRPC transport should return before the response arrives.")
}

async fn assert_grpc_config_error(config: GrpcConfig, expected: &str) {
    let (client, _server) = tokio::io::duplex(64);
    let layer = GrpcLayer::new(config);
    let Err(err) = layer.connect(Box::new(client)).await else {
        panic!("invalid grpc config unexpectedly connected");
    };
    match err {
        TransportError::Config(msg) => {
            assert!(
                msg.contains(expected),
                "expected config error containing {expected:?}, got: {msg}"
            );
        }
        other => panic!("expected TransportError::Config, got: {other:?}"),
    }
}

// ─── A: Reference framing test ────────────────────────────────────────────────
//
// Port of `transport/gun/gun.go`'s WriteBytes / ReadBytes encoding.
// Asserts byte-for-byte equality with a hand-rolled reference encoder so any
// upstream divergence is caught before it silently breaks VMess/VLESS-over-gRPC.

/// Encode `payload` using the spec definition:
///   `[0x00] [BE32(inner_len)] [0x0A] [uleb128(payload.len())] [payload]`
///
/// This is the independent reference framer — it intentionally does NOT call
/// `encode_gun_frame`; the two results are compared byte-for-byte in the test.
fn reference_encode(payload: &[u8]) -> Vec<u8> {
    // uleb128(n): emit 7 bits per byte, MSB = 1 if more bytes follow.
    fn uleb128(mut n: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(4);
        loop {
            let mut byte = (n & 0x7F) as u8;
            n >>= 7;
            if n != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if n == 0 {
                break;
            }
        }
        out
    }

    let varint = uleb128(payload.len() as u64);
    // inner = [field-1 tag] + varint + payload
    let inner_len = 1 + varint.len() + payload.len();

    let mut buf = Vec::with_capacity(5 + inner_len);
    buf.push(0x00u8); // grpc compression flag — always 0x00 (no compression)
    let n = inner_len as u32;
    buf.extend_from_slice(&n.to_be_bytes()); // BE32(inner_len)
    buf.push(0x0Au8); // proto field 1, wire type 2 (length-delimited)
    buf.extend_from_slice(&varint); // uleb128(payload.len())
    buf.extend_from_slice(payload); // raw payload bytes
    buf
}

/// A: `grpc_framing_matches_upstream`
///
/// Encodes a 1 KiB payload with both the crate's `encode_gun_frame` and the
/// inline reference framer, then asserts byte-for-byte equality.  Also verifies
/// that `decode_gun_frame` fully recovers the original payload.
#[test]
fn grpc_framing_matches_upstream() {
    // 1 KiB of a repeating pattern — non-zero to catch off-by-one in byte slices.
    let payload: Vec<u8> = (0u8..=255).cycle().take(1024).collect();

    let encoded = encode_gun_frame(&payload);
    let reference = reference_encode(&payload);

    assert_eq!(
        encoded, reference,
        "encode_gun_frame must match reference wire format byte-for-byte"
    );

    // Spot-check the 5-byte gRPC header manually.
    // uleb128(1024): 1024 = 0b10000000000; first 7 bits = 0 (need more) → 0x80;
    // next 7 bits = 8 → 0x08.  inner_len = 1 + 2 + 1024 = 1027 = 0x403.
    assert_eq!(encoded[0], 0x00, "compression flag must be 0x00");
    assert_eq!(
        &encoded[1..5],
        &[0x00, 0x00, 0x04, 0x03],
        "BE32(inner_len=1027)"
    );
    assert_eq!(encoded[5], 0x0A, "proto field tag must be 0x0A");
    assert_eq!(&encoded[6..8], &[0x80, 0x08], "uleb128(1024)");
    assert_eq!(&encoded[8..], payload.as_slice(), "payload bytes");

    // decode must be the exact inverse.
    let decoded = decode_gun_frame(&encoded).expect("decode_gun_frame");
    assert_eq!(decoded, payload.as_slice());
}

#[test]
fn grpc_decode_rejects_payload_length_overflow_without_panic() {
    let mut frame = vec![
        0x00, // compression flag
        0x00, 0x00, 0x00, 0x0B, // inner_len = tag + 10-byte varint
        0x0A, // proto field 1, wire type 2
    ];
    frame.extend_from_slice(&[0xFF; 9]);
    frame.push(0x01); // uleb128(u64::MAX)

    let err = decode_gun_frame(&frame).expect_err("overflowing payload length must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("payload length") && msg.contains("overflow"),
        "expected payload length overflow error, got: {msg}"
    );
}

#[tokio::test]
async fn grpc_rejects_invalid_request_config_before_handshake() {
    assert_grpc_config_error(
        GrpcConfig {
            service_name: "Bad Service".into(),
            ..Default::default()
        },
        "invalid request config",
    )
    .await;

    assert_grpc_config_error(
        GrpcConfig {
            authority: "bad authority".into(),
            ..Default::default()
        },
        "invalid request config",
    )
    .await;
}

// ─── B: Service name in :path ─────────────────────────────────────────────────

/// B: `grpc_service_name_in_path`
///
/// Connects via `GrpcLayer` with `service_name = "TestService"` and asserts
/// that the h2 request `:path` is `/TestService/Tun`.
///
/// upstream: transport/gun/gun.go — path is always `/{svcName}/Tun`.
#[tokio::test]
async fn grpc_service_name_in_path() {
    let (addr, info_rx) = spawn_grpc_server().await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");

    let layer = GrpcLayer::new(GrpcConfig {
        service_name: "TestService".into(),
        ..Default::default()
    });
    let _stream = layer.connect(Box::new(tcp)).await.expect("grpc connect");

    let info = tokio::time::timeout(Duration::from_secs(5), info_rx)
        .await
        .expect("timeout waiting for grpc conn info")
        .expect("server dropped sender");

    assert_eq!(
        info.path, "/TestService/Tun",
        ":path must be /<service_name>/Tun"
    );
}

// ─── C: content-type header ───────────────────────────────────────────────────

/// C: `grpc_content_type_header`
///
/// Connects via `GrpcLayer` and asserts that the HTTP/2 request carries
/// `content-type: application/grpc`.
///
/// upstream: transport/gun/gun.go — sends `application/grpc`, not
/// `application/grpc+proto` (no codec suffix).
#[tokio::test]
async fn grpc_content_type_header() {
    let (addr, info_rx) = spawn_grpc_server().await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");

    let layer = GrpcLayer::new(GrpcConfig::default());
    let _stream = layer.connect(Box::new(tcp)).await.expect("grpc connect");

    let info = tokio::time::timeout(Duration::from_secs(5), info_rx)
        .await
        .expect("timeout waiting for grpc conn info")
        .expect("server dropped sender");

    assert_eq!(
        info.content_type.as_deref(),
        Some("application/grpc"),
        "content-type must be application/grpc (no codec suffix)"
    );
}

// ─── D: Round-trip 4 MiB ─────────────────────────────────────────────────────

/// D: `grpc_round_trip`
///
/// Streams 4 MiB through a real h2 echo server via `GrpcLayer`.  The write
/// and read halves run concurrently (via `tokio::io::split`) to avoid
/// deadlocking on h2 flow-control.  Asserts the received bytes equal the
/// sent bytes.
#[tokio::test]
async fn grpc_round_trip() {
    const PAYLOAD_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

    let (addr, _info_rx) = spawn_grpc_server().await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");

    let layer = GrpcLayer::new(GrpcConfig::default());
    let gun_stream = layer.connect(Box::new(tcp)).await.expect("grpc connect");

    // Split the GunStream so write and read can proceed concurrently.
    let (mut read_half, mut write_half) = tokio::io::split(gun_stream);

    // Build the send buffer: repeating 0x00..=0xFF pattern.
    let send_buf: Vec<u8> = (0u8..=255).cycle().take(PAYLOAD_SIZE).collect();
    let send_clone = send_buf.clone();

    // Write task: send all bytes, then signal EOF.
    let write_task = tokio::spawn(async move {
        write_half
            .write_all(&send_clone)
            .await
            .expect("write_all 4 MiB");
        write_half.shutdown().await.expect("shutdown");
    });

    // Read until EOF (server echoes back the gun-framed data, GunStream decodes).
    let mut recv_buf = Vec::with_capacity(PAYLOAD_SIZE);
    read_half
        .read_to_end(&mut recv_buf)
        .await
        .expect("read_to_end 4 MiB");

    write_task.await.expect("write task");

    assert_eq!(
        recv_buf.len(),
        PAYLOAD_SIZE,
        "received byte count must match sent byte count"
    );
    assert_eq!(recv_buf, send_buf, "round-trip bytes must be identical");
}

#[tokio::test]
async fn grpc_reports_http_initial_and_trailer_failures() {
    for (response, expected) in [
        (TerminalResponse::HttpFailure, "HTTP status 421"),
        (TerminalResponse::InitialFailure, "initial status ended"),
        (TerminalResponse::TrailerFailure, "trailer ended"),
    ] {
        let mut stream = terminal_stream(response).await;
        let mut byte = [0u8; 1];
        let error = stream
            .read(&mut byte)
            .await
            .expect_err("The terminal gRPC failure should be reported.");
        assert!(
            error.to_string().contains(expected),
            "The gRPC error should contain {expected:?}, but it was {error:?}."
        );
        assert_eq!(
            stream
                .read(&mut byte)
                .await
                .expect("A repeated read after a terminal gRPC error should produce EOF."),
            0
        );
    }
}

#[tokio::test]
async fn grpc_accepts_a_successful_initial_status() {
    let mut stream = terminal_stream(TerminalResponse::InitialSuccess).await;
    let mut byte = [0u8; 1];
    assert_eq!(
        stream
            .read(&mut byte)
            .await
            .expect("The successful initial gRPC status should produce EOF."),
        0
    );
    assert_eq!(
        stream
            .read(&mut byte)
            .await
            .expect("Repeated reads after gRPC EOF should remain at EOF."),
        0
    );
}

#[tokio::test]
async fn grpc_rejects_missing_trailers_and_truncated_frames() {
    for response in [
        TerminalResponse::MissingTrailers,
        TerminalResponse::TruncatedFrame,
    ] {
        let mut stream = terminal_stream(response).await;
        let mut byte = [0u8; 1];
        stream
            .read(&mut byte)
            .await
            .expect_err("The incomplete gRPC response should be rejected.");
        assert_eq!(
            stream
                .read(&mut byte)
                .await
                .expect("A repeated read after an incomplete response should produce EOF."),
            0
        );
    }
}
