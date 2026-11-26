use hbb_common::{
    bytes::Bytes,
    futures_util::{SinkExt, StreamExt},
    protobuf::Message,
    rendezvous_proto::{RegionalRelayPing, RendezvousMessage, RequestRelay},
    tcp::FramedStream,
    tokio::{
        self, io,
        net::TcpStream,
        time::{sleep, timeout},
    },
};
use quinn::{crypto::rustls::QuicClientConfig, Endpoint};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime},
    CertificateError, DigitallySignedStruct, Error, SignatureScheme,
};
use std::{
    fs,
    io::ErrorKind,
    net::{IpAddr, SocketAddr, TcpListener, UdpSocket},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};
use tempfile::TempDir;
use tokio_tungstenite::tungstenite::Message as WsMessage;

const SNI: &str = "relay.rustdesk.invalid";
const ALPN: &[u8] = b"rustdesk-relay/1";
const SPKI: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

#[derive(Debug)]
struct Pin([u8; 32]);

impl ServerCertVerifier for Pin {
    fn requires_raw_public_keys(&self) -> bool {
        true
    }

    fn verify_server_cert(
        &self,
        received: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let expected = [SPKI.as_slice(), self.0.as_slice()].concat();
        if intermediates.is_empty() && received.as_ref() == expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("Expected TLS 1.3".to_owned()))
    }

    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        key: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature_with_raw_key(
            msg,
            &SubjectPublicKeyInfoDer::from(key.as_ref()),
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

struct Relay {
    child: Child,
    _state: TempDir,
    address: SocketAddr,
    pin: [u8; 32],
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Relay {
    async fn start(direct_only: bool, blocked: bool) -> Self {
        let state = tempfile::tempdir().unwrap();
        sodiumoxide::init().unwrap();
        let (public, private) = sodiumoxide::crypto::sign::gen_keypair();
        fs::write(state.path().join("id_ed25519"), base64::encode(&private.0)).unwrap();
        fs::write(
            state.path().join("id_ed25519.pub"),
            base64::encode(public.0),
        )
        .unwrap();

        let ip: IpAddr = std::env::var("RUSTDESK_QUIC_TEST_BIND")
            .unwrap_or_else(|_| String::from("127.0.0.1"))
            .parse()
            .unwrap();
        if blocked {
            fs::write(state.path().join("blocklist.txt"), format!("{ip}\n")).unwrap();
        }
        let address = loop {
            let preflight = TcpListener::bind((ip, 0)).unwrap();
            let addr = preflight.local_addr().unwrap();
            if let Some(ws) = addr.port().checked_add(2) {
                if TcpListener::bind((ip, ws)).is_ok() && UdpSocket::bind(addr).is_ok() {
                    break addr;
                }
            }
        };
        let mut relay = Self {
            child: Command::new(env!("CARGO_BIN_EXE_hbbr"))
                .args([
                    "-b",
                    &address.ip().to_string(),
                    "-p",
                    &address.port().to_string(),
                    "-k",
                    "_",
                ])
                .current_dir(state.path())
                .env("RUSTDESK_RELAY_QUIC", "Y")
                .env("DIRECT_ONLY", if direct_only { "Y" } else { "N" })
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
            _state: state,
            address,
            pin: public.0,
        };
        timeout(Duration::from_secs(5), async {
            loop {
                assert!(
                    relay.child.try_wait().unwrap().is_none(),
                    "hbbr exited during startup"
                );
                if TcpStream::connect(address).await.is_ok() {
                    break;
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
        relay
    }

    fn endpoint(&self) -> Endpoint {
        Endpoint::client((self.address.ip(), 0).into()).unwrap()
    }

    async fn connect(
        &self,
        endpoint: &Endpoint,
        key: [u8; 32],
        alpn: &[u8],
        sni: &str,
    ) -> Result<quinn::Connection, quinn::ConnectionError> {
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pin(key)))
        .with_no_client_auth();
        tls.alpn_protocols = vec![alpn.to_vec()];
        let crypto = QuicClientConfig::try_from(tls).unwrap();
        let config = quinn::ClientConfig::new(Arc::new(crypto));
        endpoint
            .connect_with(config, self.address, sni)
            .unwrap()
            .await
    }

    async fn leg(&self, endpoint: &Endpoint) -> FramedStream {
        let connection = self.connect(endpoint, self.pin, ALPN, SNI).await.unwrap();
        let (send, recv) = connection.open_bi().await.unwrap();
        FramedStream::from(io::join(recv, send), self.address)
    }

    fn request(&self) -> RendezvousMessage {
        let mut msg = RendezvousMessage::new();
        msg.set_request_relay(RequestRelay {
            uuid: uuid::Uuid::new_v4().to_string(),
            licence_key: base64::encode(self.pin),
            ..Default::default()
        });
        msg
    }
}

async fn read_raw(stream: &mut FramedStream, expected: &[u8]) {
    let mut bytes = Vec::new();
    while bytes.len() < expected.len() {
        bytes.extend(stream.next().await.unwrap().unwrap());
    }
    assert_eq!(bytes.as_slice(), expected);
}

async fn raw_pair(relay: &Relay, left: &mut FramedStream, right: &mut FramedStream) {
    let request = relay.request();
    left.send(&request).await.unwrap();
    right.send(&request).await.unwrap();
    left.set_raw();
    right.set_raw();
    let to_right = vec![0x60; 192 * 1024];
    let to_left = vec![0x9f; 192 * 1024];
    left.send_bytes(Bytes::copy_from_slice(&to_right))
        .await
        .unwrap();
    right
        .send_bytes(Bytes::copy_from_slice(&to_left))
        .await
        .unwrap();
    read_raw(left, &to_left).await;
    read_raw(right, &to_right).await;
}

#[tokio::test]
async fn regional_relay_ping_reaches_the_pinned_quic_endpoint() {
    let relay = Relay::start(false, false).await;
    let endpoint = relay.endpoint();
    let mut leg = relay.leg(&endpoint).await;
    let mut ping = RendezvousMessage::new();
    ping.set_regional_relay_ping(RegionalRelayPing { nonce: 0xaba0_cafe_1949, ..Default::default() });
    leg.send(&ping).await.unwrap();
    let reply = leg.next_timeout(3000).await.unwrap().unwrap();
    assert_eq!(RendezvousMessage::parse_from_bytes(&reply).unwrap(), ping);
}

#[tokio::test]
async fn authenticated_quic_relays_with_quic_websocket_and_legacy_tcp() {
    let relay = Relay::start(false, false).await;
    let endpoint = relay.endpoint();
    timeout(Duration::from_secs(15), async {
        let mut quic = relay.leg(&endpoint).await;
        let mut other_quic = relay.leg(&endpoint).await;
        raw_pair(&relay, &mut quic, &mut other_quic).await;

        let mut quic = relay.leg(&endpoint).await;
        let ws_address = SocketAddr::new(relay.address.ip(), relay.address.port() + 2);
        let tcp = TcpStream::connect(ws_address).await.unwrap();
        let (mut websocket, _) =
            tokio_tungstenite::client_async(format!("ws://{ws_address}/"), tcp)
                .await
                .unwrap();
        let request = relay.request();
        quic.send(&request).await.unwrap();
        websocket
            .send(WsMessage::Binary(request.write_to_bytes().unwrap().into()))
            .await
            .unwrap();
        let to_ws = Bytes::from(vec![0x77; 192 * 1024]);
        let to_quic = Bytes::from(vec![0xb2; 192 * 1024]);
        quic.send_bytes(to_ws.clone()).await.unwrap();
        websocket
            .send(WsMessage::Binary(to_quic.clone()))
            .await
            .unwrap();
        assert_eq!(websocket.next().await.unwrap().unwrap().into_data(), to_ws);
        assert_eq!(quic.next().await.unwrap().unwrap().as_ref(), to_quic);

        // hbbr deliberately reserves loopback native TCP for administration.
        // The Linux network-namespace test supplies a non-loopback address here.
        if !relay.address.ip().is_loopback() {
            for quic_first in [true, false] {
                let mut quic = relay.leg(&endpoint).await;
                let tcp = TcpStream::connect(relay.address).await.unwrap();
                let mut legacy = FramedStream::from(tcp, relay.address);
                if quic_first {
                    raw_pair(&relay, &mut quic, &mut legacy).await;
                } else {
                    raw_pair(&relay, &mut legacy, &mut quic).await;
                }
            }
            eprintln!("Validated QUIC/TCP with either leg first");
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn independent_relays_accept_only_their_own_transport_and_pairing_key() {
    let first = Relay::start(false, false).await;
    let second = Relay::start(false, false).await;
    assert_ne!(first.pin, second.pin);
    timeout(Duration::from_secs(15), async {
        for (relay, other) in [(&first, &second), (&second, &first)] {
            let endpoint = relay.endpoint();
            assert!(relay.connect(&endpoint, other.pin, ALPN, SNI).await.is_err());
            let mut wrong = relay.leg(&endpoint).await;
            wrong.send(&other.request()).await.unwrap();
            assert!(!matches!(wrong.next().await, Some(Ok(_))));
            let mut left = relay.leg(&endpoint).await;
            let mut right = relay.leg(&endpoint).await;
            raw_pair(relay, &mut left, &mut right).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rejects_wrong_pin_sni_alpn_and_does_not_route_udp_to_the_console() {
    let relay = Relay::start(false, false).await;
    let endpoint = relay.endpoint();
    timeout(Duration::from_secs(15), async {
        let mut wrong = relay.pin;
        wrong[0] ^= 1;
        assert!(relay.connect(&endpoint, wrong, ALPN, SNI).await.is_err());
        assert!(relay
            .connect(&endpoint, relay.pin, ALPN, "wrong.rustdesk.invalid")
            .await
            .is_err());
        assert!(relay
            .connect(&endpoint, relay.pin, b"wrong-relay", SNI)
            .await
            .is_err());

        let connection = relay
            .connect(&endpoint, relay.pin, ALPN, SNI)
            .await
            .unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(b"h\n").await.unwrap();
        send.finish().unwrap();
        let response = recv.read_to_end(1024).await;
        assert!(response.as_ref().is_ok_and(Vec::is_empty) || response.is_err());

        let mut quic = relay.leg(&endpoint).await;
        let mut request = relay.request();
        request.mut_request_relay().licence_key = String::from("invalid");
        quic.send(&request).await.unwrap();
        let rejected = quic.next().await;
        assert!(
            rejected.is_none()
                || rejected.is_some_and(|result| {
                    result.is_err_and(|err| err.kind() != ErrorKind::TimedOut)
                })
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn blocklist_and_direct_only_deny_quic_handshake() {
    for (direct_only, blocked) in [(true, false), (false, true)] {
        let relay = Relay::start(direct_only, blocked).await;
        if direct_only {
            UdpSocket::bind(relay.address)
                .expect("DIRECT_ONLY must leave the UDP endpoint unbound");
        }
        let endpoint = relay.endpoint();
        let result = timeout(
            Duration::from_secs(1),
            relay.connect(&endpoint, relay.pin, ALPN, SNI),
        )
        .await;
        assert!(!matches!(result, Ok(Ok(_))));
    }
}
