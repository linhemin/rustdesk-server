use async_speed_limit::Limiter;
use hbb_common::{
    anyhow::{ensure, Context},
    log,
    tcp::FramedStream,
    timeout,
    tokio::{
        self,
        io::{AsyncRead, AsyncWrite, ReadBuf},
        sync::{OwnedSemaphorePermit, Semaphore},
    },
    ResultType,
};
use quinn::{
    crypto::rustls::QuicServerConfig, Endpoint, EndpointConfig, Incoming, TokioRuntime,
    TransportConfig, VarInt,
};
use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    server::{AlwaysResolvesServerRawPublicKeys, ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    fs, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use zeroize::Zeroizing;

const ALPN: &[u8] = b"rustdesk-relay/1";
const SERVER_NAME: &str = "relay.rustdesk.invalid";
const MAX_HANDSHAKES: usize = 64;
const MAX_CONNECTIONS: usize = 256;
const MAX_PENDING_INITIALS: usize = 128;
const HANDSHAKE_TIMEOUT_MS: u64 = 8_000;
const STREAM_TIMEOUT_MS: u64 = 5_000;
const RECEIVE_WINDOW: u32 = 2 << 20;
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

#[derive(Debug)]
struct RelayKeyResolver(AlwaysResolvesServerRawPublicKeys);

impl ResolvesServerCert for RelayKeyResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if hello.server_name() == Some(SERVER_NAME) {
            self.0.resolve(hello)
        } else {
            None
        }
    }

    fn only_raw_public_keys(&self) -> bool {
        self.0.only_raw_public_keys()
    }
}

fn load_identity() -> ResultType<CertifiedKey> {
    let contents =
        Zeroizing::new(fs::read_to_string("id_ed25519").context("Read existing relay identity")?);
    let secret =
        Zeroizing::new(base64::decode(contents.trim()).context("Invalid relay identity encoding")?);
    let public = fs::read_to_string("id_ed25519.pub").context("Read existing relay public key")?;
    let public = base64::decode(public.trim()).context("Invalid relay public key encoding")?;
    certified_key(&secret, &public)
}

fn certified_key(secret: &[u8], public: &[u8]) -> ResultType<CertifiedKey> {
    ensure!(
        secret.len() == 64 && public.len() == 32,
        "Invalid Ed25519 relay identity length"
    );
    ensure!(
        &secret[32..] == public,
        "Relay identity differs from the shared public key"
    );

    let mut der = Zeroizing::new([0; 48]);
    der[..16].copy_from_slice(&ED25519_PKCS8_PREFIX);
    der[16..].copy_from_slice(&secret[..32]);
    let private = PrivatePkcs8KeyDer::from(der.as_slice()).into();
    let signing_key = rustls::crypto::ring::sign::any_eddsa_type(&private)?;
    let mut spki = ED25519_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(public);
    ensure!(
        signing_key.public_key().as_deref() == Some(spki.as_slice()),
        "Ed25519 relay seed differs from the shared public key"
    );
    Ok(CertifiedKey::new(
        vec![CertificateDer::from(spki)],
        signing_key,
    ))
}

fn server_config(identity: CertifiedKey) -> ResultType<quinn::ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let resolver = RelayKeyResolver(AlwaysResolvesServerRawPublicKeys::new(Arc::new(identity)));
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.send_tls13_tickets = 0;

    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(1u32.into())
        .max_concurrent_uni_streams(0u32.into())
        .max_idle_timeout(Some(Duration::from_secs(60).try_into()?))
        .stream_receive_window(RECEIVE_WINDOW.into())
        .receive_window(RECEIVE_WINDOW.into())
        .send_window(RECEIVE_WINDOW.into())
        .datagram_receive_buffer_size(None)
        .datagram_send_buffer_size(0);

    let mut server = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    server.transport_config(Arc::new(transport));
    server
        .migration(false)
        .max_incoming(MAX_PENDING_INITIALS)
        .incoming_buffer_size(32 << 10)
        .incoming_buffer_size_total(2 << 20);
    Ok(server)
}

fn bind_udp(addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if addr.ip() == Ipv6Addr::UNSPECIFIED {
        socket.set_only_v6(false)?;
    }
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

pub(super) struct QuicRelay {
    endpoint: Endpoint,
    handshakes: Arc<Semaphore>,
    connections: Arc<Semaphore>,
}

impl QuicRelay {
    pub(super) fn listen(bind_addr: Option<IpAddr>, port: u16) -> ResultType<Self> {
        let config = server_config(load_identity()?)?;
        let socket = match bind_addr {
            Some(ip) => bind_udp(SocketAddr::new(ip, port))?,
            None => bind_udp((Ipv6Addr::UNSPECIFIED, port).into())
                .or_else(|_| bind_udp((Ipv4Addr::UNSPECIFIED, port).into()))?,
        };
        let mut endpoint_config = EndpointConfig::default();
        endpoint_config.supported_versions(vec![1]);
        let endpoint = Endpoint::new(
            endpoint_config,
            Some(config),
            socket,
            Arc::new(TokioRuntime),
        )?;
        log::info!("Listening on QUIC/UDP :{}", port);
        Ok(Self::new(endpoint))
    }

    fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            handshakes: Arc::new(Semaphore::new(MAX_HANDSHAKES)),
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        }
    }

    pub(super) async fn accept(&self) -> Option<Incoming> {
        self.endpoint.accept().await
    }

    pub(super) async fn dispatch(&self, incoming: Incoming, key: &str, limiter: &Limiter) {
        let addr = incoming.remote_address();
        if crate::common::direct_only_enabled() || super::relay_blocked(addr).await {
            incoming.ignore();
            return;
        }
        // Prove return reachability before allocating an application connection or TLS handshake.
        if !incoming.remote_address_validated() {
            let _ = incoming.retry();
            return;
        }
        let (Ok(handshake), Ok(slot)) = (
            self.handshakes.clone().try_acquire_owned(),
            self.connections.clone().try_acquire_owned(),
        ) else {
            incoming.refuse();
            return;
        };

        let Ok(connecting) = incoming.accept() else {
            return;
        };
        let key = key.to_owned();
        let limiter = limiter.clone();
        tokio::spawn(async move {
            let Ok(Ok(connection)) = timeout(HANDSHAKE_TIMEOUT_MS, connecting).await else {
                return;
            };
            let Ok(Ok((send, recv))) = timeout(STREAM_TIMEOUT_MS, connection.accept_bi()).await
            else {
                return;
            };
            drop(handshake);

            let addr = connection.remote_address();
            if crate::common::direct_only_enabled() || super::relay_blocked(addr).await {
                return;
            }
            connection.set_max_concurrent_bi_streams(VarInt::from_u32(0));
            let io = QuicStream {
                send,
                recv,
                _slot: slot,
            };
            // The next bytes always enter the ordinary relay request parser, including on loopback.
            super::make_pair_(FramedStream::from(io, addr), addr, &key, limiter, Some(&connection)).await;
        });
    }
}

struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    _slot: OwnedSemaphorePermit,
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}
