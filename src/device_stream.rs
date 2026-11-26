use crate::{
    peer::{PeerMap, MAX_PEER_ID_LEN},
    webrtc_signaling::Outbound,
};
use hbb_common::{
    anyhow::{anyhow, ensure, Context},
    bytes::Bytes,
    futures_util::{SinkExt, StreamExt},
    protobuf::Message,
    rendezvous_proto::{DeviceStreamProof, RegisterPk, RegisterPkResponse, RendezvousMessage},
    tcp::FramedStream,
    timeout,
    tokio::{
        self,
        net::TcpStream,
        sync::{mpsc, oneshot, Semaphore},
        time::Duration,
    },
    ResultType,
};
use sodiumoxide::crypto::sign;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio_tungstenite::{tungstenite::Message as WsMessage, WebSocketStream};

#[derive(Clone)]
pub(crate) struct Downlink {
    pub addr: SocketAddr,
    pub tx: Option<Outbound>,
    pub supports_session_relays: bool,
}

#[derive(Clone, Default)]
pub(crate) struct Registry(Arc<Mutex<HashMap<String, (Bytes, Downlink, oneshot::Sender<()>)>>>);

impl Registry {
    pub fn get(&self, id: &str, pk: &[u8]) -> Option<Downlink> {
        let entries = self.0.lock().unwrap();
        let (key, link, _) = entries.get(id)?;
        (key.as_ref() == pk && link.tx.as_ref().is_some_and(|tx| !tx.is_closed()))
            .then(|| link.clone())
    }

    pub fn revoke_changed_key(&self, id: &str, new_pk: &[u8]) {
        let mut entries = self.0.lock().unwrap();
        if entries
            .get(id)
            .is_some_and(|(pk, _, _)| pk.as_ref() != new_pk)
        {
            entries.remove(id);
        }
    }
}

struct Lease<'a> {
    registry: &'a Registry,
    id: String,
    sender: Outbound,
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        let mut entries = self.registry.0.lock().unwrap();
        if entries
            .get(&self.id)
            .and_then(|(_, link, _)| link.tx.as_ref())
            .is_some_and(|tx| tx.same_channel(&self.sender))
        {
            entries.remove(&self.id);
        }
    }
}

pub(crate) enum Wire {
    Tcp(FramedStream),
    Ws(WebSocketStream<TcpStream>),
}

impl Wire {
    async fn send(&mut self, message: &RendezvousMessage) -> ResultType<()> {
        match self {
            Self::Tcp(conn) => timeout(3000, conn.send(message)).await??,
            Self::Ws(conn) => {
                timeout(
                    3000,
                    conn.send(WsMessage::Binary(message.write_to_bytes()?.into())),
                )
                .await??
            }
        }
        Ok(())
    }

    async fn read(&mut self) -> ResultType<Vec<u8>> {
        match self {
            Self::Tcp(conn) => Ok(conn.next().await.context("Device stream closed")??.to_vec()),
            Self::Ws(conn) => loop {
                match conn.next().await.context("Device stream closed")?? {
                    WsMessage::Binary(data) => return Ok(data.to_vec()),
                    WsMessage::Ping(_) | WsMessage::Pong(_) => continue,
                    _ => return Err(anyhow!("Unexpected device stream frame")),
                }
            },
        }
    }
}

pub(crate) fn hello(bytes: &[u8]) -> Option<RegisterPk> {
    if bytes.len() > 1024 {
        return None;
    }
    match RendezvousMessage::parse_from_bytes(bytes).ok()?.union? {
        hbb_common::rendezvous_proto::rendezvous_message::Union::RegisterPk(r)
            if (6..=MAX_PEER_ID_LEN).contains(&r.id.len())
                && r.stream_nonce.len() == 32
                && r.pk.len() == 32 =>
        {
            Some(r)
        }
        _ => None,
    }
}

pub(crate) async fn serve(
    mut wire: Wire,
    request: RegisterPk,
    addr: SocketAddr,
    pm: &PeerMap,
    registry: &Registry,
    secret: &sign::SecretKey,
) -> ResultType<()> {
    static AUTH: Semaphore = Semaphore::const_new(64);
    let slot = AUTH.try_acquire()?;
    match &mut wire {
        Wire::Tcp(conn) => {
            conn.set_max_packet_length(1024);
        }
        Wire::Ws(conn) => conn.set_config(|c| {
            c.max_frame_size = Some(1024);
            c.max_message_size = Some(1024);
        }),
    }
    let operator = secret.public_key();
    let pk = sign::PublicKey::from_slice(&request.pk).context("Invalid device key")?;
    let nonce: &[u8; 32] = request.stream_nonce.as_ref().try_into()?;
    let mut challenge = [0; 32];
    sodiumoxide::randombytes::randombytes_into(&mut challenge);
    let transcript = |server| {
        hbb_common::device_stream::transcript(
            server,
            &operator.0,
            &pk.0,
            &request.id,
            nonce,
            &challenge,
        )
    };
    let mut msg = RendezvousMessage::new();
    msg.set_device_stream_proof(DeviceStreamProof {
        challenge: Bytes::copy_from_slice(&challenge),
        signature: sign::sign_detached(&transcript(true), secret)
            .to_bytes()
            .to_vec()
            .into(),
        ..Default::default()
    });
    wire.send(&msg).await?;
    let frame = timeout(4500, wire.read()).await??;
    ensure!(frame.len() <= 128, "Invalid device stream proof");
    let answer = RendezvousMessage::parse_from_bytes(&frame)?;
    ensure!(
        answer.has_device_stream_proof(),
        "Missing device stream proof"
    );
    let sig = sign::Signature::from_bytes(&answer.device_stream_proof().signature)
        .map_err(|_| anyhow!("Invalid device stream signature"))?;
    ensure!(
        sign::verify_detached(&sig, &transcript(false), &pk),
        "Invalid device stream proof"
    );
    let peer = pm
        .get(&request.id)
        .await
        .context("Device must already be registered")?;
    let registered = peer.read().await;
    ensure!(
        registered.pk == request.pk,
        "Device is not enrolled with this public key"
    );
    let (tx, mut rx) = mpsc::channel(32);
    let (replaced, mut stop) = oneshot::channel();
    {
        let mut entries = registry.0.lock().unwrap();
        ensure!(
            entries.len() < 4096 || entries.contains_key(&request.id),
            "Device stream limit reached"
        );
        entries.insert(
            request.id.clone(),
            (
                request.pk.clone(),
                Downlink {
                    addr,
                    tx: Some(tx.clone()),
                    supports_session_relays: request.supports_session_relays,
                },
                replaced,
            ),
        );
    }
    let _lease = Lease {
        registry,
        id: request.id,
        sender: tx,
    };
    drop(registered);
    drop(slot);
    msg.set_register_pk_response(RegisterPkResponse {
        keep_alive: 12,
        ..Default::default()
    });
    wire.send(&msg).await?;
    let mut heartbeat = tokio::time::interval(Duration::from_secs(8));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_ack = tokio::time::Instant::now();
    loop {
        tokio::select! {
            _ = &mut stop => return Ok(()),
            _ = heartbeat.tick() => {
                ensure!(last_ack.elapsed() < Duration::from_secs(18)
                    && peer.read().await.pk == request.pk, "Device stream expired");
                wire.send(&RendezvousMessage::new()).await?;
            }
            data = wire.read() => {
                ensure!(data?.is_empty(), "Unexpected control-channel command");
                last_ack = tokio::time::Instant::now();
            }
            Some(message) = rx.recv() => wire.send(&message).await?,
        }
    }
}
