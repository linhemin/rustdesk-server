use hbb_common::{
    bail,
    bytes::{Bytes, BytesMut},
    protobuf::Message as _,
    rendezvous_proto::{
        rendezvous_message, IceCandidate, KeyExchange, KxParams, RendezvousMessage,
    },
    tcp::{Encrypt, FramedStream, KxTranscript, KX_PARAMS_DOMAIN, KX_VERSION_LATEST},
    timeout,
    tokio::sync::mpsc,
    try_into_v4,
    ResultType,
};
use sodiumoxide::crypto::{box_, sign};
use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};

const MAX_ROUTES: usize = 512;
const MAX_ROUTES_PER_IP: usize = 12;
const ROUTE_LIFETIME: Duration = Duration::from_secs(45);
const SDP_LIMIT: usize = 1100; // Keep the UDP downlink close to the stock client's 1024-byte budget.
const CANDIDATE_LIMIT: usize = 896;
const CANDIDATES_PER_DIRECTION: usize = 80;
pub(crate) const FRAME_LIMIT: usize = 16 * 1024;
pub(crate) type Outbound = mpsc::Sender<RendezvousMessage>;

pub(crate) async fn begin_key_exchange(
    conn: &mut FramedStream,
    sk: &sign::SecretKey,
    allow_session_direct: bool,
    allow_p2p_feedback: bool,
) -> ResultType<Option<BytesMut>> {
    let (mut server_pk, server_sk) = box_::gen_keypair();
    server_pk.0[31] |= 0x80; // X25519 ignores this bit; RustDesk uses it to require signed params.
    let params = KxParams {
        pk: Bytes::copy_from_slice(&server_pk.0),
        version: KX_VERSION_LATEST,
        allow_session_direct,
        allow_p2p_feedback,
        udp_mapping_observers: if allow_session_direct {
            crate::mapping_observer::configured()
        } else {
            Vec::new()
        },
        ..Default::default()
    };
    let mut signed = KX_PARAMS_DOMAIN.to_vec();
    signed.extend(params.write_to_bytes()?);
    let mut message = RendezvousMessage::new();
    message.set_key_exchange(KeyExchange {
        keys: vec![sign::sign(&server_pk.0, sk).into()],
        version: KX_VERSION_LATEST,
        signed_params: sign::sign(&signed, sk).into(),
        ..Default::default()
    });
    timeout(3000, conn.send(&message)).await??;
    let Some(first) = timeout(5000, conn.next()).await?.transpose()? else {
        return Ok(None);
    };
    let message = RendezvousMessage::parse_from_bytes(&first)?;
    let Some(rendezvous_message::Union::KeyExchange(exchange)) = message.union else {
        return Ok(Some(first));
    };
    if exchange.version != KX_VERSION_LATEST || exchange.keys.len() != 2 {
        bail!("unsupported secure rendezvous key exchange");
    }
    let client_pk = &exchange.keys[0];
    let key = Encrypt::decode(&exchange.keys[1], client_pk, &server_sk)?;
    conn.set_key_split(
        key,
        false,
        &KxTranscript {
            initiator_pk: client_pk,
            responder_pk: &server_pk.0,
            advertised: KX_VERSION_LATEST,
            picked: exchange.version,
        },
    )?;
    Ok(None)
}

fn direct_candidate(raw: &str) -> bool {
    let mut fields = raw.split_ascii_whitespace();
    !raw.contains(['\r', '\n'])
        && fields.nth(6) == Some("typ")
        && matches!(fields.next(), Some("host" | "srflx" | "prflx"))
}

pub(crate) fn description_key(endpoint: &str, kind: &str, direct_only: bool) -> Option<String> {
    if endpoint.len() > SDP_LIMIT {
        return None;
    }
    let decoded = base64::decode(endpoint.strip_prefix("webrtc://")?).ok()?;
    let description: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    if description.get("type")?.as_str()? != kind {
        return None;
    }
    let sdp = description.get("sdp")?.as_str()?;
    if direct_only && (description.get("ice_policy")?.as_str()? != "direct_only"
        || sdp.lines().filter_map(|line| line.trim().strip_prefix("a=candidate:"))
            .any(|candidate| !direct_candidate(candidate))) {
        return None;
    }
    let fingerprint = sdp.lines()
        .find_map(|line| line.strip_prefix("a=fingerprint:"))?;
    let digest = fingerprint.strip_prefix("sha-256 ")?;
    if digest.len() == 95
        && digest
            .split(':')
            .all(|byte| byte.len() == 2 && byte.as_bytes().iter().all(u8::is_ascii_hexdigit))
    {
        Some(fingerprint.to_owned())
    } else {
        None
    }
}

#[derive(Default)]
pub(crate) struct Routes {
    entries: HashMap<Bytes, Route>,
}

pub(crate) struct Route {
    pub controller: SocketAddr,
    pub peer: SocketAddr,
    pub peer_id: String,
    pub session_key: String,
    pub sender: Outbound,
    pub direct_only: bool,
    pub lan_udp: bool,
    pub udp_reply_token: Option<[u8; 16]>,
    expires: Instant,
    offer_retries: usize,
    controller_candidates: usize,
    peer_candidates: usize,
}

impl Routes {
    pub(crate) fn start(
        &mut self,
        route: Bytes,
        controller: SocketAddr,
        peer: SocketAddr,
        peer_id: String,
        session_key: String,
        sender: Outbound,
    ) -> bool {
        let now = Instant::now();
        self.entries
            .retain(|_, entry| entry.expires > now && !entry.sender.is_closed());
        if self.entries.contains_key(&route)
            || self.entries.len() >= MAX_ROUTES
            || self
                .entries
                .values()
                .filter(|entry| entry.controller.ip() == controller.ip())
                .count()
                >= MAX_ROUTES_PER_IP
        {
            return false;
        }
        self.entries.insert(
            route,
            Route {
                controller,
                peer,
                peer_id,
                session_key,
                sender,
                direct_only: false,
                udp_reply_token: None,
                lan_udp: false,
                expires: now + ROUTE_LIFETIME,
                offer_retries: 0,
                controller_candidates: 0,
                peer_candidates: 0,
            },
        );
        true
    }

    pub(crate) fn get(&mut self, route: &Bytes) -> Option<&mut Route> {
        let entry = self.entries.get_mut(route)?;
        (Instant::now() < entry.expires && !entry.sender.is_closed()).then_some(entry)
    }

    pub(crate) fn remove(&mut self, route: &Bytes) {
        self.entries.remove(route);
    }
}

impl Route {
    pub(crate) fn retry_offer(&mut self) -> bool {
        if self.offer_retries >= 2 {
            return false;
        }
        self.offer_retries += 1;
        true
    }

    pub(crate) fn accepts_answer(&self, from: SocketAddr, id: &str) -> bool {
        try_into_v4(self.peer).ip() == from.ip() && self.peer_id == id
    }

    pub(crate) fn allows_candidate(&mut self, candidate: &IceCandidate, from_peer: bool) -> bool {
        if self.session_key.is_empty()
            || candidate.session_key != self.session_key
            || candidate.candidate.is_empty()
            || candidate.candidate.len() > CANDIDATE_LIMIT
        {
            return false;
        }
        if self.direct_only && !serde_json::from_str::<serde_json::Value>(&candidate.candidate)
            .ok().and_then(|ice| ice.get("candidate")?.as_str()
                .map(|raw| raw.is_empty() || direct_candidate(raw)))
            .unwrap_or(false)
        {
            return false;
        }
        let count = if from_peer {
            &mut self.peer_candidates
        } else {
            &mut self.controller_candidates
        };
        if *count >= CANDIDATES_PER_DIRECTION {
            return false;
        }
        *count += 1;
        true
    }
}
