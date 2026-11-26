use hbb_common::{
    protobuf::{Message, MessageField},
    rendezvous_proto::{
        rendezvous_message::Union, RegionalRelaySample, RendezvousMessage, SessionRelayList,
    },
};
use std::net::IpAddr;

pub(crate) type Offer = MessageField<SessionRelayList>;
pub(crate) const UNAVAILABLE: &str = "No mutually configured relay";
const MAX_RELAYS: usize = 8;

fn endpoint(value: &str) -> bool {
    if value.len() > 255
        || value.is_empty()
        || !value.bytes().all(|c| c.is_ascii_graphic())
        || value.contains(['@', '?', '#', '\\'])
    {
        return false;
    }
    if value.starts_with("ws://") || value.starts_with("wss://") {
        return reqwest::Url::parse(value)
            .is_ok_and(|url| url.host().is_some() && url.port() != Some(0));
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    if !port.bytes().all(|c| c.is_ascii_digit()) || !port.parse::<u16>().is_ok_and(|p| p > 0) {
        return false;
    }
    if let Some(ip) = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return matches!(ip.parse(), Ok(IpAddr::V6(_)));
    }
    host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}

pub(crate) fn bounded(list: &mut Offer) {
    if let Some(list) = list.as_mut() {
        list.special_fields = Default::default();
        if !list.packed_hashes.is_empty()
            || list.servers.len() > MAX_RELAYS
            || !list.servers.iter().all(|s| endpoint(s))
        {
            list.servers.clear();
            list.packed_hashes.clear();
        }
    }
}

pub(crate) fn fit_udp_offer(msg: &mut RendezvousMessage) {
    if msg.compute_size() <= 1200 {
        return;
    }
    let list = match msg.union.as_mut() {
        Some(Union::PunchHole(p)) => p.session_relays.as_mut(),
        Some(Union::FetchLocalAddr(p)) => p.session_relays.as_mut(),
        Some(Union::RequestRelay(p)) => p.session_relays.as_mut(),
        _ => None,
    };
    if let Some(list) = list {
        let mut hashes = Vec::with_capacity(list.servers.len() * 16);
        for server in &list.servers {
            hashes.extend_from_slice(
                &sodiumoxide::crypto::hash::sha256::hash(server.as_bytes()).0[..16],
            );
        }
        if hashes.len() < list.servers.iter().map(|s| s.len() + 2).sum() {
            list.servers.clear();
            list.packed_hashes = hashes.into();
        }
    }
}

pub(crate) fn samples(
    list: &SessionRelayList,
    samples: &[RegionalRelaySample],
) -> Vec<RegionalRelaySample> {
    if samples.len() > MAX_RELAYS {
        return Vec::new();
    }
    samples
        .iter()
        .filter(|s| list.servers.contains(&s.relay_server) && (1..=10_000).contains(&s.connect_ms))
        .map(|s| RegionalRelaySample {
            relay_server: s.relay_server.clone(),
            connect_ms: s.connect_ms,
            ..Default::default()
        })
        .collect()
}

pub(crate) fn response(mut msg: RendezvousMessage, offered: &Offer) -> RendezvousMessage {
    let (answer, chosen) = match msg.union.as_mut() {
        Some(Union::PunchHoleResponse(p)) => (&mut p.session_relays, &mut p.relay_server),
        Some(Union::RelayResponse(r)) => (&mut r.session_relays, &mut r.relay_server),
        _ => return msg,
    };
    let Some(original) = offered.as_ref() else {
        answer.clear();
        return msg;
    };
    bounded(answer);
    let intersection = answer.mut_or_insert_default();
    intersection
        .servers
        .retain(|s| original.servers.contains(s));
    if !intersection.servers.contains(chosen) {
        chosen.clear();
        if let Some(Union::RelayResponse(r)) = msg.union.as_mut() {
            r.uuid.clear();
            r.prefer_relay_start = false;
            if r.refuse_reason.is_empty()
                && r.webrtc_sdp_answer.is_empty()
                && r.socket_addr_v6.is_empty()
            {
                r.refuse_reason = UNAVAILABLE.into();
            }
        }
    }
    msg
}
