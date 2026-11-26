use hbb_common::{
    protobuf::Message,
    rendezvous_proto::{
        rendezvous_message, RegionalRelayDirectory, RegionalRelaySample, RendezvousMessage,
    },
    ResultType,
};
use sodiumoxide::crypto::sign;

const MAX_RELAYS: usize = 8;
const MAX_CONNECT_MS: u32 = 10_000;

pub(crate) fn enabled(configured: &[String]) -> bool {
    configured
        .first()
        .is_some_and(|first| configured.iter().any(|relay| relay != first))
}

pub(crate) fn directory(configured: &[String], healthy: &[String]) -> RegionalRelayDirectory {
    let mut directory = RegionalRelayDirectory::new();
    for relay in configured {
        if relay.len() <= 255 && healthy.contains(relay) && !directory.relay_servers.contains(relay)
        {
            directory.relay_servers.push(relay.clone());
            if directory.relay_servers.len() == MAX_RELAYS {
                break;
            }
        }
    }
    directory
}

pub(crate) fn ranked(
    configured: &[String],
    healthy: &[String],
    samples: &[RegionalRelaySample],
) -> Vec<RegionalRelaySample> {
    if samples.is_empty() || samples.len() > MAX_RELAYS || !enabled(configured) {
        return Vec::new();
    }
    let mut ranked: Vec<_> = directory(configured, healthy)
        .relay_servers
        .into_iter()
        .filter_map(|relay| {
            let connect_ms = samples
                .iter()
                .filter(|s| s.relay_server == relay && (1..=MAX_CONNECT_MS).contains(&s.connect_ms))
                .map(|s| s.connect_ms)
                .min()?;
            Some(RegionalRelaySample {
                relay_server: relay,
                connect_ms,
                ..Default::default()
            })
        })
        .collect();
    ranked.sort_by_key(|s| s.connect_ms);
    ranked
}

pub(crate) fn sign_directory(
    mut directory: RegionalRelayDirectory,
    nonce: u64,
    sk: &sign::SecretKey,
) -> ResultType<RegionalRelayDirectory> {
    directory.nonce = nonce;
    let mut data = b"RustDesk regional relay directory v1\0".to_vec();
    data.extend(directory.write_to_bytes()?);
    directory.signature = sign::sign_detached(&data, sk).to_bytes().to_vec().into();
    Ok(directory)
}

pub(crate) fn fit_udp_offer(message: &mut RendezvousMessage) {
    // Optional rankings must not fragment the peer's SDP or mapping tickets.
    while match &message.union {
        Some(rendezvous_message::Union::PunchHole(offer)) => !offer.relay_samples.is_empty(),
        Some(rendezvous_message::Union::FetchLocalAddr(offer)) => !offer.relay_samples.is_empty(),
        _ => false,
    } && message.compute_size() > 1200
    {
        match &mut message.union {
            Some(rendezvous_message::Union::PunchHole(offer)) => {
                offer.relay_samples.pop();
            }
            Some(rendezvous_message::Union::FetchLocalAddr(offer)) => {
                offer.relay_samples.pop();
            }
            _ => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(server: &str, ms: u32) -> RegionalRelaySample {
        RegionalRelaySample {
            relay_server: server.into(),
            connect_ms: ms,
            ..Default::default()
        }
    }

    #[test]
    fn only_current_configured_healthy_nodes_can_win_a_measured_request() {
        let configured = ["sz:21117", "fz:21117", "tyo:21117", "fz:21117"].map(String::from);
        let healthy = ["tyo:21117", "sz:21117", "removed:21117"].map(String::from);
        let samples = [
            sample("sz:21117", 120),
            sample("removed:21117", 1),
            sample("fz:21117", 2),
            sample("tyo:21117", 0),
            sample("tyo:21117", 33),
        ];
        assert_eq!(
            directory(&configured, &healthy).relay_servers,
            ["sz:21117", "tyo:21117"]
        );
        assert_eq!(
            ranked(&configured, &healthy, &samples),
            [sample("tyo:21117", 33), sample("sz:21117", 120)]
        );
        assert!(ranked(&configured, &healthy, &[]).is_empty());
        assert!(ranked(
            &configured,
            &healthy,
            &vec![sample("sz:21117", 3); MAX_RELAYS + 1]
        )
        .is_empty());
    }
}
