//! Answer a padded STUN Binding request on the existing rendezvous UDP listener.
//! Replies go to the sender and never exceed the request's size.
use std::net::{IpAddr, SocketAddr};

const COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

// Bind supplementary candidates to endpoints recently observed by this hbbs.
fn receipt_tag(ip: IpAddr, prefix: &[u8]) -> sodiumoxide::crypto::auth::Tag {
    use sodiumoxide::crypto::auth;
    use std::sync::OnceLock;
    static KEY: OnceLock<auth::Key> = OnceLock::new();
    let mut message = match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    message.extend_from_slice(prefix);
    auth::authenticate(&message, KEY.get_or_init(auth::gen_key))
}

fn minute() -> u32 {
    (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_secs() / 60) as u32
}

pub(crate) fn verified_ports(tickets: &[u8], from: SocketAddr) -> Vec<u32> {
    if tickets.is_empty() || tickets.len() > 11 * 38 || tickets.len() % 38 != 0 {
        return Vec::new();
    }
    let ip = hbb_common::try_into_v4(from).ip();
    let now = minute();
    let mut ports = Vec::new();
    for ticket in tickets.chunks_exact(38) {
        let port = u32::from(u16::from_be_bytes([ticket[0], ticket[1]]));
        let issued = u32::from_be_bytes([ticket[2], ticket[3], ticket[4], ticket[5]]);
        if now.wrapping_sub(issued) <= 1 && port > 0 && !ports.contains(&port)
            && sodiumoxide::utils::memcmp(&receipt_tag(ip, &ticket[..6]).0, &ticket[6..]) {
            ports.push(port);
        }
    }
    ports
}

pub(crate) fn configured() -> Vec<String> {
    let mut observers = Vec::new();
    let list = std::env::var("RUSTDESK_UDP_MAPPING_OBSERVERS").unwrap_or_default();
    for value in list.split(',').take(16) {
        let Ok(addr) = value.trim().parse::<std::net::SocketAddrV4>() else {
            continue;
        };
        let ip = addr.ip();
        if addr.port() == 0
            || ip.is_unspecified()
            || ip.is_loopback()
            || ip.is_private()
            || ip.is_link_local()
            || ip.is_multicast()
            || ip.is_broadcast()
        {
            continue;
        }
        let endpoint = addr.to_string();
        if !observers.contains(&endpoint) {
            observers.push(endpoint);
        }
        if observers.len() == 4 {
            break;
        }
    }
    observers
}

/// A NAT shared with hbbs can preserve the port while exposing only the
/// inside address to hbbs. Advertise the operator's WAN address to WAN peers.
#[derive(Clone, Copy)]
pub(crate) struct SharedEgress {
    inside: ipnetwork::Ipv4Network,
    outside: std::net::Ipv4Addr,
}

impl SharedEgress {
    pub(crate) fn configured() -> Option<Self> {
        let value = std::env::var("RUSTDESK_UDP_SHARED_EGRESS").ok()?;
        let parsed = Self::parse(&value);
        if parsed.is_none() {
            hbb_common::log::warn!("Ignoring invalid RUSTDESK_UDP_SHARED_EGRESS (expected private CIDR=public IPv4)");
        }
        parsed
    }

    fn parse(value: &str) -> Option<Self> {
        let (inside, outside) = value.trim().split_once('=')?;
        let inside: ipnetwork::Ipv4Network = inside.parse().ok()?;
        let outside = outside.parse().ok()?;
        (inside.network().is_private() && inside.broadcast().is_private() && Self::public(outside))
            .then_some(Self { inside, outside })
    }

    fn public(ip: std::net::Ipv4Addr) -> bool {
        let [a, b, _, _] = ip.octets();
        a != 0 && a < 224 && !ip.is_private() && !ip.is_loopback() && !ip.is_link_local()
            && !ip.is_documentation() && !(a == 100 && (64..128).contains(&b))
            && !(a == 198 && (18..=19).contains(&b))
    }

    pub(crate) fn candidate(self, inside: SocketAddr, peer: SocketAddr) -> Option<SocketAddr> {
        let (SocketAddr::V4(src), SocketAddr::V4(dst)) =
            (hbb_common::try_into_v4(inside), hbb_common::try_into_v4(peer)) else { return None };
        (self.inside.contains(*src.ip()) && Self::public(*dst.ip()) && *dst.ip() != self.outside)
            .then(|| SocketAddr::from((self.outside, src.port())))
    }
}

pub(crate) fn is_stun(data: &[u8]) -> bool {
    data.len() >= 20 && data[0] & 0xc0 == 0 && data[4..8] == COOKIE
}

pub(crate) fn binding_reply(data: &[u8], peer: SocketAddr) -> Option<Vec<u8>> {
    if !is_stun(data)
        || data[..2] != [0, 1]
        || data.len() > 512
        || u16::from_be_bytes([data[2], data[3]]) as usize != data.len() - 20
    {
        return None;
    }
    let mut pos = 20;
    while pos < data.len() {
        let attr = data.get(pos..pos + 4)?;
        let kind = u16::from_be_bytes([attr[0], attr[1]]);
        // Only the discovery profile. In particular, ignore ICE checks, CHANGE-REQUEST,
        // RESPONSE-PORT and requests bearing credentials or an unchecked fingerprint.
        if !matches!(kind, 0x8022 | 0x0026) {
            return None;
        }
        let len = u16::from_be_bytes([attr[2], attr[3]]) as usize;
        pos += 4 + ((len + 3) & !3);
        if pos > data.len() {
            return None;
        }
    }
    let address = match peer.ip() {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    };
    let (family, ip) = match address {
        IpAddr::V4(ip) => (1, ip.octets().to_vec()),
        IpAddr::V6(ip) => (2, ip.octets().to_vec()),
    };
    let len = 28 + ip.len();
    if len > data.len() || peer.port() == 0 {
        return None;
    }
    let mut reply = Vec::with_capacity(len);
    reply.extend_from_slice(&[1, 1, 0, (len - 20) as u8]);
    reply.extend_from_slice(&data[4..20]);
    reply.extend_from_slice(&[0, 0x20, 0, (4 + ip.len()) as u8, 0, family]);
    reply.extend_from_slice(&(peer.port() ^ 0x2112).to_be_bytes());
    reply.extend(ip.iter().zip(&data[4..20]).map(|(a, b)| *a ^ *b));
    if data.len() == 96 && data[20..24] == [0, 0x26, 0, 72] && &data[24..32] == b"RD-PATH1" {
        let mut ticket = peer.port().to_be_bytes().to_vec();
        ticket.extend_from_slice(&minute().to_be_bytes());
        let tag = receipt_tag(address, &ticket);
        reply.extend_from_slice(&[0xc0, 0x51, 0, 38]);
        reply.extend_from_slice(&ticket);
        reply.extend_from_slice(&tag.0);
        reply.extend_from_slice(&[0, 0]);
        if &data[32..40] == b"RD-WIDE1" {
            reply.extend_from_slice(&[0xc0, 0x52, 0, 4, 0, 0, 0, 11]);
        }
        reply[3] = (reply.len() - 20) as u8;
    }
    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_egress_only_rewrites_the_configured_lan_for_a_wan_peer() {
        let policy = SharedEgress::parse("192.168.4.0/24=8.8.8.8").unwrap();
        let lan = "192.168.4.7:41003".parse().unwrap();
        let wan = "1.1.1.1:39436".parse().unwrap();
        assert_eq!(policy.candidate(lan, wan), Some("8.8.8.8:41003".parse().unwrap()));
        assert!(policy.candidate(wan, lan).is_none());
        assert!(policy.candidate(lan, lan).is_none());
        assert!(policy.candidate("192.168.5.4:41003".parse().unwrap(), wan).is_none());
        assert!(SharedEgress::parse("0.0.0.0/0=8.8.8.8").is_none());
    }

    fn request() -> Vec<u8> {
        let mut b = vec![0, 1, 0, 24];
        b.extend_from_slice(&COOKIE);
        b.extend_from_slice(b"test-round-1");
        b.extend_from_slice(&[0x80, 0x22, 0, 20]);
        b.extend_from_slice(b"RustDesk observation");
        b
    }

    #[test]
    fn same_transaction_encodes_actual_sender_and_family() {
        let req = request();
        let v4 = binding_reply(&req, "192.0.2.10:5077".parse().unwrap()).unwrap();
        assert_eq!(v4.len(), 32);
        assert_eq!(&v4[4..20], &req[4..20]);
        assert_eq!(&v4[24..26], &[0, 1]);
        assert_eq!(u16::from_be_bytes([v4[26], v4[27]]) ^ 0x2112, 5077);
        assert_eq!(
            v4[28..32]
                .iter()
                .zip(COOKIE)
                .map(|(a, b)| a ^ b)
                .collect::<Vec<_>>(),
            [192, 0, 2, 10]
        );
        assert_eq!(
            binding_reply(&req, "[::ffff:192.0.2.10]:5077".parse().unwrap()).unwrap(),
            v4
        );
        let v6 = binding_reply(&req, "[2001:db8::7]:19".parse().unwrap()).unwrap();
        assert_eq!(v6.len(), 44);
        assert_eq!(v6[25], 2);
        assert_eq!(
            v6[28..]
                .iter()
                .zip(&req[4..20])
                .map(|(a, b)| a ^ b)
                .collect::<Vec<_>>(),
            "2001:db8::7"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
    }

    #[test]
    fn wide_observation_is_opt_in_and_only_accepts_eleven_verified_ports() {
        let mut query = [0; 96];
        query[..8].copy_from_slice(&[0, 1, 0, 76, 0x21, 0x12, 0xa4, 0x42]);
        query[20..24].copy_from_slice(&[0, 0x26, 0, 72]);
        query[24..32].copy_from_slice(b"RD-PATH1");
        let mut source: SocketAddr = "192.0.2.10:45000".parse().unwrap();
        assert_eq!(binding_reply(&query, source).unwrap().len(), 76);
        query[32..40].copy_from_slice(b"RD-WIDE1");
        let mut tickets = Vec::new();
        for port in 45000..45011 {
            source.set_port(port);
            let reply = binding_reply(&query, source).unwrap();
            assert_eq!(&reply[76..], &[0xc0, 0x52, 0, 4, 0, 0, 0, 11]);
            tickets.extend_from_slice(&reply[36..74]);
        }
        assert_eq!(verified_ports(&tickets, source), (45000..45011).collect::<Vec<u32>>());
        tickets.extend_from_within(..38);
        assert!(verified_ports(&tickets, source).is_empty());
    }

    #[test]
    fn supplementary_candidate_requires_receipt_from_the_same_source() {
        let mut req = vec![0; 96];
        req[..8].copy_from_slice(&[0, 1, 0, 76, 0x21, 0x12, 0xa4, 0x42]);
        req[20..24].copy_from_slice(&[0, 0x26, 0, 72]);
        req[24..32].copy_from_slice(b"RD-PATH1");
        let source = "192.0.2.10:48721".parse().unwrap();
        let reply = binding_reply(&req, source).unwrap();
        assert!(reply.len() <= req.len());
        let mut ticket = reply[36..74].to_vec();
        assert_eq!(verified_ports(&ticket, source), [48721]);
        assert!(verified_ports(&ticket, "192.0.2.11:48721".parse().unwrap()).is_empty());
        ticket[1] ^= 1;
        assert!(verified_ports(&ticket, source).is_empty());
    }

    #[test]
    fn malformed_or_redirected_queries_get_no_response() {
        let peer = "127.0.0.1:1234".parse().unwrap();
        let data = request();
        for n in 0..data.len() {
            assert!(binding_reply(&data[..n], peer).is_none());
        }
        let mut small = data[..20].to_vec();
        small[3] = 0;
        assert!(binding_reply(&small, peer).is_none());
        for kind in [0x0003u16, 0x0027, 0x0008, 0x8028] {
            let mut bad = data.clone();
            bad[20..22].copy_from_slice(&kind.to_be_bytes());
            assert!(binding_reply(&bad, peer).is_none());
        }
        let mut bad = data;
        bad[23] = 80;
        assert!(binding_reply(&bad, peer).is_none());
    }
}
