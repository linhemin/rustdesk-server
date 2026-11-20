//! Answer a padded STUN Binding request on the existing rendezvous UDP listener.
//! Replies go to the sender and never exceed the request's size.
use std::net::{IpAddr, SocketAddr};

const COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

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
    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

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
