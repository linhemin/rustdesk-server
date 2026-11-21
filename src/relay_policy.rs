use hbb_common::{anyhow::{ensure, Context}, ResultType};
use ipnetwork::IpNetwork;
use serde_derive::Deserialize;
use std::net::IpAddr;

#[derive(Deserialize)]
struct Rule {
    left: String,
    right: String,
    relays: Vec<String>,
}

#[derive(Clone, Default)]
pub(crate) struct Policy(Vec<(IpNetwork, IpNetwork, Vec<String>)>);

impl Policy {
    pub(crate) fn parse(config: &str) -> ResultType<Self> {
        if config.trim().is_empty() {
            return Ok(Self::default());
        }
        let rules = serde_json::from_str::<Vec<Rule>>(config)
            .context("RELAY_ISP_ROUTES must be a JSON array")?;
        let mut policy = Self::default();
        for rule in rules {
            let left = rule.left.parse().context("Invalid left CIDR in RELAY_ISP_ROUTES")?;
            let right = rule.right.parse().context("Invalid right CIDR in RELAY_ISP_ROUTES")?;
            ensure!(rule.relays.iter().all(|relay| !relay.trim().is_empty()) && !rule.relays.is_empty(),
                "Empty relay list or name in RELAY_ISP_ROUTES");
            policy.0.push((left, right, rule.relays));
        }
        // Stable order gives earlier rules priority when prefix lengths tie.
        policy.0.sort_by_key(|(left, right, _)| {
            std::cmp::Reverse(u16::from(left.prefix()) + u16::from(right.prefix()))
        });
        Ok(policy)
    }

    pub(crate) fn select<'a>(&'a self, from: IpAddr, to: IpAddr, healthy: &[String]) -> Option<&'a str> {
        let canonical = |ip: IpAddr| match ip {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(ip)),
            ip => ip,
        };
        let (from, to) = (canonical(from), canonical(to));
        self.0.iter()
            .filter(|(left, right, _)| {
                (left.contains(from) && right.contains(to))
                    || (left.contains(to) && right.contains(from))
            })
            .flat_map(|(_, _, relays)| relays)
            .find(|relay| healthy.contains(relay))
            .map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isp_pair_uses_most_specific_healthy_relay_in_either_direction() {
        let policy = Policy::parse(r#"[
            {"left":"192.0.2.0/24","right":"198.51.100.0/24","relays":["general"]},
            {"left":"192.0.2.128/25","right":"198.51.100.0/24","relays":["preferred","backup"]},
            {"left":"2001:db8:1::/48","right":"2001:db8:2::/48","relays":["ipv6"]}
        ]"#).unwrap();
        let a = "::ffff:192.0.2.129".parse().unwrap();
        let b = "198.51.100.1".parse().unwrap();
        assert_eq!(policy.select(a, b, &["general".into(), "preferred".into()]), Some("preferred"));
        assert_eq!(policy.select(b, a, &["general".into(), "backup".into()]), Some("backup"));
        assert_eq!(policy.select(a, b, &["general".into()]), Some("general"));
        assert_eq!(policy.select(a, b, &["unrelated".into()]), None);
        assert_eq!(policy.select("2001:db8:1::1".parse().unwrap(), "2001:db8:2::1".parse().unwrap(), &["ipv6".into()]), Some("ipv6"));
    }
}
