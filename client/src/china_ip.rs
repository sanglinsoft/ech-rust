use std::net::IpAddr;

use anyhow::Context;
use ipnet::IpNet;
use tokio::fs;

use crate::config::RouteConfig;

/// Sorted, merged inclusive IP ranges for O(log n) containment checks.
#[derive(Debug, Clone)]
pub struct ChinaIpSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl ChinaIpSet {
    pub async fn load(route: &RouteConfig) -> anyhow::Result<Self> {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        read_ip_table(&route.china_ipv4_cidrs, &mut v4, &mut v6).await?;
        read_ip_table(&route.china_ipv6_cidrs, &mut v4, &mut v6).await?;
        Ok(Self {
            v4: merge_u32_ranges(v4),
            v6: merge_u128_ranges(v6),
        })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => contains_u32(&self.v4, u32::from(ip)),
            IpAddr::V6(ip) => contains_u128(&self.v6, u128::from(ip)),
        }
    }
}

fn contains_u32(ranges: &[(u32, u32)], ip: u32) -> bool {
    match ranges.binary_search_by_key(&ip, |range| range.0) {
        Ok(_) => true,
        Err(0) => false,
        Err(i) => {
            let (start, end) = ranges[i - 1];
            start <= ip && ip <= end
        }
    }
}

fn contains_u128(ranges: &[(u128, u128)], ip: u128) -> bool {
    match ranges.binary_search_by_key(&ip, |range| range.0) {
        Ok(_) => true,
        Err(0) => false,
        Err(i) => {
            let (start, end) = ranges[i - 1];
            start <= ip && ip <= end
        }
    }
}

fn merge_u32_ranges(mut ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    if ranges.is_empty() {
        return ranges;
    }
    ranges.sort_unstable_by_key(|(start, _)| *start);
    let mut merged = Vec::with_capacity(ranges.len());
    let (mut cur_start, mut cur_end) = ranges[0];
    for (start, end) in ranges.into_iter().skip(1) {
        if start <= cur_end.saturating_add(1) {
            cur_end = cur_end.max(end);
        } else {
            merged.push((cur_start, cur_end));
            cur_start = start;
            cur_end = end;
        }
    }
    merged.push((cur_start, cur_end));
    merged
}

fn merge_u128_ranges(mut ranges: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    if ranges.is_empty() {
        return ranges;
    }
    ranges.sort_unstable_by_key(|(start, _)| *start);
    let mut merged = Vec::with_capacity(ranges.len());
    let (mut cur_start, mut cur_end) = ranges[0];
    for (start, end) in ranges.into_iter().skip(1) {
        let can_merge = start <= cur_end.saturating_add(1);
        if can_merge {
            cur_end = cur_end.max(end);
        } else {
            merged.push((cur_start, cur_end));
            cur_start = start;
            cur_end = end;
        }
    }
    merged.push((cur_start, cur_end));
    merged
}

async fn read_ip_table(
    path: &std::path::Path,
    v4: &mut Vec<(u32, u32)>,
    v6: &mut Vec<(u128, u128)>,
) -> anyhow::Result<()> {
    let raw = fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read CIDR table {}", path.display()))?;

    for (idx, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let fields = line.split_whitespace().collect::<Vec<_>>();
        match fields.as_slice() {
            [single] => {
                if let Ok(net) = single.parse::<IpNet>() {
                    push_net(net, v4, v6);
                } else {
                    let ip = single.parse::<IpAddr>().with_context(|| {
                        format!("invalid IP table entry at {}:{}", path.display(), idx + 1)
                    })?;
                    push_range(ip, ip, v4, v6).with_context(|| {
                        format!("invalid IP table entry at {}:{}", path.display(), idx + 1)
                    })?;
                }
            }
            [start, end] => {
                let start = start.parse::<IpAddr>().with_context(|| {
                    format!("invalid range start at {}:{}", path.display(), idx + 1)
                })?;
                let end = end.parse::<IpAddr>().with_context(|| {
                    format!("invalid range end at {}:{}", path.display(), idx + 1)
                })?;
                push_range(start, end, v4, v6).with_context(|| {
                    format!("invalid IP range at {}:{}", path.display(), idx + 1)
                })?;
            }
            _ => anyhow::bail!("invalid IP table entry at {}:{}", path.display(), idx + 1),
        }
    }

    Ok(())
}

fn push_net(net: IpNet, v4: &mut Vec<(u32, u32)>, v6: &mut Vec<(u128, u128)>) {
    match net {
        IpNet::V4(net) => {
            let start = u32::from(net.network());
            let end = u32::from(net.broadcast());
            v4.push((start, end));
        }
        IpNet::V6(net) => {
            let prefix = u128::from(net.network());
            let hostmask = !u128::from(net.netmask());
            let start = prefix;
            let end = prefix | hostmask;
            v6.push((start, end));
        }
    }
}

fn push_range(
    start: IpAddr,
    end: IpAddr,
    v4: &mut Vec<(u32, u32)>,
    v6: &mut Vec<(u128, u128)>,
) -> anyhow::Result<()> {
    match (start, end) {
        (IpAddr::V4(start), IpAddr::V4(end)) => {
            let start = u32::from(start);
            let end = u32::from(end);
            if start > end {
                anyhow::bail!("IPv4 range start is greater than end");
            }
            v4.push((start, end));
        }
        (IpAddr::V6(start), IpAddr::V6(end)) => {
            let start = u128::from(start);
            let end = u128::from(end);
            if start > end {
                anyhow::bail!("IPv6 range start is greater than end");
            }
            v6.push((start, end));
        }
        _ => anyhow::bail!("range IP versions differ"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn merges_and_looks_up_ipv4_ranges() {
        let set = ChinaIpSet {
            v4: merge_u32_ranges(vec![
                (
                    u32::from(Ipv4Addr::new(1, 0, 1, 0)),
                    u32::from(Ipv4Addr::new(1, 0, 1, 255)),
                ),
                (
                    u32::from(Ipv4Addr::new(1, 0, 2, 0)),
                    u32::from(Ipv4Addr::new(1, 0, 3, 255)),
                ),
                (
                    u32::from(Ipv4Addr::new(10, 0, 0, 0)),
                    u32::from(Ipv4Addr::new(10, 0, 0, 255)),
                ),
            ]),
            v6: Vec::new(),
        };

        assert!(set.contains(IpAddr::V4(Ipv4Addr::new(1, 0, 2, 10))));
        assert!(set.contains(IpAddr::V4(Ipv4Addr::new(1, 0, 1, 0))));
        assert!(set.contains(IpAddr::V4(Ipv4Addr::new(1, 0, 3, 255))));
        assert!(!set.contains(IpAddr::V4(Ipv4Addr::new(1, 0, 4, 0))));
        assert!(!set.contains(IpAddr::V4(Ipv4Addr::new(9, 255, 255, 255))));
        assert!(set.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn looks_up_ipv6_ranges() {
        let start = u128::from(Ipv6Addr::new(0x2001, 0x250, 0, 0, 0, 0, 0, 0));
        let end = u128::from(Ipv6Addr::new(
            0x2001, 0x250, 0x1fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        ));
        let set = ChinaIpSet {
            v4: Vec::new(),
            v6: merge_u128_ranges(vec![(start, end)]),
        };
        assert!(set.contains(IpAddr::V6(Ipv6Addr::new(0x2001, 0x250, 1, 0, 0, 0, 0, 1))));
        assert!(!set.contains(IpAddr::V6(Ipv6Addr::new(0x2001, 0x251, 0, 0, 0, 0, 0, 1))));
    }
}
