use std::net::IpAddr;

use anyhow::Context;
use ipnet::IpNet;
use tokio::fs;

use crate::config::RouteConfig;

#[derive(Debug, Clone)]
pub struct ChinaIpSet {
    cidrs: Vec<IpNet>,
    ranges: Vec<IpRange>,
}

#[derive(Debug, Clone)]
struct IpRange {
    start: IpAddr,
    end: IpAddr,
}

impl ChinaIpSet {
    pub async fn load(route: &RouteConfig) -> anyhow::Result<Self> {
        let mut cidrs = Vec::new();
        let mut ranges = Vec::new();
        read_ip_table(&route.china_ipv4_cidrs, &mut cidrs, &mut ranges).await?;
        read_ip_table(&route.china_ipv6_cidrs, &mut cidrs, &mut ranges).await?;
        Ok(Self { cidrs, ranges })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|net| net.contains(&ip))
            || self.ranges.iter().any(|range| range.contains(ip))
    }
}

impl IpRange {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.start, self.end, ip) {
            (IpAddr::V4(start), IpAddr::V4(end), IpAddr::V4(ip)) => {
                let ip = u32::from(ip);
                u32::from(start) <= ip && ip <= u32::from(end)
            }
            (IpAddr::V6(start), IpAddr::V6(end), IpAddr::V6(ip)) => {
                let ip = u128::from(ip);
                u128::from(start) <= ip && ip <= u128::from(end)
            }
            _ => false,
        }
    }
}

async fn read_ip_table(
    path: &std::path::Path,
    cidrs: &mut Vec<IpNet>,
    ranges: &mut Vec<IpRange>,
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
                    cidrs.push(net);
                } else {
                    let ip = single.parse::<IpAddr>().with_context(|| {
                        format!("invalid IP table entry at {}:{}", path.display(), idx + 1)
                    })?;
                    ranges.push(IpRange { start: ip, end: ip });
                }
            }
            [start, end] => {
                let start = start.parse::<IpAddr>().with_context(|| {
                    format!("invalid range start at {}:{}", path.display(), idx + 1)
                })?;
                let end = end.parse::<IpAddr>().with_context(|| {
                    format!("invalid range end at {}:{}", path.display(), idx + 1)
                })?;
                validate_range(start, end).with_context(|| {
                    format!("invalid IP range at {}:{}", path.display(), idx + 1)
                })?;
                ranges.push(IpRange { start, end });
            }
            _ => anyhow::bail!("invalid IP table entry at {}:{}", path.display(), idx + 1),
        }
    }

    Ok(())
}

fn validate_range(start: IpAddr, end: IpAddr) -> anyhow::Result<()> {
    match (start, end) {
        (IpAddr::V4(start), IpAddr::V4(end)) => {
            if u32::from(start) > u32::from(end) {
                anyhow::bail!("IPv4 range start is greater than end");
            }
        }
        (IpAddr::V6(start), IpAddr::V6(end)) => {
            if u128::from(start) > u128::from(end) {
                anyhow::bail!("IPv6 range start is greater than end");
            }
        }
        _ => anyhow::bail!("range IP versions differ"),
    }
    Ok(())
}
