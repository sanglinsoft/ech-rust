use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
};

use anyhow::bail;
use tokio::task;

use crate::config::PolicyConfig;

#[derive(Debug)]
pub struct Policy {
    connect_timeout: std::time::Duration,
    deny_private_ip: bool,
    allowed_ports: Option<HashSet<u16>>,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid target host")]
    InvalidHost,
    #[error("target port is out of range")]
    InvalidPort,
    #[error("target port {0} is not allowed")]
    PortDenied(u16),
    #[error("target resolved to no addresses")]
    NoAddresses,
    #[error("target address {0} is denied")]
    AddressDenied(IpAddr),
    #[error("failed to resolve target: {0}")]
    Resolve(String),
}

impl Policy {
    pub fn from_config(config: PolicyConfig) -> anyhow::Result<Self> {
        if config.allowed_ports.iter().any(|port| *port == 0) {
            bail!("allowed_ports must not contain 0");
        }

        let connect_timeout = config.connect_timeout();
        let deny_private_ip = config.deny_private_ip;
        let allowed_ports = if config.allowed_ports.is_empty() {
            None
        } else {
            Some(config.allowed_ports.into_iter().collect())
        };

        Ok(Self {
            connect_timeout,
            deny_private_ip,
            allowed_ports,
        })
    }

    pub fn connect_timeout(&self) -> std::time::Duration {
        self.connect_timeout
    }

    pub async fn resolve_target(
        &self,
        host: &str,
        port: u32,
    ) -> Result<Vec<SocketAddr>, PolicyError> {
        let port = u16::try_from(port).map_err(|_| PolicyError::InvalidPort)?;
        if port == 0 {
            return Err(PolicyError::InvalidPort);
        }

        if let Some(allowed) = &self.allowed_ports {
            if !allowed.contains(&port) {
                return Err(PolicyError::PortDenied(port));
            }
        }

        validate_host(host)?;

        let addrs = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![SocketAddr::new(ip, port)]
        } else {
            let target = format!("{host}:{port}");
            task::spawn_blocking(move || {
                target
                    .to_socket_addrs()
                    .map(|iter| iter.collect::<Vec<_>>())
                    .map_err(|err| PolicyError::Resolve(err.to_string()))
            })
            .await
            .map_err(|err| PolicyError::Resolve(err.to_string()))??
        };

        if addrs.is_empty() {
            return Err(PolicyError::NoAddresses);
        }

        for addr in &addrs {
            self.check_ip(addr.ip())?;
        }

        Ok(addrs)
    }

    pub fn check_connected_addr(&self, addr: SocketAddr) -> Result<(), PolicyError> {
        self.check_ip(addr.ip())
    }

    fn check_ip(&self, ip: IpAddr) -> Result<(), PolicyError> {
        if !self.deny_private_ip {
            return Ok(());
        }

        let denied = match ip {
            IpAddr::V4(ip) => {
                ip.is_private()
                    || ip.is_loopback()
                    || ip.is_link_local()
                    || ip.is_multicast()
                    || ip.is_broadcast()
                    || ip.is_documentation()
                    || ip.is_unspecified()
            }
            IpAddr::V6(ip) => {
                ip.is_loopback()
                    || ip.is_multicast()
                    || ip.is_unspecified()
                    || is_ipv6_unique_local(ip)
                    || is_ipv6_unicast_link_local(ip)
                    || is_ipv6_documentation(ip)
            }
        };

        if denied {
            Err(PolicyError::AddressDenied(ip))
        } else {
            Ok(())
        }
    }
}

fn validate_host(host: &str) -> Result<(), PolicyError> {
    if host.is_empty() || host.len() > 253 {
        return Err(PolicyError::InvalidHost);
    }
    if host.bytes().any(|byte| {
        byte == 0 || byte == b'/' || byte == b'\\' || byte == b'@' || byte.is_ascii_whitespace()
    }) {
        return Err(PolicyError::InvalidHost);
    }
    Ok(())
}

fn is_ipv6_unique_local(ip: std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

fn is_ipv6_unicast_link_local(ip: std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn is_ipv6_documentation(ip: std::net::Ipv6Addr) -> bool {
    ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8
}
