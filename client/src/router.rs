use std::{net::IpAddr, sync::Arc};

use tokio::net::{lookup_host, TcpStream};

use crate::{
    auth::UserProfile,
    china_ip::ChinaIpSet,
    config::{DomainStrategy, RouteConfig},
    grpc_pool::{BackendPool, PoolRegistry},
};

#[derive(Debug, Clone)]
pub struct Router {
    route: RouteConfig,
    china_ip: Arc<ChinaIpSet>,
    pools: PoolRegistry,
}

#[derive(Clone)]
pub enum RouteDecision {
    Direct { connect_host: String },
    Proxy { pool: Arc<BackendPool> },
}

impl Router {
    pub fn new(route: RouteConfig, china_ip: ChinaIpSet, pools: PoolRegistry) -> Self {
        Self {
            route,
            china_ip: Arc::new(china_ip),
            pools,
        }
    }

    pub async fn decide(
        &self,
        user: &UserProfile,
        target_host: &str,
        target_port: u16,
    ) -> anyhow::Result<RouteDecision> {
        if self.route.china_ip_direct {
            if let Ok(ip) = target_host.parse::<IpAddr>() {
                if self.china_ip.contains(ip) {
                    return Ok(RouteDecision::Direct {
                        connect_host: target_host.to_owned(),
                    });
                }
            } else if self.route.domain_strategy == DomainStrategy::SystemDns {
                if let Some(ip) = self.classify_domain(target_host, target_port).await? {
                    return Ok(RouteDecision::Direct {
                        connect_host: ip.to_string(),
                    });
                }
            }
        }

        let pool = self
            .pools
            .get(&user.backend)
            .ok_or_else(|| anyhow::anyhow!("backend {} not found", user.backend))?;
        Ok(RouteDecision::Proxy { pool })
    }

    async fn classify_domain(
        &self,
        host: &str,
        port: u16,
    ) -> anyhow::Result<Option<std::net::IpAddr>> {
        let addrs = lookup_host((host, port)).await?;
        let ips = addrs.map(|addr| addr.ip()).collect::<Vec<_>>();
        if ips.is_empty() {
            return Ok(None);
        }
        if ips.iter().all(|ip| self.china_ip.contains(*ip)) {
            Ok(ips.into_iter().next())
        } else {
            Ok(None)
        }
    }
}

pub async fn connect_direct(connect_host: &str, target_port: u16) -> anyhow::Result<TcpStream> {
    let stream = TcpStream::connect((connect_host, target_port)).await?;
    crate::tcp_util::configure_proxy_tcp(&stream);
    Ok(stream)
}
