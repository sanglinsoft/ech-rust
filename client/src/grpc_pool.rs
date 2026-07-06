use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use anyhow::{bail, Context};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tonic::transport::Channel;

use crate::{
    config::{BackendConfig, EchConfig},
    ech_tls,
};

#[derive(Debug)]
pub struct BackendPool {
    backend: BackendConfig,
    channels: Vec<Channel>,
    next: AtomicUsize,
    stream_permits: Arc<Semaphore>,
}

#[derive(Debug, Clone)]
pub struct PoolRegistry {
    pools: Arc<HashMap<String, Arc<BackendPool>>>,
}

impl PoolRegistry {
    pub async fn connect(
        backends: HashMap<String, BackendConfig>,
        ech: EchConfig,
    ) -> anyhow::Result<Self> {
        if backends.is_empty() {
            bail!("backends must contain at least one backend");
        }

        let mut pools = HashMap::with_capacity(backends.len());
        for (id, backend) in backends {
            let pool = BackendPool::connect(backend.clone(), &ech)
                .await
                .with_context(|| format!("failed to initialize backend {id}"))?;
            pools.insert(id, Arc::new(pool));
        }

        Ok(Self {
            pools: Arc::new(pools),
        })
    }

    pub fn get(&self, id: &str) -> Option<Arc<BackendPool>> {
        self.pools.get(id).cloned()
    }
}

impl BackendPool {
    async fn connect(backend: BackendConfig, ech: &EchConfig) -> anyhow::Result<Self> {
        let pool_size = backend.pool_size.max(1);
        let mut channels = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            channels.push(ech_tls::connect_channel(&backend, ech).await?);
        }

        Ok(Self {
            stream_permits: Arc::new(Semaphore::new(
                pool_size * backend.max_streams_per_channel.max(1),
            )),
            backend,
            channels,
            next: AtomicUsize::new(0),
        })
    }

    pub fn pick(&self) -> Channel {
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.channels.len();
        self.channels[idx].clone()
    }

    pub fn auth_token(&self) -> &str {
        &self.backend.auth_token
    }

    pub async fn acquire_stream_permit(&self) -> anyhow::Result<OwnedSemaphorePermit> {
        self.stream_permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow::anyhow!("backend stream limiter is closed"))
    }
}
