use std::collections::HashSet;

use anyhow::bail;
use tonic::{metadata::MetadataMap, Status};

#[derive(Debug)]
pub struct TokenAuth {
    tokens: HashSet<String>,
}

impl TokenAuth {
    pub fn new(tokens: Vec<String>) -> anyhow::Result<Self> {
        if tokens.is_empty() {
            bail!("auth.tokens must contain at least one token");
        }

        Ok(Self {
            tokens: tokens.into_iter().collect(),
        })
    }

    pub fn authenticate(&self, metadata: &MetadataMap) -> Result<String, Status> {
        let value = metadata
            .get("authorization")
            .ok_or_else(|| Status::unauthenticated("missing authorization metadata"))?
            .to_str()
            .map_err(|_| Status::unauthenticated("invalid authorization metadata"))?;

        let token = value
            .strip_prefix("Bearer ")
            .or_else(|| value.strip_prefix("bearer "))
            .unwrap_or(value)
            .trim();

        if token.is_empty() || !self.tokens.contains(token) {
            return Err(Status::unauthenticated("invalid backend token"));
        }

        Ok(token.to_owned())
    }
}
