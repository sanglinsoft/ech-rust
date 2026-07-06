use std::{collections::HashMap, sync::Arc};

use anyhow::{bail, Context};

use crate::config::UserConfig;

#[derive(Debug, Clone)]
pub struct UserProfile {
    pub username: String,
    pub password: String,
    pub backend: String,
}

#[derive(Debug, Clone)]
pub struct AuthStore {
    users: Arc<HashMap<String, UserProfile>>,
}

impl AuthStore {
    pub fn from_config(users: HashMap<String, UserConfig>) -> anyhow::Result<Self> {
        if users.is_empty() {
            bail!("users must contain at least one user");
        }

        let mut profiles = HashMap::with_capacity(users.len());
        for (username, user) in users {
            let password = user
                .password
                .or(user.password_hash)
                .with_context(|| format!("users.{username} must set password"))?;
            profiles.insert(
                username.clone(),
                UserProfile {
                    username,
                    password,
                    backend: user.backend,
                },
            );
        }

        Ok(Self {
            users: Arc::new(profiles),
        })
    }

    pub fn authenticate(&self, username: &str, password: &str) -> Option<UserProfile> {
        let user = self.users.get(username)?;
        if user.password == password {
            Some(user.clone())
        } else {
            None
        }
    }

    pub fn user(&self, username: &str) -> Option<UserProfile> {
        self.users.get(username).cloned()
    }
}
