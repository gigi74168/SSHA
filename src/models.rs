use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthMethod {
    Password {
        password: String,
    },
    Key {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase: Option<String>,
    },
}

impl AuthMethod {
    pub fn label(&self) -> &'static str {
        match self {
            AuthMethod::Password { .. } => "MDP",
            AuthMethod::Key { .. } => "CLÉ",
        }
    }

    pub fn is_password(&self) -> bool {
        matches!(self, AuthMethod::Password { .. })
    }
}

impl Drop for AuthMethod {
    fn drop(&mut self) {
        match self {
            AuthMethod::Password { password } => password.zeroize(),
            AuthMethod::Key { passphrase, .. } => {
                if let Some(p) = passphrase {
                    p.zeroize();
                }
            }
        }
    }
}

impl fmt::Debug for AuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthMethod::Password { .. } => f
                .debug_struct("Password")
                .field("password", &"[REDACTED]")
                .finish(),
            AuthMethod::Key { path, passphrase } => f
                .debug_struct("Key")
                .field("path", path)
                .field(
                    "passphrase",
                    &passphrase.as_ref().map(|_| "[REDACTED]"),
                )
                .finish(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SshHost {
    pub name: String,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub username: String,
    pub auth: AuthMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used: Option<DateTime<Utc>>,
}

fn default_port() -> u16 {
    22
}

impl SshHost {
    pub fn endpoint_display(&self) -> String {
        if self.port == 22 {
            format!("{}@{}", self.username, self.host)
        } else {
            format!("{}@{}:{}", self.username, self.host, self.port)
        }
    }

    pub fn host_key_id(&self) -> String {
        if self.port == 22 {
            self.host.to_lowercase()
        } else {
            format!("[{}]:{}", self.host.to_lowercase(), self.port)
        }
    }

    pub fn matches_query(&self, query: &str) -> bool {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return true;
        }
        self.name.to_lowercase().contains(&q)
            || self.host.to_lowercase().contains(&q)
            || self.username.to_lowercase().contains(&q)
            || self
                .group
                .as_deref()
                .map(|g| g.to_lowercase().contains(&q))
                .unwrap_or(false)
            || self
                .note
                .as_deref()
                .map(|n| n.to_lowercase().contains(&q))
                .unwrap_or(false)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultData {
    pub version: u32,
    pub hosts: Vec<SshHost>,
}

impl Default for VaultData {
    fn default() -> Self {
        Self {
            version: 1,
            hosts: Vec::new(),
        }
    }
}

impl VaultData {
    pub fn find_index_by_name(&self, name: &str) -> Option<usize> {
        let target = name.trim().to_lowercase();
        self.hosts
            .iter()
            .position(|h| h.name.to_lowercase() == target)
    }

    pub fn find_by_name(&self, name: &str) -> Option<&SshHost> {
        self.find_index_by_name(name).map(|i| &self.hosts[i])
    }

    pub fn remove_by_name(&mut self, name: &str) -> Option<SshHost> {
        self.find_index_by_name(name).map(|i| self.hosts.remove(i))
    }

    pub fn mark_used(&mut self, name: &str) {
        if let Some(idx) = self.find_index_by_name(name) {
            self.hosts[idx].last_used = Some(Utc::now());
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KnownHostEntry {
    pub algorithm: String,
    pub fingerprint: String,
    pub first_seen: DateTime<Utc>,
}

pub fn format_relative_time(dt: Option<DateTime<Utc>>) -> String {
    let Some(dt) = dt else {
        return "jamais".to_string();
    };
    let delta = Utc::now().signed_duration_since(dt);
    let secs = delta.num_seconds();
    if secs < 60 {
        "à l'instant".to_string()
    } else if secs < 3600 {
        format!("il y a {} min", secs / 60)
    } else if secs < 86400 {
        format!("il y a {} h", secs / 3600)
    } else if secs < 86400 * 30 {
        format!("il y a {} j", secs / 86400)
    } else {
        dt.format("%d/%m/%Y").to_string()
    }
}
