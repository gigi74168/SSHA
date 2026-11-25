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
    pub fn label(&self) -> String {
        match self {
            AuthMethod::Password { .. } => t!("common.auth_password").into_owned(),
            AuthMethod::Key { .. } => t!("common.auth_key").into_owned(),
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
                .field("passphrase", &passphrase.as_ref().map(|_| "[REDACTED]"))
                .finish(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalForwardSpec {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
}

fn default_bind_addr() -> String {
    "127.0.0.1".to_string()
}

impl LocalForwardSpec {
    /// Parses `local_port:remote_host:remote_port` or `bind_addr:local_port:remote_host:remote_port`
    /// or OpenSSH style `[bind_addr:]local_port remote_host:remote_port`.
    pub fn parse(input: &str) -> Result<Self, String> {
        let trimmed = input.trim();
        // OpenSSH config style: `8080 127.0.0.1:80` or `127.0.0.1:8080 localhost:80`
        let space_parts: Vec<&str> = trimmed.split_whitespace().collect();
        if space_parts.len() == 2 {
            let (bind_addr, local_port) = if let Some((b, p)) = space_parts[0].rsplit_once(':') {
                (
                    b.trim_matches(['[', ']']).to_string(),
                    p.parse::<u16>()
                        .map_err(|_| t!("models.err.local_port", input = input).into_owned())?,
                )
            } else {
                (
                    default_bind_addr(),
                    space_parts[0]
                        .parse::<u16>()
                        .map_err(|_| t!("models.err.local_port", input = input).into_owned())?,
                )
            };
            let (remote_host, rp) = space_parts[1]
                .rsplit_once(':')
                .ok_or_else(|| t!("models.err.remote_dest", input = input).into_owned())?;
            let remote_port = rp
                .parse::<u16>()
                .map_err(|_| t!("models.err.remote_port", input = input).into_owned())?;
            return Ok(Self {
                bind_addr,
                local_port,
                remote_host: remote_host.trim_matches(['[', ']']).to_string(),
                remote_port,
            });
        }

        // Colon-separated CLI style: `8080:127.0.0.1:80` or `127.0.0.1:8080:localhost:80`
        let parts: Vec<&str> = trimmed.split(':').collect();
        match parts.as_slice() {
            [lp, rh, rp] => Ok(Self {
                bind_addr: default_bind_addr(),
                local_port: lp
                    .parse::<u16>()
                    .map_err(|_| t!("models.err.local_port", input = input).into_owned())?,
                remote_host: (*rh).to_string(),
                remote_port: rp
                    .parse::<u16>()
                    .map_err(|_| t!("models.err.remote_port", input = input).into_owned())?,
            }),
            [ba, lp, rh, rp] => Ok(Self {
                bind_addr: (*ba).to_string(),
                local_port: lp
                    .parse::<u16>()
                    .map_err(|_| t!("models.err.local_port", input = input).into_owned())?,
                remote_host: (*rh).to_string(),
                remote_port: rp
                    .parse::<u16>()
                    .map_err(|_| t!("models.err.remote_port", input = input).into_owned())?,
            }),
            _ => Err(t!("models.err.forward_format", input = input).into_owned()),
        }
    }
}

impl fmt::Display for LocalForwardSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{}",
            self.bind_addr, self.local_port, self.remote_host, self.remote_port
        )
    }
}

fn is_false(b: &bool) -> bool {
    !*b
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
    /// Bastion / ProxyJump: either another saved `ssha` host name or `user@host[:port]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_jump: Option<String>,
    /// Local port forwards (`-L local_port:remote_host:remote_port`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub local_forwards: Vec<LocalForwardSpec>,
    /// Additional SSH private key paths tried as fallback (multiple IdentityFile).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_keys: Vec<String>,
    /// Whether agent forwarding was requested (preserved from ~/.ssh/config).
    #[serde(default, skip_serializing_if = "is_false")]
    pub forward_agent: bool,
    /// Live CPU/RAM monitoring of this machine in the `ssha` list.
    #[serde(default, skip_serializing_if = "is_false")]
    pub monitor: bool,
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
        return t!("common.time.never").into_owned();
    };
    let delta = Utc::now().signed_duration_since(dt);
    let secs = delta.num_seconds();
    if secs < 60 {
        t!("common.time.just_now").into_owned()
    } else if secs < 3600 {
        t!("common.time.minutes_ago", n = secs / 60).into_owned()
    } else if secs < 86400 {
        t!("common.time.hours_ago", n = secs / 3600).into_owned()
    } else if secs < 86400 * 30 {
        t!("common.time.days_ago", n = secs / 86400).into_owned()
    } else {
        dt.format(&t!("common.time.date_format")).to_string()
    }
}
