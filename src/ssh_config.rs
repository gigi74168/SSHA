use crate::models::{AuthMethod, LocalForwardSpec, SshHost};
use crate::storage::{ImportReport, Storage};
use anyhow::{bail, Context, Result};
use chrono::Utc;
use std::fs;
use std::path::{Path, PathBuf};

/// Returns the default OpenSSH user config path (`~/.ssh/config`).
pub fn default_ssh_config_path() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|b| b.home_dir().join(".ssh").join("config"))
}

#[derive(Default)]
struct RawBlock {
    aliases: Vec<String>,
    hostname: Option<String>,
    port: Option<u16>,
    user: Option<String>,
    identity_files: Vec<String>,
    proxy_jump: Option<String>,
    local_forwards: Vec<LocalForwardSpec>,
    forward_agent: bool,
}

/// Parses an OpenSSH `~/.ssh/config` string into `ssha` `SshHost` entries.
/// Wildcard patterns (`*`, `?`, `!`) are skipped automatically.
pub fn parse_ssh_config_str(content: &str) -> Vec<SshHost> {
    let mut blocks: Vec<RawBlock> = Vec::new();
    let mut current: Option<RawBlock> = None;

    for raw_line in content.lines() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        let Some((key, value)) = split_directive(line) else {
            continue;
        };
        let key_lower = key.to_lowercase();

        if key_lower == "host" {
            if let Some(prev) = current.take() {
                blocks.push(prev);
            }
            let aliases: Vec<String> = value
                .split_whitespace()
                .map(|s| s.trim_matches('"').to_string())
                .filter(|s| {
                    !s.is_empty() && !s.contains('*') && !s.contains('?') && !s.starts_with('!')
                })
                .collect();
            current = Some(RawBlock {
                aliases,
                ..Default::default()
            });
            continue;
        }

        if key_lower == "match" {
            if let Some(prev) = current.take() {
                blocks.push(prev);
            }
            continue;
        }

        let Some(ref mut blk) = current else {
            continue;
        };

        match key_lower.as_str() {
            "hostname" => blk.hostname = Some(unquote(value)),
            "port" => {
                if let Ok(p) = unquote(value).parse::<u16>() {
                    if p > 0 {
                        blk.port = Some(p);
                    }
                }
            }
            "user" => blk.user = Some(unquote(value)),
            "identityfile" => {
                let path = unquote(value);
                if !path.is_empty() && !blk.identity_files.contains(&path) {
                    blk.identity_files.push(path);
                }
            }
            "proxyjump" => {
                let pj = unquote(value);
                if !pj.is_empty() && pj.to_lowercase() != "none" {
                    blk.proxy_jump = Some(pj);
                }
            }
            "localforward" => {
                if let Ok(spec) = LocalForwardSpec::parse(&unquote(value)) {
                    blk.local_forwards.push(spec);
                }
            }
            "forwardagent" => {
                let v = unquote(value).to_lowercase();
                blk.forward_agent = matches!(v.as_str(), "yes" | "true" | "1");
            }
            _ => {}
        }
    }

    if let Some(last) = current {
        blocks.push(last);
    }

    let default_user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "root".to_string());

    let mut result = Vec::new();
    for blk in blocks {
        for alias in &blk.aliases {
            let host = blk.hostname.clone().unwrap_or_else(|| alias.clone());
            let username = blk.user.clone().unwrap_or_else(|| default_user.clone());
            let port = blk.port.unwrap_or(22);

            let (primary_key, extra_keys) = if blk.identity_files.is_empty() {
                (
                    "~/.ssh/id_ed25519".to_string(),
                    vec!["~/.ssh/id_rsa".to_string()],
                )
            } else {
                (
                    blk.identity_files[0].clone(),
                    blk.identity_files[1..].to_vec(),
                )
            };

            result.push(SshHost {
                name: alias.clone(),
                host,
                port,
                username,
                auth: AuthMethod::Key {
                    path: primary_key,
                    passphrase: None,
                },
                group: Some("ssh-config".to_string()),
                note: Some(t!("ssh_config.imported_note").into_owned()),
                proxy_jump: blk.proxy_jump.clone(),
                local_forwards: blk.local_forwards.clone(),
                extra_keys,
                forward_agent: blk.forward_agent,
                monitor: false,
                created_at: Utc::now(),
                last_used: None,
            });
        }
    }

    result
}

/// Imports hosts from an OpenSSH config file into the encrypted `ssha` vault.
pub fn import_from_ssh_config(
    storage: &Storage,
    path: &Path,
    overwrite_existing: bool,
) -> Result<ImportReport> {
    if !path.exists() {
        bail!("Fichier SSH config introuvable : {}", path.display());
    }
    let content = fs::read_to_string(path)
        .with_context(|| t!("common.err.read", path = path.display()).into_owned())?;

    let parsed = parse_ssh_config_str(&content);
    let mut vault = storage.load_vault()?;
    let mut report = ImportReport::default();

    for host in parsed {
        if let Some(idx) = vault.find_index_by_name(&host.name) {
            if overwrite_existing {
                vault.hosts[idx] = host;
                report.updated += 1;
            } else {
                report.skipped += 1;
            }
        } else {
            vault.hosts.push(host);
            report.added += 1;
        }
    }

    storage.save_vault(&vault)?;
    Ok(report)
}

fn strip_comment(line: &str) -> &str {
    let mut in_quotes = false;
    for (idx, ch) in line.char_indices() {
        if ch == '"' {
            in_quotes = !in_quotes;
        } else if ch == '#' && !in_quotes {
            return &line[..idx];
        }
    }
    line
}

fn split_directive(line: &str) -> Option<(&str, &str)> {
    // OpenSSH allows either `Key Value` or `Key=Value`
    let mut chars = line.char_indices();
    while let Some((idx, ch)) = chars.next() {
        if ch.is_whitespace() || ch == '=' {
            let key = &line[..idx];
            let rest = line[idx + 1..].trim_start_matches(|c: char| c.is_whitespace() || c == '=');
            if !key.is_empty() && !rest.is_empty() {
                return Some((key, rest));
            }
            return None;
        }
    }
    None
}

fn unquote(s: &str) -> String {
    let t = s.trim();
    if t.starts_with('"') && t.ends_with('"') && t.len() >= 2 {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_openssh_config_with_advanced_options() {
        let cfg = r#"
# Global defaults (must be ignored because of wildcard)
Host *
    ServerAliveInterval 60

Host bastion
    HostName 10.0.0.1
    User admin
    Port 2222
    IdentityFile ~/.ssh/id_bastion

Host prod-web
    HostName 192.168.10.50
    User deploy
    ProxyJump bastion
    IdentityFile ~/.ssh/id_prod
    IdentityFile ~/.ssh/id_fallback
    LocalForward 8080 127.0.0.1:80
    ForwardAgent yes
"#;

        let hosts = parse_ssh_config_str(cfg);
        assert_eq!(hosts.len(), 2);

        assert_eq!(hosts[0].name, "bastion");
        assert_eq!(hosts[0].host, "10.0.0.1");
        assert_eq!(hosts[0].port, 2222);
        assert_eq!(hosts[0].username, "admin");

        assert_eq!(hosts[1].name, "prod-web");
        assert_eq!(hosts[1].host, "192.168.10.50");
        assert_eq!(hosts[1].proxy_jump.as_deref(), Some("bastion"));
        assert_eq!(hosts[1].extra_keys, vec!["~/.ssh/id_fallback"]);
        assert_eq!(hosts[1].local_forwards.len(), 1);
        assert_eq!(hosts[1].local_forwards[0].local_port, 8080);
        assert_eq!(hosts[1].local_forwards[0].remote_port, 80);
        assert!(hosts[1].forward_agent);
    }
}
