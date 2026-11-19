use crate::crypto::{decrypt_vault, encrypt_vault, load_or_create_key, write_secret_file};
use crate::models::{KnownHostEntry, VaultData};
use anyhow::{anyhow, Context, Result};
use directories::ProjectDirs;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub struct Storage {
    config_dir: PathBuf,
}

impl Storage {
    pub fn new() -> Result<Self> {
        let config_dir = if let Ok(custom) = env::var("SSHA_CONFIG_DIR") {
            PathBuf::from(custom)
        } else {
            let dirs = ProjectDirs::from("", "", "ssha").ok_or_else(|| {
                anyhow!("Impossible de déterminer le dossier de configuration utilisateur.")
            })?;
            dirs.config_dir().to_path_buf()
        };

        ensure_private_dir(&config_dir)?;
        Ok(Self { config_dir })
    }

    #[cfg(test)]
    pub fn with_dir(dir: PathBuf) -> Result<Self> {
        ensure_private_dir(&dir)?;
        Ok(Self { config_dir: dir })
    }

    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    pub fn vault_path(&self) -> PathBuf {
        self.config_dir.join("vault.enc")
    }

    pub fn key_path(&self) -> PathBuf {
        self.config_dir.join(".vault.key")
    }

    pub fn known_hosts_path(&self) -> PathBuf {
        self.config_dir.join("known_hosts.json")
    }

    pub fn load_vault(&self) -> Result<VaultData> {
        let path = self.vault_path();
        if !path.exists() {
            // Ensure key is initialized lazily when saving, or return empty vault cleanly.
            return Ok(VaultData::default());
        }

        let key = load_or_create_key(&self.key_path())?;
        let encrypted = fs::read(&path)
            .with_context(|| format!("Impossible de lire le coffre-fort: {}", path.display()))?;
        let plaintext = decrypt_vault(&encrypted, &key)?;
        let vault: VaultData = serde_json::from_slice(&plaintext)
            .context("Impossible de désérialiser les données du coffre-fort.")?;
        Ok(vault)
    }

    pub fn save_vault(&self, vault: &VaultData) -> Result<()> {
        let key = load_or_create_key(&self.key_path())?;
        let json = Zeroizing::new(
            serde_json::to_vec_pretty(vault)
                .context("Impossible de sérialiser le coffre-fort.")?,
        );
        let encrypted = encrypt_vault(&json, &key)?;

        // Atomic write via temporary file in the same directory.
        let tmp_path = self.config_dir.join("vault.enc.tmp");
        write_secret_file(&tmp_path, &encrypted)?;
        fs::rename(&tmp_path, self.vault_path()).with_context(|| {
            format!(
                "Impossible de remplacer le coffre-fort {}",
                self.vault_path().display()
            )
        })?;
        Ok(())
    }

    pub fn load_known_hosts(&self) -> Result<BTreeMap<String, KnownHostEntry>> {
        let path = self.known_hosts_path();
        if !path.exists() {
            return Ok(BTreeMap::new());
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("Impossible de lire {}", path.display()))?;
        let map: BTreeMap<String, KnownHostEntry> =
            serde_json::from_str(&raw).unwrap_or_default();
        Ok(map)
    }

    pub fn save_known_hosts(&self, hosts: &BTreeMap<String, KnownHostEntry>) -> Result<()> {
        let json = serde_json::to_string_pretty(hosts)?;
        write_secret_file(&self.known_hosts_path(), json.as_bytes())
    }
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)
            .with_context(|| format!("Impossible de créer le dossier {}", path.display()))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// Expands leading `~` to the user's home directory across Linux and Windows.
pub fn expand_tilde(path: &str) -> PathBuf {
    let trimmed = path.trim();
    if let Some(rest) = trimmed.strip_prefix("~/").or_else(|| trimmed.strip_prefix("~\\")) {
        if let Some(home) = home_dir() {
            return home.join(rest);
        }
    } else if trimmed == "~" {
        if let Some(home) = home_dir() {
            return home;
        }
    }
    PathBuf::from(trimmed)
}

fn home_dir() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AuthMethod, SshHost};
    use chrono::Utc;

    #[test]
    fn save_and_load_encrypted_vault() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::with_dir(dir.path().to_path_buf()).unwrap();

        let mut vault = storage.load_vault().unwrap();
        assert!(vault.hosts.is_empty());

        vault.hosts.push(SshHost {
            name: "mon-pc".into(),
            host: "192.168.1.192".into(),
            port: 22,
            username: "user".into(),
            auth: AuthMethod::Password {
                password: "super-secret-password".into(),
            },
            group: Some("Maison".into()),
            note: None,
            created_at: Utc::now(),
            last_used: None,
        });

        storage.save_vault(&vault).unwrap();

        // Verify password is NOT stored in plaintext on disk
        let raw_bytes = fs::read(storage.vault_path()).unwrap();
        let raw_lossy = String::from_utf8_lossy(&raw_bytes);
        assert!(!raw_lossy.contains("super-secret-password"));
        assert!(!raw_lossy.contains("192.168.1.192"));

        // Verify reload succeeds
        let reloaded = storage.load_vault().unwrap();
        assert_eq!(reloaded.hosts.len(), 1);
        assert_eq!(reloaded.hosts[0].name, "mon-pc");
        assert_eq!(reloaded.hosts[0].host, "192.168.1.192");
    }
}
