use crate::crypto::{
    decrypt_vault, decrypt_vault_with_password, encrypt_vault, encrypt_vault_with_password,
    is_master_password_vault, load_or_create_key, write_secret_file,
};
use crate::models::{KnownHostEntry, VaultData};
use anyhow::{anyhow, Context, Result};
use directories::ProjectDirs;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use zeroize::Zeroizing;

pub struct Storage {
    config_dir: PathBuf,
    master_password: Mutex<Option<Zeroizing<String>>>,
}

impl Storage {
    pub fn new() -> Result<Self> {
        let config_dir = if let Ok(custom) = env::var("SSHA_CONFIG_DIR") {
            PathBuf::from(custom)
        } else {
            let dirs = ProjectDirs::from("", "", "ssha")
                .ok_or_else(|| anyhow!(t!("storage.err.config_dir").into_owned()))?;
            dirs.config_dir().to_path_buf()
        };

        ensure_private_dir(&config_dir)?;
        Ok(Self {
            config_dir,
            master_password: Mutex::new(None),
        })
    }

    #[cfg(test)]
    pub fn with_dir(dir: PathBuf) -> Result<Self> {
        ensure_private_dir(&dir)?;
        Ok(Self {
            config_dir: dir,
            master_password: Mutex::new(None),
        })
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

    pub fn is_master_password_enabled(&self) -> bool {
        let path = self.vault_path();
        if !path.exists() {
            return self
                .master_password
                .lock()
                .map(|g| g.is_some())
                .unwrap_or(false);
        }
        fs::read(&path)
            .map(|b| is_master_password_vault(&b))
            .unwrap_or(false)
    }

    fn cached_master_password(&self) -> Option<Zeroizing<String>> {
        self.master_password.lock().ok().and_then(|g| g.clone())
    }

    fn set_cached_master_password(&self, pw: Option<String>) {
        if let Ok(mut guard) = self.master_password.lock() {
            *guard = pw.map(Zeroizing::new);
        }
    }

    /// Prompts once for the master password if the vault uses optional Master Password mode (v2).
    pub fn ensure_unlocked(&self) -> Result<()> {
        if !self.is_master_password_enabled() || self.cached_master_password().is_some() {
            return Ok(());
        }
        let encrypted = fs::read(self.vault_path())?;
        for attempt in 1..=3 {
            let pw = rpassword::prompt_password(format!("{} : ", t!("storage.master_prompt")))?;
            match decrypt_vault_with_password(&encrypted, &pw) {
                Ok(_) => {
                    self.set_cached_master_password(Some(pw));
                    return Ok(());
                }
                Err(_) if attempt < 3 => {
                    eprintln!(
                        "\x1b[1;31m✗\x1b[0m {}",
                        t!("storage.master_wrong", attempt = attempt)
                    );
                }
                Err(e) => return Err(e),
            }
        }
        anyhow::bail!(t!("storage.err.master_attempts").into_owned())
    }

    /// Migrates the vault to optional Master Password mode (Argon2id + AES-256-GCM) and removes `.vault.key`.
    pub fn enable_master_password(&self, new_password: &str) -> Result<()> {
        if new_password.is_empty() {
            anyhow::bail!(t!("storage.err.master_empty").into_owned());
        }
        let vault = self.load_vault()?;
        self.set_cached_master_password(Some(new_password.to_string()));
        self.save_vault(&vault)?;
        let _ = fs::remove_file(self.key_path());
        Ok(())
    }

    /// Migrates the vault back to automatic key mode (no master password prompt).
    pub fn disable_master_password(&self) -> Result<()> {
        let vault = self.load_vault()?;
        self.set_cached_master_password(None);
        // Force v1 save by writing with automatic key
        let key = load_or_create_key(&self.key_path())?;
        let json = Zeroizing::new(serde_json::to_vec_pretty(&vault)?);
        let encrypted = encrypt_vault(&json, &key)?;
        self.atomic_write_vault(&encrypted)
    }

    pub fn load_vault(&self) -> Result<VaultData> {
        let path = self.vault_path();
        if !path.exists() {
            return Ok(VaultData::default());
        }

        let encrypted = fs::read(&path)
            .with_context(|| t!("storage.err.read_vault", path = path.display()).into_owned())?;

        let plaintext = if is_master_password_vault(&encrypted) {
            if self.cached_master_password().is_none() {
                self.ensure_unlocked()?;
            }
            let pw = self
                .cached_master_password()
                .ok_or_else(|| anyhow!(t!("storage.err.locked").into_owned()))?;
            decrypt_vault_with_password(&encrypted, &pw)?
        } else {
            let key = load_or_create_key(&self.key_path())?;
            decrypt_vault(&encrypted, &key)?
        };

        let vault: VaultData = serde_json::from_slice(&plaintext)
            .context(t!("storage.err.deserialize").into_owned())?;
        Ok(vault)
    }

    pub fn save_vault(&self, vault: &VaultData) -> Result<()> {
        let json = Zeroizing::new(
            serde_json::to_vec_pretty(vault).context(t!("storage.err.serialize").into_owned())?,
        );

        let encrypted = if let Some(pw) = self.cached_master_password() {
            encrypt_vault_with_password(&json, &pw)?
        } else {
            let key = load_or_create_key(&self.key_path())?;
            encrypt_vault(&json, &key)?
        };

        self.atomic_write_vault(&encrypted)
    }

    fn atomic_write_vault(&self, encrypted: &[u8]) -> Result<()> {
        let tmp_path = self.config_dir.join("vault.enc.tmp");
        write_secret_file(&tmp_path, encrypted)?;
        fs::rename(&tmp_path, self.vault_path()).with_context(|| {
            t!(
                "storage.err.replace_vault",
                path = self.vault_path().display()
            )
            .into_owned()
        })?;
        Ok(())
    }

    pub fn load_known_hosts(&self) -> Result<BTreeMap<String, KnownHostEntry>> {
        let path = self.known_hosts_path();
        if !path.exists() {
            return Ok(BTreeMap::new());
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| t!("common.err.read", path = path.display()).into_owned())?;
        let map: BTreeMap<String, KnownHostEntry> = serde_json::from_str(&raw).unwrap_or_default();
        Ok(map)
    }

    pub fn save_known_hosts(&self, hosts: &BTreeMap<String, KnownHostEntry>) -> Result<()> {
        let json = serde_json::to_string_pretty(hosts)?;
        write_secret_file(&self.known_hosts_path(), json.as_bytes())
    }

    pub fn settings_path(&self) -> PathBuf {
        self.config_dir.join("settings.json")
    }

    /// Loads non-secret user preferences (language, last seen version). Never fails.
    pub fn load_settings(&self) -> Settings {
        fs::read_to_string(self.settings_path())
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default()
    }

    pub fn save_settings(&self, settings: &Settings) -> Result<()> {
        let json = serde_json::to_string_pretty(settings)?;
        let path = self.settings_path();
        fs::write(&path, json)
            .with_context(|| t!("common.err.write", path = path.display()).into_owned())?;
        Ok(())
    }
}

/// Non-secret user preferences stored in `settings.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Settings {
    /// Interface language code (`en`, `fr`, `ru`, `uk`, `es`, `it`). `None` = not chosen yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// Last `ssha` version launched, used to show the "What's new" screen once after an update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_version: Option<String>,
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)
            .with_context(|| t!("common.err.create_dir", path = path.display()).into_owned())?;
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
    if let Some(rest) = trimmed
        .strip_prefix("~/")
        .or_else(|| trimmed.strip_prefix("~\\"))
    {
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

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ExportBundle {
    #[serde(default = "default_export_format")]
    format: String,
    #[serde(default = "chrono::Utc::now")]
    exported_at: chrono::DateTime<chrono::Utc>,
    hosts: Vec<crate::models::SshHost>,
}

fn default_export_format() -> String {
    "ssha-export-v1".to_string()
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ImportReport {
    pub added: usize,
    pub updated: usize,
    pub skipped: usize,
}

/// Exports all saved SSH hosts (IPs, users, passwords, keys, groups, notes) to a portable JSON file.
pub fn export_vault_to_file(vault: &VaultData, path: &Path) -> Result<usize> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent).with_context(|| {
                t!("common.err.create_dir", path = parent.display()).into_owned()
            })?;
        }
    }

    let bundle = ExportBundle {
        format: default_export_format(),
        exported_at: chrono::Utc::now(),
        hosts: vault.hosts.clone(),
    };
    let json = Zeroizing::new(
        serde_json::to_vec_pretty(&bundle)
            .context(t!("storage.err.serialize_export").into_owned())?,
    );
    write_secret_file(path, &json)?;
    Ok(bundle.hosts.len())
}

/// Imports SSH hosts from an exported JSON file into the local encrypted vault.
/// When `overwrite_existing` is true, existing entries with the same name are updated;
/// otherwise they are kept untouched and counted as skipped.
pub fn import_vault_from_file(
    storage: &Storage,
    path: &Path,
    overwrite_existing: bool,
) -> Result<ImportReport> {
    if !path.exists() {
        anyhow::bail!("Fichier d'import introuvable : {}", path.display());
    }
    let raw = Zeroizing::new(
        fs::read(path)
            .with_context(|| t!("common.err.read", path = path.display()).into_owned())?,
    );

    let imported_hosts: Vec<crate::models::SshHost> =
        if let Ok(bundle) = serde_json::from_slice::<ExportBundle>(&raw) {
            bundle.hosts
        } else if let Ok(v) = serde_json::from_slice::<VaultData>(&raw) {
            v.hosts
        } else {
            anyhow::bail!(t!("storage.err.import_format", path = path.display()).into_owned());
        };

    let mut vault = storage.load_vault()?;
    let mut report = ImportReport::default();

    for host in imported_hosts {
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
            name: "my-pc".into(),
            host: "192.168.1.192".into(),
            port: 22,
            username: "user".into(),
            auth: AuthMethod::Password {
                password: "super-secret-password".into(),
            },
            group: Some("Maison".into()),
            note: None,
            proxy_jump: None,
            local_forwards: Vec::new(),
            extra_keys: Vec::new(),
            forward_agent: false,
            monitor: false,
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
        assert_eq!(reloaded.hosts[0].name, "my-pc");
        assert_eq!(reloaded.hosts[0].host, "192.168.1.192");
    }

    #[test]
    fn export_and_import_between_two_vaults() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let storage_a = Storage::with_dir(dir_a.path().to_path_buf()).unwrap();
        let storage_b = Storage::with_dir(dir_b.path().to_path_buf()).unwrap();

        let mut vault_a = VaultData::default();
        vault_a.hosts.push(SshHost {
            name: "serveur-linux".into(),
            host: "192.168.1.192".into(),
            port: 2222,
            username: "gigi".into(),
            auth: AuthMethod::Password {
                password: "export-test-password".into(),
            },
            group: Some("Maison".into()),
            note: Some("PC principal".into()),
            proxy_jump: None,
            local_forwards: Vec::new(),
            extra_keys: Vec::new(),
            forward_agent: false,
            monitor: false,
            created_at: Utc::now(),
            last_used: None,
        });
        storage_a.save_vault(&vault_a).unwrap();

        let export_file = dir_a.path().join("ssha-backup.json");
        let count = export_vault_to_file(&vault_a, &export_file).unwrap();
        assert_eq!(count, 1);

        let report = import_vault_from_file(&storage_b, &export_file, true).unwrap();
        assert_eq!(report.added, 1);
        assert_eq!(report.updated, 0);

        let vault_b = storage_b.load_vault().unwrap();
        assert_eq!(vault_b.hosts.len(), 1);
        assert_eq!(vault_b.hosts[0].host, "192.168.1.192");
        assert_eq!(vault_b.hosts[0].port, 2222);
        assert_eq!(vault_b.hosts[0].username, "gigi");
        assert_eq!(
            vault_b.hosts[0].auth,
            AuthMethod::Password {
                password: "export-test-password".into()
            }
        );

        // Re-importing with overwrite=false skips duplicate
        let report2 = import_vault_from_file(&storage_b, &export_file, false).unwrap();
        assert_eq!(report2.added, 0);
        assert_eq!(report2.skipped, 1);
    }

    #[test]
    fn master_password_enable_and_disable_migration() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::with_dir(dir.path().to_path_buf()).unwrap();

        let mut vault = VaultData::default();
        vault.hosts.push(SshHost {
            name: "pc".into(),
            host: "10.0.0.2".into(),
            port: 22,
            username: "root".into(),
            auth: AuthMethod::Password {
                password: "secret".into(),
            },
            group: None,
            note: None,
            proxy_jump: None,
            local_forwards: Vec::new(),
            extra_keys: Vec::new(),
            forward_agent: false,
            monitor: false,
            created_at: Utc::now(),
            last_used: None,
        });
        storage.save_vault(&vault).unwrap();
        assert!(!storage.is_master_password_enabled());
        assert!(storage.key_path().exists());

        // Enable master password -> v2 vault, .vault.key removed
        storage
            .enable_master_password("my-master-password")
            .unwrap();
        assert!(storage.is_master_password_enabled());
        assert!(!storage.key_path().exists());
        let reloaded = storage.load_vault().unwrap();
        assert_eq!(reloaded.hosts.len(), 1);

        // Disable master password -> back to v1 automatic mode
        storage.disable_master_password().unwrap();
        assert!(!storage.is_master_password_enabled());
        assert!(storage.key_path().exists());
        let reloaded2 = storage.load_vault().unwrap();
        assert_eq!(reloaded2.hosts.len(), 1);
    }
}
