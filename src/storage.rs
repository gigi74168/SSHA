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
                format!("Impossible de créer le dossier {}", parent.display())
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
            .context("Impossible de sérialiser la configuration pour l'export.")?,
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
            .with_context(|| format!("Impossible de lire le fichier {}", path.display()))?,
    );

    let imported_hosts: Vec<crate::models::SshHost> =
        if let Ok(bundle) = serde_json::from_slice::<ExportBundle>(&raw) {
            bundle.hosts
        } else if let Ok(v) = serde_json::from_slice::<VaultData>(&raw) {
            v.hosts
        } else {
            anyhow::bail!(
                "Format de fichier d'import invalide : '{}'. Attendu un export JSON généré par ssha.",
                path.display()
            );
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
                password: "mdp-export-test".into(),
            },
            group: Some("Maison".into()),
            note: Some("PC principal".into()),
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
                password: "mdp-export-test".into()
            }
        );

        // Re-importing with overwrite=false skips duplicate
        let report2 = import_vault_from_file(&storage_b, &export_file, false).unwrap();
        assert_eq!(report2.added, 0);
        assert_eq!(report2.skipped, 1);
    }
}
