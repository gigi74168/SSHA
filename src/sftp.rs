use crate::models::SshHost;
use crate::ssh::{connect_and_authenticate, SshClientHandler};
use crate::storage::{expand_tilde, Storage};
use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Local, Utc};
use russh::{client, Disconnect};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CHUNK_SIZE: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct RemoteEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub permissions: Option<u32>,
    pub mtime: Option<u32>,
}

impl RemoteEntry {
    pub fn is_hidden(&self) -> bool {
        self.name.starts_with('.')
    }
}

#[derive(Clone, Debug, Default)]
pub struct TransferStats {
    pub files: usize,
    pub bytes: u64,
}

pub struct SftpClient {
    session: client::Handle<SshClientHandler>,
    sftp: SftpSession,
}

impl SftpClient {
    /// Connects to the remote host over SSH and opens the SFTP subsystem.
    pub async fn connect(host: &SshHost, storage: Arc<Storage>) -> Result<Self> {
        let session = connect_and_authenticate(host, storage).await?;
        let channel = session
            .channel_open_session()
            .await
            .context("Impossible d'ouvrir un canal SSH pour SFTP")?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .context("Le serveur distant ne semble pas activer le sous-système SFTP")?;
        let sftp = SftpSession::new(channel.into_stream())
            .await
            .context("Impossible d'initialiser la session SFTP")?;

        Ok(Self { session, sftp })
    }

    pub async fn canonicalize(&self, path: &str) -> Result<String> {
        self.sftp
            .canonicalize(path)
            .await
            .with_context(|| format!("Impossible de résoudre le chemin distant '{}'", path))
    }

    pub async fn list_dir(&self, path: &str) -> Result<Vec<RemoteEntry>> {
        let entries = self
            .sftp
            .read_dir(path)
            .await
            .with_context(|| format!("Impossible de lire le dossier distant '{}'", path))?;

        let mut list = Vec::new();
        for entry in entries {
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let meta = entry.metadata();
            let ft = meta.file_type();
            let is_symlink = ft.is_symlink();
            let full_path = join_remote_path(path, &name);

            // For symlinks, check if target is a directory so navigation works seamlessly
            let is_dir = if is_symlink {
                self.sftp
                    .metadata(&full_path)
                    .await
                    .map(|m| m.file_type().is_dir())
                    .unwrap_or(false)
            } else {
                ft.is_dir()
            };

            list.push(RemoteEntry {
                name,
                path: full_path,
                is_dir,
                is_symlink,
                size: meta.size.unwrap_or(0),
                permissions: meta.permissions,
                mtime: meta.mtime,
            });
        }

        // Sort: directories first, then alphabetical (case-insensitive)
        list.sort_by(|a, b| {
            b.is_dir
                .cmp(&a.is_dir)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });

        Ok(list)
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        self.sftp
            .create_dir(path)
            .await
            .with_context(|| format!("Impossible de créer le dossier '{}'", path))
    }

    pub async fn rename(&self, old_path: &str, new_path: &str) -> Result<()> {
        self.sftp
            .rename(old_path, new_path)
            .await
            .with_context(|| format!("Impossible de renommer '{}' en '{}'", old_path, new_path))
    }

    pub async fn remove_recursive(&self, path: &str, is_dir: bool) -> Result<()> {
        if !is_dir {
            self.sftp
                .remove_file(path)
                .await
                .with_context(|| format!("Impossible de supprimer le fichier '{}'", path))?;
            return Ok(());
        }
        self.remove_dir_recursive_boxed(path.to_string()).await
    }

    fn remove_dir_recursive_boxed<'a>(
        &'a self,
        path: String,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>> {
        Box::pin(async move {
            let entries = self.list_dir(&path).await?;
            for entry in entries {
                if entry.is_dir && !entry.is_symlink {
                    self.remove_dir_recursive_boxed(entry.path).await?;
                } else {
                    self.sftp.remove_file(&entry.path).await.with_context(|| {
                        format!("Impossible de supprimer '{}'", entry.path)
                    })?;
                }
            }
            self.sftp
                .remove_dir(&path)
                .await
                .with_context(|| format!("Impossible de supprimer le dossier '{}'", path))
        })
    }

    /// Reads up to `max_bytes` from a remote file for inline preview.
    pub async fn read_preview(&self, remote_path: &str, max_bytes: usize) -> Result<(Vec<u8>, bool)> {
        let mut file = self
            .sftp
            .open(remote_path)
            .await
            .with_context(|| format!("Impossible d'ouvrir '{}'", remote_path))?;

        let mut buf = vec![0u8; max_bytes + 1];
        let mut total = 0;
        while total < buf.len() {
            let n = file
                .read(&mut buf[total..])
                .await
                .with_context(|| format!("Erreur de lecture de '{}'", remote_path))?;
            if n == 0 {
                break;
            }
            total += n;
        }
        let truncated = total > max_bytes;
        buf.truncate(total.min(max_bytes));
        Ok((buf, truncated))
    }

    /// Expands leading `~` or `~/` using the remote SFTP home directory (`canonicalize(".")`).
    pub async fn expand_remote_path(&self, path: &str) -> String {
        let trimmed = path.trim();
        if trimmed == "~" {
            return self.canonicalize(".").await.unwrap_or_else(|_| ".".to_string());
        }
        if let Some(rest) = trimmed.strip_prefix("~/") {
            let home = self.canonicalize(".").await.unwrap_or_else(|_| ".".to_string());
            return join_remote_path(&home, rest);
        }
        trimmed.to_string()
    }

    /// Downloads a remote file or directory (recursively) to `local_dest`.
    /// If `local_dest` is an existing directory, the remote file/folder name is appended automatically.
    pub async fn download<F>(
        &self,
        remote_path: &str,
        local_dest: &Path,
        mut on_progress: F,
    ) -> Result<(PathBuf, TransferStats)>
    where
        F: FnMut(&str, u64, Option<u64>),
    {
        let remote_path = self.expand_remote_path(remote_path).await;
        let meta = self
            .sftp
            .metadata(&remote_path)
            .await
            .with_context(|| format!("Chemin distant introuvable : '{}'", remote_path))?;

        let remote_name = remote_file_name(&remote_path);
        let target = if local_dest.is_dir() {
            local_dest.join(&remote_name)
        } else {
            local_dest.to_path_buf()
        };

        let mut stats = TransferStats::default();
        if meta.file_type().is_dir() {
            self.download_dir_boxed(
                remote_path,
                target.clone(),
                &mut stats,
                &mut on_progress,
            )
            .await?;
        } else {
            self.download_file(&remote_path, &target, meta.size, &mut stats, &mut on_progress)
                .await?;
        }

        Ok((target, stats))
    }

    async fn download_file<F>(
        &self,
        remote_path: &str,
        local_path: &Path,
        total_size: Option<u64>,
        stats: &mut TransferStats,
        on_progress: &mut F,
    ) -> Result<()>
    where
        F: FnMut(&str, u64, Option<u64>),
    {
        if let Some(parent) = local_path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await.with_context(|| {
                    format!("Impossible de créer le dossier local '{}'", parent.display())
                })?;
            }
        }

        let mut remote_file = self
            .sftp
            .open(remote_path)
            .await
            .with_context(|| format!("Impossible d'ouvrir le fichier distant '{}'", remote_path))?;

        let mut local_file = tokio::fs::File::create(local_path).await.with_context(|| {
            format!(
                "Impossible de créer le fichier local '{}'",
                local_path.display()
            )
        })?;

        let name = remote_file_name(remote_path);
        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut transferred: u64 = 0;

        loop {
            let n = remote_file
                .read(&mut buf)
                .await
                .with_context(|| format!("Erreur de lecture distante '{}'", remote_path))?;
            if n == 0 {
                break;
            }
            local_file
                .write_all(&buf[..n])
                .await
                .with_context(|| format!("Erreur d'écriture locale '{}'", local_path.display()))?;
            transferred += n as u64;
            on_progress(&name, transferred, total_size);
        }

        local_file.flush().await?;
        stats.files += 1;
        stats.bytes += transferred;
        Ok(())
    }

    fn download_dir_boxed<'a, F>(
        &'a self,
        remote_dir: String,
        local_dir: PathBuf,
        stats: &'a mut TransferStats,
        on_progress: &'a mut F,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>>
    where
        F: FnMut(&str, u64, Option<u64>) + 'a,
    {
        Box::pin(async move {
            tokio::fs::create_dir_all(&local_dir).await.with_context(|| {
                format!(
                    "Impossible de créer le dossier local '{}'",
                    local_dir.display()
                )
            })?;

            let entries = self.list_dir(&remote_dir).await?;
            for entry in entries {
                let child_local = local_dir.join(&entry.name);
                if entry.is_dir && !entry.is_symlink {
                    self.download_dir_boxed(entry.path, child_local, stats, on_progress)
                        .await?;
                } else if !entry.is_symlink {
                    self.download_file(
                        &entry.path,
                        &child_local,
                        Some(entry.size),
                        stats,
                        on_progress,
                    )
                    .await?;
                }
            }
            Ok(())
        })
    }

    /// Uploads a local file or directory (recursively) into `remote_dest`.
    pub async fn upload<F>(
        &self,
        local_source: &Path,
        remote_dest: &str,
        mut on_progress: F,
    ) -> Result<(String, TransferStats)>
    where
        F: FnMut(&str, u64, Option<u64>),
    {
        if !local_source.exists() {
            bail!("Fichier ou dossier local introuvable : '{}'", local_source.display());
        }

        let canonical_local = std::fs::canonicalize(local_source).ok();
        let file_name = local_source
            .file_name()
            .or_else(|| canonical_local.as_deref().and_then(|p| p.file_name()))
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow!("Nom de fichier local invalide : '{}'", local_source.display()))?
            .to_string();

        let remote_dest = self.expand_remote_path(remote_dest).await;
        // Convert any accidental Windows backslashes in remote Linux path to `/`
        let remote_dest = remote_dest.replace('\\', "/");

        // Check if remote_dest is an existing directory (or ends with '/'); if so, append local filename
        let remote_is_dir = remote_dest.ends_with('/')
            || self
                .sftp
                .metadata(&remote_dest)
                .await
                .map(|m| m.file_type().is_dir())
                .unwrap_or(false);

        let target_remote = if remote_is_dir {
            join_remote_path(&remote_dest, &file_name)
        } else {
            remote_dest
        };

        let mut stats = TransferStats::default();
        if local_source.is_dir() {
            self.upload_dir_boxed(
                local_source.to_path_buf(),
                target_remote.clone(),
                &mut stats,
                &mut on_progress,
            )
            .await?;
        } else {
            self.upload_file(local_source, &target_remote, &mut stats, &mut on_progress)
                .await?;
        }

        Ok((target_remote, stats))
    }

    async fn upload_file<F>(
        &self,
        local_path: &Path,
        remote_path: &str,
        stats: &mut TransferStats,
        on_progress: &mut F,
    ) -> Result<()>
    where
        F: FnMut(&str, u64, Option<u64>),
    {
        let meta = tokio::fs::metadata(local_path).await.with_context(|| {
            format!("Impossible de lire les métadonnées de '{}'", local_path.display())
        })?;
        let total_size = Some(meta.len());

        let mut local_file = tokio::fs::File::open(local_path).await.with_context(|| {
            format!("Impossible d'ouvrir le fichier local '{}'", local_path.display())
        })?;

        let mut remote_file = self
            .sftp
            .open_with_flags(
                remote_path,
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            )
            .await
            .with_context(|| format!("Impossible de créer le fichier distant '{}'", remote_path))?;

        let name = local_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("fichier")
            .to_string();
        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut transferred: u64 = 0;

        loop {
            let n = local_file
                .read(&mut buf)
                .await
                .with_context(|| format!("Erreur de lecture locale '{}'", local_path.display()))?;
            if n == 0 {
                break;
            }
            remote_file
                .write_all(&buf[..n])
                .await
                .with_context(|| format!("Erreur d'écriture distante '{}'", remote_path))?;
            transferred += n as u64;
            on_progress(&name, transferred, total_size);
        }

        remote_file.flush().await?;
        remote_file.shutdown().await?;
        stats.files += 1;
        stats.bytes += transferred;
        Ok(())
    }

    fn upload_dir_boxed<'a, F>(
        &'a self,
        local_dir: PathBuf,
        remote_dir: String,
        stats: &'a mut TransferStats,
        on_progress: &'a mut F,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>>
    where
        F: FnMut(&str, u64, Option<u64>) + 'a,
    {
        Box::pin(async move {
            if !self.sftp.try_exists(&remote_dir).await.unwrap_or(false) {
                self.sftp.create_dir(&remote_dir).await.with_context(|| {
                    format!("Impossible de créer le dossier distant '{}'", remote_dir)
                })?;
            }

            let mut reader = tokio::fs::read_dir(&local_dir).await.with_context(|| {
                format!("Impossible de lire le dossier local '{}'", local_dir.display())
            })?;

            while let Some(entry) = reader.next_entry().await? {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                let child_remote = join_remote_path(&remote_dir, &name);
                let file_type = entry.file_type().await?;

                if file_type.is_dir() {
                    self.upload_dir_boxed(path, child_remote, stats, on_progress)
                        .await?;
                } else if file_type.is_file() {
                    self.upload_file(&path, &child_remote, stats, on_progress)
                        .await?;
                }
            }
            Ok(())
        })
    }

    pub async fn close(self) {
        let _ = self.sftp.close().await;
        let _ = self
            .session
            .disconnect(Disconnect::ByApplication, "", "fr")
            .await;
    }
}

pub fn join_remote_path(base: &str, child: &str) -> String {
    if child.starts_with('/') {
        return child.to_string();
    }
    if base.is_empty() || base == "." {
        child.to_string()
    } else if base.ends_with('/') {
        format!("{base}{child}")
    } else {
        format!("{base}/{child}")
    }
}

pub fn parent_remote_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/".to_string();
    }
    match trimmed.rfind('/') {
        Some(0) => "/".to_string(),
        Some(idx) => trimmed[..idx].to_string(),
        None => ".".to_string(),
    }
}

pub fn remote_file_name(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(idx) if idx + 1 < trimmed.len() => trimmed[idx + 1..].to_string(),
        _ => {
            if trimmed.is_empty() {
                "download".to_string()
            } else {
                trimmed.to_string()
            }
        }
    }
}

pub fn default_download_dir() -> PathBuf {
    directories::UserDirs::new()
        .and_then(|u| u.download_dir().map(|p| p.to_path_buf()))
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Resolves a user-entered local path, handling Windows Explorer quotes (`"C:\..."`),
/// PowerShell drag-and-drop prefixes (`& '...'`), and leading `~`.
pub fn resolve_local_path(input: &str) -> PathBuf {
    let mut s = input.trim();
    // PowerShell drag-and-drop often prefixes with `& `
    if let Some(rest) = s.strip_prefix("& ") {
        s = rest.trim();
    }
    // Strip matching surrounding double or single quotes (e.g. Windows "Copy as path")
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        s = &s[1..s.len() - 1];
    }
    expand_tilde(s)
}

pub fn format_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let b = bytes as f64;
    if b >= GB {
        format!("{:.1} Go", b / GB)
    } else if b >= MB {
        format!("{:.1} Mo", b / MB)
    } else if b >= KB {
        format!("{:.1} Ko", b / KB)
    } else {
        format!("{bytes} o")
    }
}

pub fn format_permissions(perms: Option<u32>, is_dir: bool, is_symlink: bool) -> String {
    let Some(mode) = perms else {
        return "----------".to_string();
    };
    let mut s = String::with_capacity(10);
    s.push(if is_symlink {
        'l'
    } else if is_dir {
        'd'
    } else {
        '-'
    });
    let flags = [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ];
    for (bit, ch) in flags {
        s.push(if mode & bit != 0 { ch } else { '-' });
    }
    s
}

pub fn format_mtime(mtime: Option<u32>) -> String {
    let Some(ts) = mtime else {
        return "—".to_string();
    };
    let Some(dt_utc) = DateTime::<Utc>::from_timestamp(ts as i64, 0) else {
        return "—".to_string();
    };
    let local: DateTime<Local> = dt_utc.into();
    local.format("%d/%m/%Y %H:%M").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_path_helpers_work() {
        assert_eq!(join_remote_path("/home/gigi", "notes.txt"), "/home/gigi/notes.txt");
        assert_eq!(join_remote_path("/", "etc"), "/etc");
        assert_eq!(join_remote_path("/home/gigi/", "docs"), "/home/gigi/docs");
        assert_eq!(join_remote_path("/home/gigi", "/tmp/a"), "/tmp/a");

        assert_eq!(parent_remote_path("/home/gigi/docs"), "/home/gigi");
        assert_eq!(parent_remote_path("/home"), "/");
        assert_eq!(parent_remote_path("/"), "/");

        assert_eq!(remote_file_name("/home/gigi/photo.png"), "photo.png");
        assert_eq!(remote_file_name("/home/gigi/docs/"), "docs");
    }

    #[test]
    fn windows_quoted_and_drag_drop_paths_are_cleaned() {
        assert_eq!(
            resolve_local_path(r#" "C:\Users\Gigi\Desktop\mon fichier.txt" "#),
            PathBuf::from(r"C:\Users\Gigi\Desktop\mon fichier.txt")
        );
        assert_eq!(
            resolve_local_path(r#"& 'C:\Users\Gigi\test.pdf'"#),
            PathBuf::from(r"C:\Users\Gigi\test.pdf")
        );
    }

    #[test]
    fn formatting_helpers_work() {
        assert_eq!(format_size(512), "512 o");
        assert_eq!(format_size(2048), "2.0 Ko");
        assert_eq!(format_size(5 * 1024 * 1024), "5.0 Mo");
        assert_eq!(format_permissions(Some(0o755), true, false), "drwxr-xr-x");
        assert_eq!(format_permissions(Some(0o644), false, false), "-rw-r--r--");
    }
}
