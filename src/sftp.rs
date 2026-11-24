use crate::models::{AuthMethod, SshHost};
use crate::ssh::{connect_and_authenticate, exec_remote_command, SshClientHandler};
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
use zeroize::Zeroizing;

const CHUNK_SIZE: usize = 64 * 1024;

const REMOTE_SFTP_INSTALL_SCRIPT: &str = r#"set -e
has_sftp() {
  for p in /usr/lib/openssh/sftp-server /usr/libexec/sftp-server /usr/lib/ssh/sftp-server /usr/libexec/openssh/sftp-server; do
    [ -x "$p" ] && return 0
  done
  command -v sftp-server >/dev/null 2>&1
}

if ! has_sftp; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-sftp-server
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm openssh
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q openssh-server
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q openssh-server
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache openssh-sftp-server
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install openssh
  elif command -v opkg >/dev/null 2>&1; then
    opkg update && opkg install openssh-sftp-server
  fi
fi

if [ -f /etc/ssh/sshd_config ]; then
  if ! grep -Eq '^[[:space:]]*Subsystem[[:space:]]+sftp[[:space:]]' /etc/ssh/sshd_config; then
    printf '\nSubsystem sftp internal-sftp\n' >> /etc/ssh/sshd_config
  fi
  if command -v sshd >/dev/null 2>&1; then
    sshd -t
  fi
  if command -v systemctl >/dev/null 2>&1; then
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
  elif command -v service >/dev/null 2>&1; then
    service ssh reload 2>/dev/null || service sshd reload 2>/dev/null || service ssh restart 2>/dev/null || service sshd restart 2>/dev/null || true
  elif [ -f /run/sshd.pid ]; then
    kill -HUP "$(cat /run/sshd.pid)" 2>/dev/null || true
  elif [ -f /var/run/sshd.pid ]; then
    kill -HUP "$(cat /var/run/sshd.pid)" 2>/dev/null || true
  fi
fi
"#;

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
    /// If SFTP is not installed or not enabled on the remote Linux host, automatically
    /// installs/enables it and retries once.
    pub async fn connect(host: &SshHost, storage: Arc<Storage>) -> Result<Self> {
        let session = connect_and_authenticate(host, Arc::clone(&storage)).await?;

        match try_open_sftp_subsystem(&session).await {
            Ok(sftp) => Ok(Self { session, sftp }),
            Err(first_err) => {
                eprintln!(
                    "\x1b[1;33m[ssha]\x1b[0m {}",
                    t!(
                        "sftp.not_active",
                        name = format!("\x1b[1m{}\x1b[0m", host.name),
                        error = first_err
                    )
                );
                eprintln!("\x1b[1;36m[ssha]\x1b[0m {}", t!("sftp.installing"));

                ensure_remote_sftp_installed(&session, host).await?;
                let _ = session
                    .disconnect(Disconnect::ByApplication, "", "en")
                    .await;

                // Reconnect so the reloaded sshd picks up the new SFTP subsystem
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                let fresh_session = connect_and_authenticate(host, storage).await?;
                let sftp = try_open_sftp_subsystem(&fresh_session)
                    .await
                    .with_context(|| t!("sftp.err.still_unavailable").into_owned())?;

                eprintln!(
                    "\x1b[1;32m✓\x1b[0m {}",
                    t!(
                        "sftp.installed",
                        name = format!("\x1b[1m{}\x1b[0m", host.name)
                    )
                );
                Ok(Self {
                    session: fresh_session,
                    sftp,
                })
            }
        }
    }

    pub async fn canonicalize(&self, path: &str) -> Result<String> {
        self.sftp
            .canonicalize(path)
            .await
            .with_context(|| t!("sftp.err.resolve", path = path).into_owned())
    }

    pub async fn list_dir(&self, path: &str) -> Result<Vec<RemoteEntry>> {
        let entries = self
            .sftp
            .read_dir(path)
            .await
            .with_context(|| t!("sftp.err.read_remote_dir", path = path).into_owned())?;

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
            .with_context(|| t!("sftp.err.mkdir", path = path).into_owned())
    }

    pub async fn rename(&self, old_path: &str, new_path: &str) -> Result<()> {
        self.sftp
            .rename(old_path, new_path)
            .await
            .with_context(|| t!("sftp.err.rename", from = old_path, to = new_path).into_owned())
    }

    pub async fn remove_recursive(&self, path: &str, is_dir: bool) -> Result<()> {
        if !is_dir {
            self.sftp
                .remove_file(path)
                .await
                .with_context(|| t!("sftp.err.delete_file", path = path).into_owned())?;
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
                    self.sftp
                        .remove_file(&entry.path)
                        .await
                        .with_context(|| t!("sftp.err.delete", path = entry.path).into_owned())?;
                }
            }
            self.sftp
                .remove_dir(&path)
                .await
                .with_context(|| t!("sftp.err.delete_dir", path = path).into_owned())
        })
    }

    /// Reads up to `max_bytes` from a remote file for inline preview.
    pub async fn read_preview(
        &self,
        remote_path: &str,
        max_bytes: usize,
    ) -> Result<(Vec<u8>, bool)> {
        let mut file = self
            .sftp
            .open(remote_path)
            .await
            .with_context(|| t!("sftp.err.open", path = remote_path).into_owned())?;

        let mut buf = vec![0u8; max_bytes + 1];
        let mut total = 0;
        while total < buf.len() {
            let n = file
                .read(&mut buf[total..])
                .await
                .with_context(|| t!("sftp.err.read_remote", path = remote_path).into_owned())?;
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
            return self
                .canonicalize(".")
                .await
                .unwrap_or_else(|_| ".".to_string());
        }
        if let Some(rest) = trimmed.strip_prefix("~/") {
            let home = self
                .canonicalize(".")
                .await
                .unwrap_or_else(|_| ".".to_string());
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
        let meta =
            self.sftp.metadata(&remote_path).await.with_context(|| {
                t!("sftp.err.remote_not_found", path = remote_path).into_owned()
            })?;

        let remote_name = remote_file_name(&remote_path);
        let target = if local_dest.is_dir() {
            local_dest.join(&remote_name)
        } else {
            local_dest.to_path_buf()
        };

        let mut stats = TransferStats::default();
        if meta.file_type().is_dir() {
            self.download_dir_boxed(remote_path, target.clone(), &mut stats, &mut on_progress)
                .await?;
        } else {
            self.download_file(
                &remote_path,
                &target,
                meta.size,
                &mut stats,
                &mut on_progress,
            )
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
                    t!("sftp.err.mkdir_local", path = parent.display()).into_owned()
                })?;
            }
        }

        let mut remote_file = self
            .sftp
            .open(remote_path)
            .await
            .with_context(|| t!("sftp.err.open_remote", path = remote_path).into_owned())?;

        let mut local_file = tokio::fs::File::create(local_path).await.with_context(|| {
            t!("sftp.err.create_local", path = local_path.display()).into_owned()
        })?;

        let name = remote_file_name(remote_path);
        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut transferred: u64 = 0;

        loop {
            let n = remote_file
                .read(&mut buf)
                .await
                .with_context(|| t!("sftp.err.read_remote", path = remote_path).into_owned())?;
            if n == 0 {
                break;
            }
            local_file.write_all(&buf[..n]).await.with_context(|| {
                t!("sftp.err.write_local", path = local_path.display()).into_owned()
            })?;
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
            tokio::fs::create_dir_all(&local_dir)
                .await
                .with_context(|| {
                    t!("sftp.err.mkdir_local", path = local_dir.display()).into_owned()
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
            bail!(t!("cli.sftp.local_not_found", path = local_source.display()).into_owned());
        }

        let canonical_local = std::fs::canonicalize(local_source).ok();
        let file_name = local_source
            .file_name()
            .or_else(|| canonical_local.as_deref().and_then(|p| p.file_name()))
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                anyhow!(t!("sftp.err.local_name", path = local_source.display()).into_owned())
            })?
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
        let meta = tokio::fs::metadata(local_path)
            .await
            .with_context(|| t!("sftp.err.metadata", path = local_path.display()).into_owned())?;
        let total_size = Some(meta.len());

        let mut local_file = tokio::fs::File::open(local_path)
            .await
            .with_context(|| t!("sftp.err.open_local", path = local_path.display()).into_owned())?;

        let mut remote_file = self
            .sftp
            .open_with_flags(
                remote_path,
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            )
            .await
            .with_context(|| t!("sftp.err.create_remote", path = remote_path).into_owned())?;

        let name = local_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        let mut buf = vec![0u8; CHUNK_SIZE];
        let mut transferred: u64 = 0;

        loop {
            let n = local_file.read(&mut buf).await.with_context(|| {
                t!("sftp.err.read_local", path = local_path.display()).into_owned()
            })?;
            if n == 0 {
                break;
            }
            remote_file
                .write_all(&buf[..n])
                .await
                .with_context(|| t!("sftp.err.write_remote", path = remote_path).into_owned())?;
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
                self.sftp
                    .create_dir(&remote_dir)
                    .await
                    .with_context(|| t!("sftp.err.mkdir_remote", path = remote_dir).into_owned())?;
            }

            let mut reader = tokio::fs::read_dir(&local_dir).await.with_context(|| {
                t!("sftp.err.read_local_dir", path = local_dir.display()).into_owned()
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

async fn try_open_sftp_subsystem(
    session: &client::Handle<SshClientHandler>,
) -> Result<SftpSession> {
    let channel = session
        .channel_open_session()
        .await
        .context(t!("sftp.err.channel").into_owned())?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .context(t!("sftp.err.subsystem_refused").into_owned())?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .context(t!("sftp.err.init").into_owned())?;
    Ok(sftp)
}

async fn ensure_remote_sftp_installed(
    session: &client::Handle<SshClientHandler>,
    host: &SshHost,
) -> Result<()> {
    // Check that the remote host is a POSIX/Linux system
    let (uname_code, uname_out) = exec_remote_command(session, "uname -s", None).await?;
    if uname_code != 0 || !uname_out.to_lowercase().contains("linux") {
        let detected = if uname_out.is_empty() {
            t!("sftp.unknown_os").into_owned()
        } else {
            uname_out.clone()
        };
        bail!(t!("sftp.err.linux_only", os = detected).into_owned());
    }

    let quoted_script = shell_single_quote(REMOTE_SFTP_INSTALL_SCRIPT);

    // Determine privilege escalation method: root, passwordless sudo, or sudo -S with saved password
    let (_, uid_out) = exec_remote_command(session, "id -u", None).await?;
    let (exit_code, output) = if uid_out.trim() == "0" {
        exec_remote_command(session, &format!("sh -c {quoted_script}"), None).await?
    } else {
        let (sudo_nopass, _) = exec_remote_command(session, "sudo -n true", None).await?;
        if sudo_nopass == 0 {
            exec_remote_command(session, &format!("sudo -n sh -c {quoted_script}"), None).await?
        } else if let AuthMethod::Password { ref password } = host.auth {
            let stdin_pw = Zeroizing::new(format!("{password}\n"));
            exec_remote_command(
                session,
                &format!("sudo -S -p '' sh -c {quoted_script}"),
                Some(stdin_pw.as_bytes()),
            )
            .await?
        } else {
            bail!(t!("sftp.err.root_required", name = host.name).into_owned());
        }
    };

    if exit_code != 0 {
        let output = if output.is_empty() {
            t!("sftp.no_output").into_owned()
        } else {
            output
        };
        bail!(t!("sftp.err.install_failed", code = exit_code, output = output).into_owned());
    }

    Ok(())
}

fn shell_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
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
    let units = t!("sftp.size_units");
    let units: Vec<&str> = units.split(',').map(str::trim).collect();
    format_size_with(bytes, &units, &t!("monitor.decimal_sep"))
}

/// `units` = [bytes, KB, MB, GB] symbols of the active language.
fn format_size_with(bytes: u64, units: &[&str], decimal_sep: &str) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let unit = |i: usize| units.get(i).copied().unwrap_or(["B", "KB", "MB", "GB"][i]);

    let b = bytes as f64;
    let (value, idx) = if b >= GB {
        (b / GB, 3)
    } else if b >= MB {
        (b / MB, 2)
    } else if b >= KB {
        (b / KB, 1)
    } else {
        return format!("{bytes} {}", unit(0));
    };
    format!("{:.1} {}", value, unit(idx)).replace('.', decimal_sep)
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
    local.format(&t!("common.time.datetime_format")).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_path_helpers_work() {
        assert_eq!(
            join_remote_path("/home/gigi", "notes.txt"),
            "/home/gigi/notes.txt"
        );
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
            resolve_local_path(r#" "C:\Users\Gigi\Desktop\my file.txt" "#),
            PathBuf::from(r"C:\Users\Gigi\Desktop\my file.txt")
        );
        assert_eq!(
            resolve_local_path(r#"& 'C:\Users\Gigi\test.pdf'"#),
            PathBuf::from(r"C:\Users\Gigi\test.pdf")
        );
    }

    #[test]
    fn formatting_helpers_work() {
        let fr = ["o", "Ko", "Mo", "Go"];
        assert_eq!(format_size_with(512, &fr, ","), "512 o");
        assert_eq!(format_size_with(2048, &fr, ","), "2,0 Ko");
        assert_eq!(
            format_size_with(5 * 1024 * 1024, &["B", "KB", "MB", "GB"], "."),
            "5.0 MB"
        );
        assert_eq!(format_permissions(Some(0o755), true, false), "drwxr-xr-x");
        assert_eq!(format_permissions(Some(0o644), false, false), "-rw-r--r--");
    }
}
