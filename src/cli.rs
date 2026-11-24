use crate::crypto::protection_summary;
use crate::files_tui;
use crate::i18n::{self, tn, tr, Lang};
use crate::models::{format_relative_time, AuthMethod, LocalForwardSpec, SshHost};
use crate::picker::{self, PickerResult};
use crate::sftp::{self, SftpClient};
use crate::ssh;
use crate::ssh_config;
use crate::storage::{export_vault_to_file, import_vault_from_file, Storage};
use anyhow::{bail, Result};
use chrono::Utc;
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use std::io::{self, Write};
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(
    name = "ssha",
    version,
    about = "100% CLI SSH & SFTP connection manager with an encrypted vault (Windows, Linux, macOS)",
    long_about = "Run `ssha` without arguments to open the interactive interface (with /new, /files, /export, /import, /import-ssh),\nor pass a machine name directly (`ssha my-pc`) to connect to it instantly."
)]
pub struct Cli {
    /// Name of a saved connection to connect to directly
    #[arg(value_name = "NAME")]
    pub target: Option<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Add a new SSH connection
    #[command(visible_alias = "add")]
    New(NewArgs),

    /// List all saved connections
    #[command(visible_alias = "ls")]
    List,

    /// Open the remote file manager (SFTP) on a machine
    #[command(visible_alias = "sftp")]
    Files {
        /// Connection name / alias
        name: String,
        /// Initial remote folder (optional)
        path: Option<String>,
    },

    /// Download a file or folder from a remote machine
    #[command(visible_aliases = ["download", "dl"])]
    Get {
        /// Connection name / alias
        name: String,
        /// Path of the file or folder on the remote machine
        remote: String,
        /// Local destination path (default: Downloads folder)
        local: Option<String>,
    },

    /// Upload a local file or folder to a remote machine
    #[command(visible_aliases = ["upload", "up"])]
    Put {
        /// Connection name / alias
        name: String,
        /// Local file or folder path (if omitted, opens the native file dialog)
        local: Option<String>,
        /// Remote destination folder or path (default: remote home folder)
        remote: Option<String>,
        /// Open the folder picker (when no local path is given)
        #[arg(short = 'd', long)]
        dir: bool,
    },

    /// Export all connections (IPs, users, passwords) to a portable JSON file
    #[command(visible_alias = "backup")]
    Export {
        /// Output file (if omitted, opens the Save dialog or creates ssha-config.json)
        output: Option<String>,
    },

    /// Import connections from a file exported by another ssha
    #[command(visible_alias = "restore")]
    Import {
        /// JSON file to import (if omitted, opens the Open dialog)
        input: Option<String>,
        /// Do not overwrite existing connections with the same name
        #[arg(long)]
        keep_existing: bool,
    },

    /// Automatically import hosts from ~/.ssh/config (OpenSSH)
    #[command(name = "import-ssh")]
    ImportSsh {
        /// Path to the SSH config file (default: ~/.ssh/config)
        path: Option<String>,
        /// Overwrite existing connections with the same name
        #[arg(long)]
        overwrite: bool,
    },

    /// Manage vault security (automatic key or optional master password)
    Security {
        #[command(subcommand)]
        action: SecurityAction,
    },

    /// Delete a saved connection
    #[command(visible_aliases = ["delete", "del"])]
    Rm {
        /// Name / alias of the connection to delete
        name: String,
        /// Do not ask for confirmation
        #[arg(short = 'y', long)]
        yes: bool,
    },

    /// Test whether a machine answers on its SSH port
    Test {
        /// Name / alias of the connection to test
        name: String,
    },

    /// Check for and install the latest ssha update
    #[command(visible_alias = "upgrade")]
    Update {
        /// Update without asking for confirmation
        #[arg(short = 'y', long)]
        yes: bool,
    },

    /// Show the new features and fixes of recent versions
    #[command(visible_alias = "whatsnew")]
    Changelog {
        /// Number of versions to show (default: 3)
        #[arg(short = 'n', long)]
        count: Option<usize>,
    },

    /// Show or change the interface language (en, fr, ru, uk, es, it)
    #[command(visible_alias = "language")]
    Lang {
        /// Language code; without it, opens the language picker
        code: Option<String>,
    },

    /// Show the encrypted vault location and security information
    Info,
}

#[derive(Subcommand, Debug)]
pub enum SecurityAction {
    /// Show the current encryption mode (automatic key or master password)
    Status,
    /// Enable an optional master password (Argon2id + AES-256-GCM, portable vault)
    EnableMasterPassword,
    /// Go back to the automatic key mode without a master password
    DisableMasterPassword,
}

#[derive(Args, Debug)]
pub struct NewArgs {
    /// Machine name / alias (e.g. my-pc)
    #[arg(short, long)]
    pub name: Option<String>,

    /// IP address or hostname (e.g. 192.168.1.192)
    #[arg(short = 'H', long)]
    pub host: Option<String>,

    /// SSH port (default: 22)
    #[arg(short, long)]
    pub port: Option<u16>,

    /// SSH username
    #[arg(short, long)]
    pub user: Option<String>,

    /// Path to an SSH private key (instead of a password)
    #[arg(short, long)]
    pub key: Option<String>,

    /// Optional group / tag (e.g. Home, Prod)
    #[arg(short, long)]
    pub group: Option<String>,

    /// Optional note / description
    #[arg(long)]
    pub note: Option<String>,

    /// Bastion / ProxyJump (name of an ssha machine or user@host[:port])
    #[arg(short = 'J', long)]
    pub proxy_jump: Option<String>,

    /// Local port forwarding (-L local_port:remote_host:remote_port), repeatable
    #[arg(short = 'L', long)]
    pub local_forward: Vec<String>,

    /// Show live CPU/RAM usage of this machine in the ssha list
    #[arg(short = 'm', long)]
    pub monitor: bool,
}

/// Parses the command line with `--help` texts translated into the active language.
pub fn parse_localized() -> Cli {
    let matches = localize_command(Cli::command(), "cli.help").get_matches();
    match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(e) => e.exit(),
    }
}

fn has_key(key: &str) -> bool {
    crate::_rust_i18n_try_translate(&rust_i18n::locale(), key).is_some()
}

fn localize_command(mut cmd: clap::Command, prefix: &str) -> clap::Command {
    let about_key = format!("{prefix}.about");
    if has_key(&about_key) {
        cmd = cmd.about(tr(&about_key));
    }
    let long_key = format!("{prefix}.long_about");
    if has_key(&long_key) {
        cmd = cmd.long_about(tr(&long_key));
    }
    let arg_ids: Vec<String> = cmd
        .get_arguments()
        .map(|a| a.get_id().to_string())
        .collect();
    for id in arg_ids {
        let key = format!("{prefix}.arg.{id}");
        if has_key(&key) {
            let text = tr(&key);
            cmd = cmd.mut_arg(id, |a| a.help(text));
        }
    }
    let subs: Vec<String> = cmd
        .get_subcommands()
        .map(|s| s.get_name().to_string())
        .collect();
    for sub in subs {
        let sub_prefix = format!("{prefix}.{sub}");
        cmd = cmd.mut_subcommand(&sub, |sc| localize_command(sc, &sub_prefix));
    }
    cmd
}

fn bold(s: impl std::fmt::Display) -> String {
    format!("\x1b[1m{s}\x1b[0m")
}

fn cyan(s: impl std::fmt::Display) -> String {
    format!("\x1b[1;36m{s}\x1b[0m")
}

fn not_found(name: &str) -> anyhow::Error {
    anyhow::anyhow!(t!("cli.err.not_found", name = name).into_owned())
}

pub fn cmd_new(storage: &Storage, args: NewArgs) -> Result<()> {
    let mut vault = storage.load_vault()?;

    println!("{} {}\n", cyan("[ssha]"), t!("cli.new.title"));

    let name = match args.name {
        Some(n) => n.trim().to_string(),
        None => prompt_required(&t!("cli.new.prompt_name"))?,
    };
    if name.starts_with('/') {
        bail!(t!("common.err.name_slash").into_owned());
    }
    if vault.find_by_name(&name).is_some() {
        bail!(t!("common.err.name_exists", name = name).into_owned());
    }

    let host = match args.host {
        Some(h) => h.trim().to_string(),
        None => prompt_required(&t!("cli.new.prompt_host"))?,
    };

    let port = match args.port {
        Some(p) => p,
        None => {
            let input = prompt_optional(&t!("cli.new.prompt_port"))?;
            if input.is_empty() {
                22
            } else {
                input
                    .parse::<u16>()
                    .ok()
                    .filter(|&p| p > 0)
                    .ok_or_else(|| {
                        anyhow::anyhow!(t!("common.err.invalid_port", port = input).into_owned())
                    })?
            }
        }
    };

    let default_user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "root".to_string());
    let username = match args.user {
        Some(u) => u.trim().to_string(),
        None => {
            let input = prompt_optional(&t!("cli.new.prompt_user", user = default_user))?;
            if input.is_empty() {
                default_user
            } else {
                input
            }
        }
    };

    let auth = if let Some(key_path) = args.key {
        let passphrase =
            rpassword::prompt_password(format!("{} : ", t!("cli.new.prompt_passphrase")))?;
        AuthMethod::Key {
            path: key_path.trim().to_string(),
            passphrase: if passphrase.is_empty() {
                None
            } else {
                Some(passphrase)
            },
        }
    } else {
        let mode = prompt_optional(&t!("cli.new.prompt_auth_kind"))?;
        let mode = mode.to_lowercase();
        let key_answers = t!("cli.new.key_answers");
        if key_answers.split(',').any(|w| w.trim() == mode) {
            let path = prompt_optional(&t!("cli.new.prompt_key_path"))?;
            let path = if path.is_empty() {
                "~/.ssh/id_ed25519".to_string()
            } else {
                path
            };
            let passphrase =
                rpassword::prompt_password(format!("{} : ", t!("cli.new.prompt_passphrase")))?;
            AuthMethod::Key {
                path,
                passphrase: if passphrase.is_empty() {
                    None
                } else {
                    Some(passphrase)
                },
            }
        } else {
            let password =
                rpassword::prompt_password(format!("{} : ", t!("cli.new.prompt_password")))?;
            if password.is_empty() {
                bail!(t!("common.err.password_empty").into_owned());
            }
            AuthMethod::Password { password }
        }
    };

    let group = match args.group {
        Some(g) => non_empty(&g),
        None => non_empty(&prompt_optional(&t!("cli.new.prompt_group"))?),
    };
    let note = match args.note {
        Some(n) => non_empty(&n),
        None => non_empty(&prompt_optional(&t!("cli.new.prompt_note"))?),
    };

    let mut local_forwards = Vec::new();
    for spec_str in &args.local_forward {
        let spec = LocalForwardSpec::parse(spec_str).map_err(|e| anyhow::anyhow!(e))?;
        local_forwards.push(spec);
    }

    let entry = SshHost {
        name: name.clone(),
        host,
        port,
        username,
        auth,
        group,
        note,
        proxy_jump: args.proxy_jump.and_then(|p| non_empty(&p)),
        local_forwards,
        extra_keys: Vec::new(),
        forward_agent: false,
        monitor: args.monitor,
        created_at: Utc::now(),
        last_used: None,
    };

    vault.hosts.push(entry);
    storage.save_vault(&vault)?;

    println!(
        "\n\x1b[1;32m✓\x1b[0m {}",
        t!("cli.new.saved", name = bold(&name))
    );
    println!(
        "  {}",
        t!(
            "cli.new.connect_hint",
            cmd = cyan(format!("ssha {name}")),
            ssha = cyan("ssha")
        )
    );
    Ok(())
}

pub async fn cmd_list(storage: &Storage) -> Result<()> {
    let vault = storage.load_vault()?;
    if vault.hosts.is_empty() {
        println!("{}", t!("cli.list.empty"));
        println!(
            "{}",
            t!(
                "cli.list.empty_hint",
                ssha = cyan("ssha"),
                new = "\x1b[1;33m/new\x1b[0m",
                cmd = cyan("ssha new")
            )
        );
        return Ok(());
    }

    // Probe all hosts concurrently
    let mut handles = Vec::with_capacity(vault.hosts.len());
    for h in &vault.hosts {
        let host = h.host.clone();
        let port = h.port;
        handles.push(tokio::spawn(
            async move { ssh::probe_host(&host, port).await },
        ));
    }

    let mut states = Vec::with_capacity(handles.len());
    for handle in handles {
        states.push(handle.await.unwrap_or(ssh::PingState::Down));
    }

    println!(
        "\x1b[1;36m{:<18} {:<34} {:<8} {:<14} {:<18} {:<9} {}\x1b[0m",
        t!("cli.list.col_name").to_uppercase(),
        t!("cli.list.col_address").to_uppercase(),
        t!("cli.list.col_auth").to_uppercase(),
        t!("cli.list.col_group").to_uppercase(),
        t!("cli.list.col_last_used").to_uppercase(),
        "CPU/RAM",
        t!("cli.list.col_state").to_uppercase()
    );
    println!("{}", "─".repeat(108));
    for (h, st) in vault.hosts.iter().zip(states.iter()) {
        let (tag, dot) = match st {
            ssh::PingState::Up(_) => ("\x1b[1;32mUP\x1b[0m", "\x1b[1;32m●\x1b[0m"),
            ssh::PingState::Down => ("\x1b[1;31mDOWN\x1b[0m", "\x1b[1;31m●\x1b[0m"),
            ssh::PingState::Checking => ("\x1b[2m...\x1b[0m", "\x1b[33m●\x1b[0m"),
        };
        let ep = h.endpoint_display();
        let tag_plain_len = match st {
            ssh::PingState::Up(_) => 2,
            ssh::PingState::Down => 4,
            ssh::PingState::Checking => 3,
        };
        let pad = 34usize.saturating_sub(ep.chars().count() + 2 + tag_plain_len);
        let monitor = if h.monitor {
            t!("cli.list.monitor_on")
        } else {
            t!("cli.list.monitor_off")
        };
        println!(
            "{:<18} {}  {}{} {:<8} {:<14} {:<18} {:<9}   {}",
            h.name,
            ep,
            tag,
            " ".repeat(pad),
            h.auth.label(),
            h.group.as_deref().unwrap_or("—"),
            format_relative_time(h.last_used),
            monitor,
            dot
        );
    }
    Ok(())
}

pub fn cmd_rm(storage: &Storage, name: &str, yes: bool) -> Result<()> {
    let mut vault = storage.load_vault()?;
    let Some(existing) = vault.find_by_name(name).cloned() else {
        bail!(t!("cli.err.no_such", name = name).into_owned());
    };

    if !yes {
        let confirm = prompt_optional(&t!(
            "cli.rm.confirm",
            name = existing.name,
            endpoint = existing.endpoint_display()
        ))?;
        if !i18n::is_yes(&confirm) {
            println!("{}", t!("cli.rm.cancelled"));
            return Ok(());
        }
    }

    vault.remove_by_name(&existing.name);
    storage.save_vault(&vault)?;
    println!(
        "\x1b[1;32m✓\x1b[0m {}",
        t!("cli.rm.done", name = existing.name)
    );
    Ok(())
}

pub async fn cmd_test(storage: &Storage, name: &str) -> Result<()> {
    let vault = storage.load_vault()?;
    let Some(host) = vault.find_by_name(name) else {
        bail!(t!("cli.err.no_such", name = name).into_owned());
    };

    print!(
        "[ssha] {} ",
        t!(
            "cli.test.running",
            name = host.name,
            endpoint = format!("{}:{}", host.host, host.port)
        )
    );
    io::stdout().flush()?;

    match ssh::test_tcp_connection(&host.host, host.port).await {
        Ok(rtt) => {
            println!("\x1b[1;32mOK\x1b[0m ({:.1} ms)", rtt.as_secs_f64() * 1000.0);
            Ok(())
        }
        Err(e) => {
            println!("\x1b[1;31m{}\x1b[0m", t!("cli.test.failed"));
            Err(e)
        }
    }
}

pub fn cmd_info(storage: &Storage) -> Result<()> {
    let vault = storage.load_vault()?;
    println!("{} v{}", cyan("ssha"), env!("CARGO_PKG_VERSION"));
    let rows = [
        (
            t!("cli.info.config_dir"),
            storage.config_dir().display().to_string(),
        ),
        (
            t!("cli.info.vault"),
            storage.vault_path().display().to_string(),
        ),
        (
            t!("cli.info.known_hosts"),
            storage.known_hosts_path().display().to_string(),
        ),
        (
            t!("cli.info.settings"),
            storage.settings_path().display().to_string(),
        ),
        (t!("cli.info.protection"), protection_summary()),
        (
            t!("cli.info.language"),
            format!(
                "{} ({})",
                i18n::current_lang().native_name(),
                i18n::current_lang().code()
            ),
        ),
        (t!("cli.info.connections"), vault.hosts.len().to_string()),
    ];
    let width = rows
        .iter()
        .map(|(k, _)| k.chars().count())
        .max()
        .unwrap_or(0);
    for (k, v) in rows {
        println!("  {}{} : {}", k, " ".repeat(width - k.chars().count()), v);
    }
    Ok(())
}

/// `ssha lang [code]`: changes the interface language (opens the picker without a code).
pub fn cmd_lang(storage: &Storage, code: Option<&str>) -> Result<()> {
    let lang = match code {
        Some(c) => match Lang::from_code(c) {
            Some(l) => l,
            None => {
                let list = Lang::ALL
                    .iter()
                    .map(|l| format!("{} ({})", l.code(), l.native_name()))
                    .collect::<Vec<_>>()
                    .join(", ");
                bail!(t!("cli.lang.unknown", code = c, list = list).into_owned());
            }
        },
        None => match i18n::run_first_start_picker(i18n::current_lang())? {
            Some(l) => l,
            None => return Ok(()),
        },
    };
    let mut settings = storage.load_settings();
    settings.language = Some(lang.code().to_string());
    storage.save_settings(&settings)?;
    i18n::set_lang(lang);
    println!(
        "\x1b[1;32m✓\x1b[0m {}",
        t!("cli.lang.saved", lang = bold(lang.native_name()))
    );
    if i18n::env_override().is_some() {
        println!("\x1b[33m[!]\x1b[0m {}", t!("cli.lang.env_override"));
    }
    Ok(())
}

pub async fn cmd_direct_connect(storage: Arc<Storage>, name: &str) -> Result<i32> {
    let mut vault = storage.load_vault()?;
    let Some(host) = vault.find_by_name(name).cloned() else {
        return Err(not_found(name));
    };

    vault.mark_used(&host.name);
    let _ = storage.save_vault(&vault);

    let code = ssh::connect_interactive(&host, storage).await?;
    Ok(code as i32)
}

pub async fn cmd_files(
    storage: Arc<Storage>,
    name: &str,
    initial_path: Option<&str>,
) -> Result<()> {
    let mut vault = storage.load_vault()?;
    let Some(host) = vault.find_by_name(name).cloned() else {
        return Err(not_found(name));
    };

    vault.mark_used(&host.name);
    let _ = storage.save_vault(&vault);

    files_tui::run_files_tui(&host, storage, initial_path).await
}

fn print_progress(arrow: &str, fname: &str, done: u64, total: Option<u64>) {
    if let Some(t) = total.filter(|&t| t > 0) {
        let pct = ((done as f64 / t as f64) * 100.0).min(100.0);
        eprint!(
            "\r\x1b[2K  {arrow} {} : {} / {} ({:.0}%)",
            fname,
            sftp::format_size(done),
            sftp::format_size(t),
            pct
        );
    } else {
        eprint!("\r\x1b[2K  {arrow} {} : {}", fname, sftp::format_size(done));
    }
    let _ = io::stderr().flush();
}

pub async fn cmd_get(
    storage: Arc<Storage>,
    name: &str,
    remote: &str,
    local: Option<&str>,
) -> Result<()> {
    let mut vault = storage.load_vault()?;
    let Some(host) = vault.find_by_name(name).cloned() else {
        return Err(not_found(name));
    };

    vault.mark_used(&host.name);
    let _ = storage.save_vault(&vault);

    println!(
        "{} {}",
        cyan("[ssha]"),
        t!(
            "cli.sftp.connecting",
            name = bold(&host.name),
            endpoint = host.endpoint_display()
        )
    );
    let client = SftpClient::connect(&host, storage).await?;

    let local_dest = match local {
        Some(p) => sftp::resolve_local_path(p),
        None => sftp::default_download_dir(),
    };

    let result = client
        .download(remote, &local_dest, |fname, done, total| {
            print_progress("↓", fname, done, total)
        })
        .await;

    eprintln!();
    client.close().await;

    let (saved_path, stats) = result?;
    println!(
        "\x1b[1;32m✓\x1b[0m {}",
        t!(
            "cli.sftp.download_done",
            files = tn("common.files", stats.files as u64, &[]),
            size = sftp::format_size(stats.bytes),
            path = bold(saved_path.display())
        )
    );
    Ok(())
}

pub async fn cmd_put(
    storage: Arc<Storage>,
    name: &str,
    local: Option<&str>,
    remote: Option<&str>,
    pick_dir: bool,
) -> Result<()> {
    let mut vault = storage.load_vault()?;
    let Some(host) = vault.find_by_name(name).cloned() else {
        return Err(not_found(name));
    };

    let local_src = match local {
        Some(p) => sftp::resolve_local_path(p),
        None => {
            let title = if pick_dir {
                t!("cli.sftp.pick_folder_title", name = host.name).into_owned()
            } else {
                t!("cli.sftp.pick_file_title", name = host.name).into_owned()
            };
            let res = tokio::task::spawn_blocking(move || {
                if pick_dir {
                    picker::pick_folder(&title)
                } else {
                    picker::pick_file(&title, None)
                }
            })
            .await
            .unwrap_or(PickerResult::Unavailable);
            match res {
                PickerResult::Selected(p) => p,
                PickerResult::Cancelled => {
                    println!("{}", t!("cli.sftp.upload_cancelled"));
                    return Ok(());
                }
                PickerResult::Unavailable => {
                    let entered = prompt_required(&t!("cli.sftp.prompt_local_path"))?;
                    sftp::resolve_local_path(&entered)
                }
            }
        }
    };

    if !local_src.exists() {
        bail!(t!("cli.sftp.local_not_found", path = local_src.display()).into_owned());
    }

    vault.mark_used(&host.name);
    let _ = storage.save_vault(&vault);

    println!(
        "{} {}",
        cyan("[ssha]"),
        t!(
            "cli.sftp.connecting",
            name = bold(&host.name),
            endpoint = host.endpoint_display()
        )
    );
    let client = SftpClient::connect(&host, storage).await?;

    let remote_dest = match remote {
        Some(r) => r.to_string(),
        None => client
            .canonicalize(".")
            .await
            .unwrap_or_else(|_| ".".to_string()),
    };

    let result = client
        .upload(&local_src, &remote_dest, |fname, done, total| {
            print_progress("↑", fname, done, total)
        })
        .await;

    eprintln!();
    client.close().await;

    let (saved_remote, stats) = result?;
    println!(
        "\x1b[1;32m✓\x1b[0m {}",
        t!(
            "cli.sftp.upload_done",
            files = tn("common.files", stats.files as u64, &[]),
            size = sftp::format_size(stats.bytes),
            path = bold(saved_remote)
        )
    );
    Ok(())
}

pub fn cmd_export(storage: &Storage, output: Option<&str>) -> Result<()> {
    let vault = storage.load_vault()?;
    if vault.hosts.is_empty() {
        println!("{}", t!("cli.export.empty"));
        return Ok(());
    }

    let dest = match output {
        Some(p) => sftp::resolve_local_path(p),
        None => match picker::pick_save_file(
            &t!("common.export_title"),
            "ssha-config.json",
            Some((&t!("common.json_filter"), "*.json")),
        ) {
            PickerResult::Selected(p) => p,
            PickerResult::Cancelled => {
                println!("{}", t!("common.export_cancelled"));
                return Ok(());
            }
            PickerResult::Unavailable => sftp::default_download_dir().join("ssha-config.json"),
        },
    };

    let count = export_vault_to_file(&vault, &dest)?;
    println!(
        "\x1b[1;32m✓\x1b[0m {}",
        tn(
            "common.exported",
            count as u64,
            &[("path", &bold(dest.display()))]
        )
    );
    println!("\x1b[33m[!]\x1b[0m {}", t!("cli.export.warning"));
    Ok(())
}

pub fn cmd_import(storage: &Storage, input: Option<&str>, keep_existing: bool) -> Result<()> {
    let src = match input {
        Some(p) => sftp::resolve_local_path(p),
        None => match picker::pick_file(
            &t!("common.import_title"),
            Some((&t!("common.json_filter"), "*.json")),
        ) {
            PickerResult::Selected(p) => p,
            PickerResult::Cancelled => {
                println!("{}", t!("common.import_cancelled"));
                return Ok(());
            }
            PickerResult::Unavailable => {
                let entered = prompt_required(&t!("cli.import.prompt_path"))?;
                sftp::resolve_local_path(&entered)
            }
        },
    };

    let report = import_vault_from_file(storage, &src, !keep_existing)?;
    println!(
        "\x1b[1;32m✓\x1b[0m {}",
        t!("cli.import.done", path = bold(src.display()))
    );
    println!(
        "  {} — {}",
        import_report_text(report.added, report.updated, report.skipped),
        t!("cli.import.encrypted")
    );
    Ok(())
}

/// "3 added, 1 updated, 0 skipped" in the active language.
pub fn import_report_text(added: usize, updated: usize, skipped: usize) -> String {
    t!(
        "common.import_report",
        added = added,
        updated = updated,
        skipped = skipped
    )
    .into_owned()
}

pub fn cmd_import_ssh(storage: &Storage, path: Option<&str>, overwrite: bool) -> Result<()> {
    let target_path = match path {
        Some(p) => sftp::resolve_local_path(p),
        None => ssh_config::default_ssh_config_path()
            .ok_or_else(|| anyhow::anyhow!(t!("common.err.no_ssh_config").into_owned()))?,
    };

    let report = ssh_config::import_from_ssh_config(storage, &target_path, overwrite)?;
    println!(
        "\x1b[1;32m✓\x1b[0m {}",
        t!("cli.import_ssh.done", path = bold(target_path.display()))
    );
    println!(
        "  {}.",
        import_report_text(report.added, report.updated, report.skipped)
    );
    Ok(())
}

pub fn cmd_security(storage: &Storage, action: SecurityAction) -> Result<()> {
    match action {
        SecurityAction::Status => {
            if storage.is_master_password_enabled() {
                println!(
                    "\x1b[1;32m●\x1b[0m {}",
                    t!(
                        "cli.security.mode",
                        mode = bold(t!("cli.security.mode_master"))
                    )
                );
                println!("  {}", t!("cli.security.portable"));
            } else {
                println!(
                    "\x1b[1;36m●\x1b[0m {}",
                    t!("cli.security.mode", mode = bold(protection_summary()))
                );
                println!(
                    "  {}",
                    t!(
                        "cli.security.no_master",
                        cmd = "`ssha security enable-master-password`"
                    )
                );
            }
        }
        SecurityAction::EnableMasterPassword => {
            storage.ensure_unlocked()?;
            let pw1 = rpassword::prompt_password(format!("{} : ", t!("cli.security.new_pw")))?;
            if pw1.len() < 4 {
                bail!(t!("cli.security.too_short").into_owned());
            }
            let pw2 = rpassword::prompt_password(format!("{} : ", t!("cli.security.confirm_pw")))?;
            if pw1 != pw2 {
                bail!(t!("cli.security.mismatch").into_owned());
            }
            storage.enable_master_password(&pw1)?;
            println!("\x1b[1;32m✓\x1b[0m {}", t!("cli.security.enabled"));
            println!("  {}", t!("cli.security.enabled_detail"));
        }
        SecurityAction::DisableMasterPassword => {
            if !storage.is_master_password_enabled() {
                println!("{}", t!("cli.security.already_auto"));
                return Ok(());
            }
            storage.ensure_unlocked()?;
            storage.disable_master_password()?;
            println!(
                "\x1b[1;32m✓\x1b[0m {}",
                t!("cli.security.disabled", mode = protection_summary())
            );
        }
    }
    Ok(())
}

fn prompt_required(label: &str) -> Result<String> {
    loop {
        let val = prompt_optional(label)?;
        if !val.is_empty() {
            return Ok(val);
        }
        println!("  \x1b[33m{}\x1b[0m", t!("cli.err.required"));
    }
}

fn prompt_optional(label: &str) -> Result<String> {
    print!("{label} : ");
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

fn non_empty(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}
