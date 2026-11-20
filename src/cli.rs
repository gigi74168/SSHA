use crate::crypto::protection_summary;
use crate::files_tui;
use crate::models::{format_relative_time, AuthMethod, LocalForwardSpec, SshHost};
use crate::picker::{self, PickerResult};
use crate::sftp::{self, SftpClient};
use crate::ssh;
use crate::ssh_config;
use crate::storage::{export_vault_to_file, import_vault_from_file, Storage};
use anyhow::{bail, Result};
use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use std::io::{self, Write};
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(
    name = "ssha",
    version,
    about = "Gestionnaire de connexions SSH & SFTP 100% CLI avec coffre-fort chiffré (Windows, Linux, macOS)",
    long_about = "Lance `ssha` sans argument pour ouvrir l'interface interactive (avec /new, /files, /export, /import, /import-ssh),\nou passe directement le nom d'une machine (`ssha mon-pc`) pour t'y connecter instantanément."
)]
pub struct Cli {
    /// Nom d'une connexion enregistrée pour s'y connecter directement
    #[arg(value_name = "NOM")]
    pub target: Option<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Ajouter une nouvelle connexion SSH
    #[command(visible_alias = "add")]
    New(NewArgs),

    /// Lister toutes les connexions enregistrées
    #[command(visible_alias = "ls")]
    List,

    /// Ouvrir le gestionnaire de fichiers distant (SFTP) sur une machine
    #[command(visible_alias = "sftp")]
    Files {
        /// Nom / alias de la connexion
        name: String,
        /// Dossier distant initial (optionnel)
        path: Option<String>,
    },

    /// Télécharger un fichier ou dossier depuis une machine distante
    #[command(visible_aliases = ["download", "dl"])]
    Get {
        /// Nom / alias de la connexion
        name: String,
        /// Chemin du fichier ou dossier sur la machine distante
        remote: String,
        /// Chemin de destination local (défaut: dossier Téléchargements)
        local: Option<String>,
    },

    /// Envoyer un fichier ou dossier local vers une machine distante
    #[command(visible_aliases = ["upload", "up"])]
    Put {
        /// Nom / alias de la connexion
        name: String,
        /// Chemin du fichier ou dossier local (si omis, ouvre la fenêtre Windows/Linux/macOS)
        local: Option<String>,
        /// Dossier ou chemin de destination sur la machine distante (défaut: dossier home distant)
        remote: Option<String>,
        /// Ouvrir la fenêtre de sélection de dossier (si aucun chemin local n'est fourni)
        #[arg(short = 'd', long)]
        dir: bool,
    },

    /// Exporter toutes les connexions (IP, utilisateurs, mots de passe) dans un fichier JSON portable
    #[command(visible_alias = "backup")]
    Export {
        /// Fichier de sortie (si omis, ouvre la fenêtre Enregistrer sous ou crée ssha-config.json)
        output: Option<String>,
    },

    /// Importer des connexions depuis un fichier exporté par un autre ssha
    #[command(visible_alias = "restore")]
    Import {
        /// Fichier JSON à importer (si omis, ouvre la fenêtre Ouvrir)
        input: Option<String>,
        /// Ne pas écraser les connexions existantes ayant le même nom
        #[arg(long)]
        keep_existing: bool,
    },

    /// Importer automatiquement les hôtes depuis ~/.ssh/config (OpenSSH)
    #[command(name = "import-ssh")]
    ImportSsh {
        /// Chemin vers le fichier SSH config (défaut: ~/.ssh/config)
        path: Option<String>,
        /// Écraser les connexions existantes ayant le même nom
        #[arg(long)]
        overwrite: bool,
    },

    /// Gérer la sécurité du coffre-fort (clé automatique ou mot de passe maître optionnel)
    Security {
        #[command(subcommand)]
        action: SecurityAction,
    },

    /// Supprimer une connexion enregistrée
    #[command(visible_aliases = ["delete", "del"])]
    Rm {
        /// Nom / alias de la connexion à supprimer
        name: String,
        /// Ne pas demander de confirmation
        #[arg(short = 'y', long)]
        yes: bool,
    },

    /// Tester si une machine répond sur son port SSH
    Test {
        /// Nom / alias de la connexion à tester
        name: String,
    },

    /// Vérifier et installer la dernière mise à jour de ssha
    #[command(visible_alias = "upgrade")]
    Update {
        /// Mettre à jour sans demander de confirmation
        #[arg(short = 'y', long)]
        yes: bool,
    },

    /// Afficher l'emplacement du coffre-fort chiffré et les infos de sécurité
    Info,
}

#[derive(Subcommand, Debug)]
pub enum SecurityAction {
    /// Afficher le mode de chiffrement actuel (automatique ou mot de passe maître)
    Status,
    /// Activer un mot de passe maître optionnel (Argon2id + AES-256-GCM, coffre-fort portable)
    EnableMasterPassword,
    /// Revenir au mode clé automatique sans mot de passe maître
    DisableMasterPassword,
}

#[derive(Args, Debug)]
pub struct NewArgs {
    /// Nom / alias de la machine (ex: mon-pc)
    #[arg(short, long)]
    pub name: Option<String>,

    /// Adresse IP ou nom d'hôte (ex: 192.168.1.192)
    #[arg(short = 'H', long)]
    pub host: Option<String>,

    /// Port SSH (défaut: 22)
    #[arg(short, long)]
    pub port: Option<u16>,

    /// Nom d'utilisateur SSH
    #[arg(short, long)]
    pub user: Option<String>,

    /// Chemin vers une clé privée SSH (au lieu d'un mot de passe)
    #[arg(short, long)]
    pub key: Option<String>,

    /// Groupe / tag optionnel (ex: Maison, Prod)
    #[arg(short, long)]
    pub group: Option<String>,

    /// Note / description optionnelle
    #[arg(long)]
    pub note: Option<String>,

    /// Bastion / ProxyJump (nom d'une machine ssha ou user@host[:port])
    #[arg(short = 'J', long)]
    pub proxy_jump: Option<String>,

    /// Redirection de port locale (-L local_port:remote_host:remote_port), répétable
    #[arg(short = 'L', long)]
    pub local_forward: Vec<String>,
}

pub fn cmd_new(storage: &Storage, args: NewArgs) -> Result<()> {
    let mut vault = storage.load_vault()?;

    println!("\x1b[1;36m[ssha]\x1b[0m Ajout d'une nouvelle connexion SSH\n");

    let name = match args.name {
        Some(n) => n.trim().to_string(),
        None => prompt_required("Nom / Alias (ex: mon-pc)")?,
    };
    if name.starts_with('/') {
        bail!("Le nom ne peut pas commencer par '/'.");
    }
    if vault.find_by_name(&name).is_some() {
        bail!("Une connexion nommée '{}' existe déjà.", name);
    }

    let host = match args.host {
        Some(h) => h.trim().to_string(),
        None => prompt_required("Hôte / IP (ex: 192.168.1.192)")?,
    };

    let port = match args.port {
        Some(p) => p,
        None => {
            let input = prompt_optional("Port SSH [22]")?;
            if input.is_empty() {
                22
            } else {
                input
                    .parse::<u16>()
                    .ok()
                    .filter(|&p| p > 0)
                    .ok_or_else(|| anyhow::anyhow!("Port invalide : '{}'", input))?
            }
        }
    };

    let default_user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "root".to_string());
    let username = match args.user {
        Some(u) => u.trim().to_string(),
        None => {
            let input = prompt_optional(&format!("Utilisateur [{}]", default_user))?;
            if input.is_empty() {
                default_user
            } else {
                input
            }
        }
    };

    let auth = if let Some(key_path) = args.key {
        let passphrase = rpassword::prompt_password("Passphrase de la clé (vide si aucune) : ")?;
        AuthMethod::Key {
            path: key_path.trim().to_string(),
            passphrase: if passphrase.is_empty() {
                None
            } else {
                Some(passphrase)
            },
        }
    } else {
        let mode = prompt_optional("Type d'authentification — (m)ot de passe / (c)lé SSH [m]")?;
        if matches!(mode.to_lowercase().as_str(), "c" | "cle" | "clé" | "key" | "k") {
            let path = prompt_optional("Chemin de la clé privée [~/.ssh/id_ed25519]")?;
            let path = if path.is_empty() {
                "~/.ssh/id_ed25519".to_string()
            } else {
                path
            };
            let passphrase =
                rpassword::prompt_password("Passphrase de la clé (vide si aucune) : ")?;
            AuthMethod::Key {
                path,
                passphrase: if passphrase.is_empty() {
                    None
                } else {
                    Some(passphrase)
                },
            }
        } else {
            let password = rpassword::prompt_password("Mot de passe SSH (masqué) : ")?;
            if password.is_empty() {
                bail!("Le mot de passe ne peut pas être vide.");
            }
            AuthMethod::Password { password }
        }
    };

    let group = match args.group {
        Some(g) => non_empty(&g),
        None => non_empty(&prompt_optional("Groupe / Tag (optionnel)")?),
    };
    let note = match args.note {
        Some(n) => non_empty(&n),
        None => non_empty(&prompt_optional("Note (optionnelle)")?),
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
        created_at: Utc::now(),
        last_used: None,
    };

    vault.hosts.push(entry);
    storage.save_vault(&vault)?;

    println!(
        "\n\x1b[1;32m✓\x1b[0m Connexion '\x1b[1m{}\x1b[0m' enregistrée et chiffrée.",
        name
    );
    println!("  Connecte-toi avec : \x1b[1;36mssha {}\x1b[0m (ou simplement \x1b[1;36mssha\x1b[0m)", name);
    Ok(())
}

pub async fn cmd_list(storage: &Storage) -> Result<()> {
    let vault = storage.load_vault()?;
    if vault.hosts.is_empty() {
        println!("Aucune connexion SSH enregistrée.");
        println!("Lance \x1b[1;36mssha\x1b[0m puis tape \x1b[1;33m/new\x1b[0m (ou \x1b[1;36mssha new\x1b[0m) pour en ajouter une.");
        return Ok(());
    }

    // Probe all hosts concurrently
    let mut handles = Vec::with_capacity(vault.hosts.len());
    for h in &vault.hosts {
        let host = h.host.clone();
        let port = h.port;
        handles.push(tokio::spawn(async move { ssh::probe_host(&host, port).await }));
    }

    let mut states = Vec::with_capacity(handles.len());
    for handle in handles {
        states.push(handle.await.unwrap_or(ssh::PingState::Down));
    }

    println!(
        "\x1b[1;36m{:<18} {:<34} {:<8} {:<14} {:<18} {}\x1b[0m",
        "NOM", "ADRESSE", "AUTH", "GROUPE", "DERNIÈRE CONNEXION", "ÉTAT"
    );
    println!("{}", "─".repeat(98));
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
        println!(
            "{:<18} {}  {}{} {:<8} {:<14} {:<18}   {}",
            h.name,
            ep,
            tag,
            " ".repeat(pad),
            h.auth.label(),
            h.group.as_deref().unwrap_or("—"),
            format_relative_time(h.last_used),
            dot
        );
    }
    Ok(())
}

pub fn cmd_rm(storage: &Storage, name: &str, yes: bool) -> Result<()> {
    let mut vault = storage.load_vault()?;
    let Some(existing) = vault.find_by_name(name).cloned() else {
        bail!("Aucune connexion trouvée avec le nom '{}'.", name);
    };

    if !yes {
        let confirm = prompt_optional(&format!(
            "Supprimer '{}' ({}) ? [o/N]",
            existing.name,
            existing.endpoint_display()
        ))?;
        if !matches!(confirm.to_lowercase().as_str(), "o" | "oui" | "y" | "yes") {
            println!("Suppression annulée.");
            return Ok(());
        }
    }

    vault.remove_by_name(&existing.name);
    storage.save_vault(&vault)?;
    println!("\x1b[1;32m✓\x1b[0m Connexion '{}' supprimée.", existing.name);
    Ok(())
}

pub async fn cmd_test(storage: &Storage, name: &str) -> Result<()> {
    let vault = storage.load_vault()?;
    let Some(host) = vault.find_by_name(name) else {
        bail!("Aucune connexion trouvée avec le nom '{}'.", name);
    };

    print!(
        "[ssha] Test TCP vers {} ({}:{})... ",
        host.name, host.host, host.port
    );
    io::stdout().flush()?;

    match ssh::test_tcp_connection(&host.host, host.port).await {
        Ok(rtt) => {
            println!("\x1b[1;32mOK\x1b[0m ({:.1} ms)", rtt.as_secs_f64() * 1000.0);
            Ok(())
        }
        Err(e) => {
            println!("\x1b[1;31mÉCHEC\x1b[0m");
            Err(e)
        }
    }
}

pub fn cmd_info(storage: &Storage) -> Result<()> {
    let vault = storage.load_vault()?;
    println!("\x1b[1;36mssha\x1b[0m v{}", env!("CARGO_PKG_VERSION"));
    println!("  Dossier config   : {}", storage.config_dir().display());
    println!("  Coffre-fort      : {}", storage.vault_path().display());
    println!("  Empreintes SSH   : {}", storage.known_hosts_path().display());
    println!("  Protection       : {}", protection_summary());
    println!("  Connexions       : {}", vault.hosts.len());
    Ok(())
}

pub async fn cmd_direct_connect(storage: Arc<Storage>, name: &str) -> Result<i32> {
    let mut vault = storage.load_vault()?;
    let Some(host) = vault.find_by_name(name).cloned() else {
        bail!(
            "Connexion '{}' introuvable. Lance `ssha list` pour voir tes machines enregistrées.",
            name
        );
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
        bail!(
            "Connexion '{}' introuvable. Lance `ssha list` pour voir tes machines enregistrées.",
            name
        );
    };

    vault.mark_used(&host.name);
    let _ = storage.save_vault(&vault);

    files_tui::run_files_tui(&host, storage, initial_path).await
}

pub async fn cmd_get(
    storage: Arc<Storage>,
    name: &str,
    remote: &str,
    local: Option<&str>,
) -> Result<()> {
    let mut vault = storage.load_vault()?;
    let Some(host) = vault.find_by_name(name).cloned() else {
        bail!(
            "Connexion '{}' introuvable. Lance `ssha list` pour voir tes machines enregistrées.",
            name
        );
    };

    vault.mark_used(&host.name);
    let _ = storage.save_vault(&vault);

    println!(
        "\x1b[1;36m[ssha]\x1b[0m Connexion SFTP à \x1b[1m{}\x1b[0m ({})...",
        host.name,
        host.endpoint_display()
    );
    let client = SftpClient::connect(&host, storage).await?;

    let local_dest = match local {
        Some(p) => sftp::resolve_local_path(p),
        None => sftp::default_download_dir(),
    };

    let result = client
        .download(remote, &local_dest, |fname, done, total| {
            if let Some(t) = total.filter(|&t| t > 0) {
                let pct = ((done as f64 / t as f64) * 100.0).min(100.0);
                eprint!(
                    "\r\x1b[2K  ↓ {} : {} / {} ({:.0}%)",
                    fname,
                    sftp::format_size(done),
                    sftp::format_size(t),
                    pct
                );
            } else {
                eprint!("\r\x1b[2K  ↓ {} : {}", fname, sftp::format_size(done));
            }
            let _ = io::stderr().flush();
        })
        .await;

    eprintln!();
    client.close().await;

    let (saved_path, stats) = result?;
    println!(
        "\x1b[1;32m✓\x1b[0m Téléchargement terminé ({} fichier(s), {}) → \x1b[1m{}\x1b[0m",
        stats.files,
        sftp::format_size(stats.bytes),
        saved_path.display()
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
        bail!(
            "Connexion '{}' introuvable. Lance `ssha list` pour voir tes machines enregistrées.",
            name
        );
    };

    let local_src = match local {
        Some(p) => sftp::resolve_local_path(p),
        None => {
            let title = if pick_dir {
                format!("Choisir un dossier à envoyer vers {}", host.name)
            } else {
                format!("Choisir un fichier à envoyer vers {}", host.name)
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
                    println!("Envoi annulé.");
                    return Ok(());
                }
                PickerResult::Unavailable => {
                    let entered = prompt_required("Chemin du fichier ou dossier local à envoyer")?;
                    sftp::resolve_local_path(&entered)
                }
            }
        }
    };

    if !local_src.exists() {
        bail!("Fichier ou dossier local introuvable : '{}'", local_src.display());
    }

    vault.mark_used(&host.name);
    let _ = storage.save_vault(&vault);

    println!(
        "\x1b[1;36m[ssha]\x1b[0m Connexion SFTP à \x1b[1m{}\x1b[0m ({})...",
        host.name,
        host.endpoint_display()
    );
    let client = SftpClient::connect(&host, storage).await?;

    let remote_dest = match remote {
        Some(r) => r.to_string(),
        None => client.canonicalize(".").await.unwrap_or_else(|_| ".".to_string()),
    };

    let result = client
        .upload(&local_src, &remote_dest, |fname, done, total| {
            if let Some(t) = total.filter(|&t| t > 0) {
                let pct = ((done as f64 / t as f64) * 100.0).min(100.0);
                eprint!(
                    "\r\x1b[2K  ↑ {} : {} / {} ({:.0}%)",
                    fname,
                    sftp::format_size(done),
                    sftp::format_size(t),
                    pct
                );
            } else {
                eprint!("\r\x1b[2K  ↑ {} : {}", fname, sftp::format_size(done));
            }
            let _ = io::stderr().flush();
        })
        .await;

    eprintln!();
    client.close().await;

    let (saved_remote, stats) = result?;
    println!(
        "\x1b[1;32m✓\x1b[0m Envoi terminé ({} fichier(s), {}) → \x1b[1m{}\x1b[0m",
        stats.files,
        sftp::format_size(stats.bytes),
        saved_remote
    );
    Ok(())
}

pub fn cmd_export(storage: &Storage, output: Option<&str>) -> Result<()> {
    let vault = storage.load_vault()?;
    if vault.hosts.is_empty() {
        println!("Aucune connexion SSH enregistrée à exporter.");
        return Ok(());
    }

    let dest = match output {
        Some(p) => sftp::resolve_local_path(p),
        None => match picker::pick_save_file(
            "Exporter la configuration ssha",
            "ssha-config.json",
            Some(("Configuration ssha (*.json)", "*.json")),
        ) {
            PickerResult::Selected(p) => p,
            PickerResult::Cancelled => {
                println!("Export annulé.");
                return Ok(());
            }
            PickerResult::Unavailable => sftp::default_download_dir().join("ssha-config.json"),
        },
    };

    let count = export_vault_to_file(&vault, &dest)?;
    println!(
        "\x1b[1;32m✓\x1b[0m {} connexion(s) exportée(s) → \x1b[1m{}\x1b[0m",
        count,
        dest.display()
    );
    println!("\x1b[33m[!]\x1b[0m Ce fichier contient tes mots de passe SSH : garde-le en lieu sûr et supprime-le après transfert.");
    Ok(())
}

pub fn cmd_import(storage: &Storage, input: Option<&str>, keep_existing: bool) -> Result<()> {
    let src = match input {
        Some(p) => sftp::resolve_local_path(p),
        None => match picker::pick_file(
            "Importer une configuration ssha",
            Some(("Configuration ssha (*.json)", "*.json")),
        ) {
            PickerResult::Selected(p) => p,
            PickerResult::Cancelled => {
                println!("Import annulé.");
                return Ok(());
            }
            PickerResult::Unavailable => {
                let entered = prompt_required("Chemin du fichier ssha-config.json à importer")?;
                sftp::resolve_local_path(&entered)
            }
        },
    };

    let report = import_vault_from_file(storage, &src, !keep_existing)?;
    println!(
        "\x1b[1;32m✓\x1b[0m Import terminé depuis \x1b[1m{}\x1b[0m :",
        src.display()
    );
    println!(
        "  {} ajoutée(s), {} mise(s) à jour, {} ignorée(s) — chiffrées automatiquement dans vault.enc.",
        report.added, report.updated, report.skipped
    );
    Ok(())
}

pub fn cmd_import_ssh(storage: &Storage, path: Option<&str>, overwrite: bool) -> Result<()> {
    let target_path = match path {
        Some(p) => sftp::resolve_local_path(p),
        None => ssh_config::default_ssh_config_path()
            .ok_or_else(|| anyhow::anyhow!("Impossible de localiser ~/.ssh/config."))?,
    };

    let report = ssh_config::import_from_ssh_config(storage, &target_path, overwrite)?;
    println!(
        "\x1b[1;32m✓\x1b[0m Import OpenSSH terminé depuis \x1b[1m{}\x1b[0m :",
        target_path.display()
    );
    println!(
        "  {} ajoutée(s), {} mise(s) à jour, {} ignorée(s).",
        report.added, report.updated, report.skipped
    );
    Ok(())
}

pub fn cmd_security(storage: &Storage, action: SecurityAction) -> Result<()> {
    match action {
        SecurityAction::Status => {
            if storage.is_master_password_enabled() {
                println!("\x1b[1;32m●\x1b[0m Mode actuel : \x1b[1mMot de passe maître (Argon2id + AES-256-GCM)\x1b[0m");
                println!("  Ton fichier vault.enc est 100% portable d'une machine à l'autre.");
            } else {
                println!("\x1b[1;36m●\x1b[0m Mode actuel : \x1b[1m{}\x1b[0m", protection_summary());
                println!("  Aucun mot de passe maître requis. Utilise `ssha security enable-master-password` pour l'activer.");
            }
        }
        SecurityAction::EnableMasterPassword => {
            storage.ensure_unlocked()?;
            let pw1 = rpassword::prompt_password("Nouveau mot de passe maître : ")?;
            if pw1.len() < 4 {
                bail!("Le mot de passe maître doit contenir au moins 4 caractères.");
            }
            let pw2 = rpassword::prompt_password("Confirmer le mot de passe maître : ")?;
            if pw1 != pw2 {
                bail!("Les mots de passe ne correspondent pas.");
            }
            storage.enable_master_password(&pw1)?;
            println!("\x1b[1;32m✓\x1b[0m Mot de passe maître activé (Argon2id + AES-256-GCM).");
            println!("  La clé locale automatique a été supprimée ; vault.enc est maintenant portable.");
        }
        SecurityAction::DisableMasterPassword => {
            if !storage.is_master_password_enabled() {
                println!("Le mode clé automatique est déjà actif.");
                return Ok(());
            }
            storage.ensure_unlocked()?;
            storage.disable_master_password()?;
            println!("\x1b[1;32m✓\x1b[0m Retour au mode clé automatique ({}).", protection_summary());
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
        println!("  \x1b[33mCe champ est obligatoire.\x1b[0m");
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
