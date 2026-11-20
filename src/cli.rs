use crate::crypto::protection_summary;
use crate::files_tui;
use crate::models::{format_relative_time, AuthMethod, SshHost};
use crate::sftp::{self, SftpClient};
use crate::ssh;
use crate::storage::Storage;
use anyhow::{bail, Result};
use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use std::io::{self, Write};
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(
    name = "ssha",
    version,
    about = "Gestionnaire de connexions SSH 100% CLI avec coffre-fort chiffré automatique",
    long_about = "Lance `ssha` sans argument pour ouvrir l'interface interactive (avec /new, /files, /edit, /del, recherche live),\nou passe directement le nom d'une machine (`ssha mon-pc`) pour t'y connecter instantanément."
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
        /// Chemin du fichier ou dossier local à envoyer
        local: String,
        /// Dossier ou chemin de destination sur la machine distante (défaut: dossier home distant)
        remote: Option<String>,
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

    let entry = SshHost {
        name: name.clone(),
        host,
        port,
        username,
        auth,
        group,
        note,
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

pub fn cmd_list(storage: &Storage) -> Result<()> {
    let vault = storage.load_vault()?;
    if vault.hosts.is_empty() {
        println!("Aucune connexion SSH enregistrée.");
        println!("Lance \x1b[1;36mssha\x1b[0m puis tape \x1b[1;33m/new\x1b[0m (ou \x1b[1;36mssha new\x1b[0m) pour en ajouter une.");
        return Ok(());
    }

    println!(
        "\x1b[1;36m{:<18} {:<30} {:<8} {:<14} {}\x1b[0m",
        "NOM", "ADRESSE", "AUTH", "GROUPE", "DERNIÈRE CONNEXION"
    );
    println!("{}", "─".repeat(88));
    for h in &vault.hosts {
        println!(
            "{:<18} {:<30} {:<8} {:<14} {}",
            h.name,
            h.endpoint_display(),
            h.auth.label(),
            h.group.as_deref().unwrap_or("—"),
            format_relative_time(h.last_used)
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
    local: &str,
    remote: Option<&str>,
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

    let local_src = sftp::resolve_local_path(local);
    if !local_src.exists() {
        bail!("Fichier ou dossier local introuvable : '{}'", local_src.display());
    }

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
