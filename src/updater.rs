use crate::sftp::format_size;
use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::env;
use std::fs::{self, File};
use std::io::{self, IsTerminal, Read, Write};
use std::time::Duration;

const REPO: &str = "gigi74168/SSHA";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    size: u64,
}

#[derive(Debug, Clone)]
pub struct ReleaseInfo {
    pub version: String,
    pub html_url: String,
    pub asset_name: String,
    pub download_url: String,
    pub size: u64,
}

pub fn platform_asset_name() -> Option<&'static str> {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        Some("ssha-windows-x86_64.exe")
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        Some("ssha-linux-x86_64")
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        Some("ssha-linux-aarch64")
    }
    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64")
    )))]
    {
        None
    }
}

pub fn parse_semver(s: &str) -> Option<(u64, u64, u64)> {
    let clean = s.trim().trim_start_matches(['v', 'V']);
    let main_part = clean.split('-').next()?;
    let mut parts = main_part.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next().unwrap_or("0").parse::<u64>().ok()?;
    let patch = parts.next().unwrap_or("0").parse::<u64>().ok()?;
    Some((major, minor, patch))
}

pub fn is_newer_version(latest: &str, current: &str) -> bool {
    match (parse_semver(latest), parse_semver(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

fn build_agent(timeout: Duration) -> ureq::Agent {
    let tls = ureq::tls::TlsConfig::builder()
        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
        .build();
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .tls_config(tls)
        .build();
    config.into()
}

/// Queries GitHub Releases for a newer version of `ssha`.
/// Returns `Ok(Some(ReleaseInfo))` if a newer version with a matching binary is available.
pub fn check_latest_release(timeout: Duration) -> Result<Option<ReleaseInfo>> {
    let Some(expected_asset) = platform_asset_name() else {
        return Ok(None);
    };

    let agent = build_agent(timeout);

    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let release: GithubRelease = agent
        .get(&url)
        .header("User-Agent", &format!("ssha/{CURRENT_VERSION}"))
        .header("Accept", "application/vnd.github+json")
        .call()
        .context("Impossible de contacter GitHub pour vérifier les mises à jour")?
        .body_mut()
        .read_json()
        .context("Réponse GitHub invalide")?;

    if !is_newer_version(&release.tag_name, CURRENT_VERSION) {
        return Ok(None);
    }

    let Some(asset) = release
        .assets
        .into_iter()
        .find(|a| a.name == expected_asset)
    else {
        return Ok(None);
    };

    Ok(Some(ReleaseInfo {
        version: release.tag_name,
        html_url: release.html_url,
        asset_name: asset.name,
        download_url: asset.browser_download_url,
        size: asset.size,
    }))
}

/// Downloads the release binary and atomically replaces the currently running `ssha` executable.
pub fn download_and_install(release: &ReleaseInfo) -> Result<()> {
    let agent = build_agent(Duration::from_secs(120));

    println!(
        "\x1b[1;36m[ssha]\x1b[0m Téléchargement de \x1b[1m{}\x1b[0m ({})...",
        release.version, release.asset_name
    );

    let mut response = agent
        .get(&release.download_url)
        .header("User-Agent", &format!("ssha/{CURRENT_VERSION}"))
        .call()
        .with_context(|| format!("Impossible de télécharger {}", release.download_url))?;

    let tmp_path = env::temp_dir().join(format!(
        "ssha-update-{}-{}",
        std::process::id(),
        release.asset_name
    ));

    let mut tmp_file = File::create(&tmp_path)
        .with_context(|| format!("Impossible de créer le fichier temporaire {}", tmp_path.display()))?;

    let mut reader = response.body_mut().as_reader();
    let mut buf = [0u8; 64 * 1024];
    let mut downloaded: u64 = 0;
    let mut magic = [0u8; 4];
    let mut magic_len = 0usize;

    loop {
        let n = reader
            .read(&mut buf)
            .context("Erreur pendant le téléchargement de la mise à jour")?;
        if n == 0 {
            break;
        }
        if magic_len < 4 {
            let take = (4 - magic_len).min(n);
            magic[magic_len..magic_len + take].copy_from_slice(&buf[..take]);
            magic_len += take;
        }
        tmp_file.write_all(&buf[..n])?;
        downloaded += n as u64;

        if release.size > 0 {
            let pct = ((downloaded as f64 / release.size as f64) * 100.0).min(100.0);
            eprint!(
                "\r\x1b[2K  ↓ {} : {} / {} ({:.0}%)",
                release.asset_name,
                format_size(downloaded),
                format_size(release.size),
                pct
            );
        } else {
            eprint!(
                "\r\x1b[2K  ↓ {} : {}",
                release.asset_name,
                format_size(downloaded)
            );
        }
        let _ = io::stderr().flush();
    }
    eprintln!();
    tmp_file.flush()?;
    drop(tmp_file);

    // Basic binary header validation before replacing executable
    if !is_valid_binary_header(&magic[..magic_len]) {
        let _ = fs::remove_file(&tmp_path);
        bail!("Le fichier téléchargé ne semble pas être un exécutable valide. Mise à jour annulée.");
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o755))?;
    }

    self_replace::self_replace(&tmp_path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        anyhow!(
            "Impossible de remplacer l'exécutable actuel ({e}). Sur Linux dans /usr/local/bin, essaie avec sudo ou relance l'installateur."
        )
    })?;

    let _ = fs::remove_file(&tmp_path);

    println!(
        "\x1b[1;32m✓\x1b[0m ssha a été mis à jour vers \x1b[1m{}\x1b[0m !",
        release.version
    );
    println!("  Relance \x1b[1;36mssha\x1b[0m pour utiliser la nouvelle version.");
    Ok(())
}

fn is_valid_binary_header(header: &[u8]) -> bool {
    #[cfg(windows)]
    {
        header.len() >= 2 && header[0] == b'M' && header[1] == b'Z'
    }
    #[cfg(unix)]
    {
        header.len() >= 4 && header == b"\x7fELF"
    }
}

/// Checks for a new release at startup (fast 2s timeout, silent on offline/error)
/// and prompts the user in the terminal if an update is available.
/// Returns `Ok(true)` if an update was installed (caller should exit so the user can relaunch).
pub async fn check_and_prompt_startup() -> bool {
    if env::var("SSHA_NO_UPDATE_CHECK").is_ok() {
        return false;
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return false;
    }

    let check = tokio::task::spawn_blocking(|| check_latest_release(Duration::from_secs(2))).await;
    let Ok(Ok(Some(release))) = check else {
        return false;
    };

    prompt_and_install(&release)
}

/// Explicit `ssha update` command.
pub async fn cmd_update(force_yes: bool) -> Result<()> {
    println!(
        "\x1b[1;36m[ssha]\x1b[0m Vérification des mises à jour (version actuelle : v{})...",
        CURRENT_VERSION
    );

    let release = tokio::task::spawn_blocking(|| check_latest_release(Duration::from_secs(10)))
        .await
        .map_err(|e| anyhow!("Erreur interne lors de la vérification : {e}"))??;

    let Some(release) = release else {
        println!(
            "\x1b[1;32m✓\x1b[0m Tu utilises déjà la dernière version de ssha (v{}).",
            CURRENT_VERSION
        );
        return Ok(());
    };

    if force_yes {
        tokio::task::spawn_blocking(move || download_and_install(&release))
            .await
            .map_err(|e| anyhow!("Erreur interne : {e}"))??;
        return Ok(());
    }

    if prompt_and_install(&release) {
        return Ok(());
    }
    println!("Mise à jour ignorée.");
    Ok(())
}

fn prompt_and_install(release: &ReleaseInfo) -> bool {
    println!();
    println!("\x1b[1;33m╭──────────────────────────────────────────────────────────────────╮\x1b[0m");
    println!(
        "\x1b[1;33m│\x1b[0m  Nouvelle version de \x1b[1;36mssha\x1b[0m disponible : \x1b[1;32m{}\x1b[0m (actuelle : v{})",
        release.version, CURRENT_VERSION
    );
    if !release.html_url.is_empty() {
        println!("\x1b[1;33m│\x1b[0m  \x1b[2m{}\x1b[0m", release.html_url);
    }
    println!("\x1b[1;33m╰──────────────────────────────────────────────────────────────────╯\x1b[0m");
    print!("Voulez-vous mettre à jour maintenant ? [O/n] : ");
    let _ = io::stdout().flush();

    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err() {
        return false;
    }

    let trimmed = answer.trim().to_lowercase();
    if matches!(trimmed.as_str(), "" | "o" | "oui" | "y" | "yes") {
        match download_and_install(release) {
            Ok(()) => return true,
            Err(err) => {
                eprintln!("\x1b[1;31m[ssha] Échec de la mise à jour :\x1b[0m {err:#}");
                eprintln!("  Continuation avec la version actuelle...\n");
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_comparison_works() {
        assert!(is_newer_version("v0.4.0", "0.3.1"));
        assert!(is_newer_version("v1.0.0", "0.9.9"));
        assert!(is_newer_version("0.3.2", "0.3.1"));
        assert!(!is_newer_version("v0.3.1", "0.3.1"));
        assert!(!is_newer_version("v0.3.0", "0.3.1"));
        assert!(!is_newer_version("invalid", "0.3.1"));
    }
}
