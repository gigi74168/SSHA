use crate::i18n::{self, Lang};
use crate::sftp::format_size;
use crate::storage::Storage;
use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::env;
use std::fs::{self, File};
use std::io::{self, IsTerminal, Read, Write};
use std::time::Duration;

const REPO: &str = "gigi74168/SSHA";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Changelogs embedded at build time, used for the "What's new" screen and `ssha changelog`.
const CHANGELOG_EN: &str = include_str!("../CHANGELOG.md");
const CHANGELOG_FR: &str = include_str!("../CHANGELOG.fr.md");
const CHANGELOG_RU: &str = include_str!("../CHANGELOG.ru.md");
const CHANGELOG_UK: &str = include_str!("../CHANGELOG.uk.md");
const CHANGELOG_ES: &str = include_str!("../CHANGELOG.es.md");
const CHANGELOG_IT: &str = include_str!("../CHANGELOG.it.md");

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    body: String,
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
    /// New features / fixes of every version between the installed one and this release.
    pub notes: Vec<VersionNotes>,
}

/// Items of one changelog version, grouped by kind. Sub-items start with two spaces.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReleaseNotes {
    pub added: Vec<String>,
    pub fixed: Vec<String>,
    pub changed: Vec<String>,
}

impl ReleaseNotes {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.fixed.is_empty() && self.changed.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionNotes {
    pub version: String,
    pub date: Option<String>,
    pub notes: ReleaseNotes,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Added,
    Fixed,
    Changed,
    Ignored,
}

fn classify_heading(title: &str) -> Section {
    let t = title.trim().to_lowercase();
    let starts = |words: &[&str]| words.iter().any(|w| t.starts_with(w));
    if starts(&["added", "ajouté", "new", "features", "nouveaut"]) {
        Section::Added
    } else if starts(&["fixed", "corrigé", "fixes", "bug"]) {
        Section::Fixed
    } else if starts(&[
        "changed",
        "modifié",
        "removed",
        "security",
        "deprecated",
        "supprimé",
    ]) {
        Section::Changed
    } else {
        Section::Ignored
    }
}

fn clean_inline(text: &str) -> String {
    text.replace("**", "").replace('`', "").trim().to_string()
}

/// Parses the `### Added / ### Fixed / ### Changed` sections of a Markdown changelog
/// block (Keep a Changelog style). Unknown sections (e.g. GitHub's auto-generated
/// "What's Changed") are ignored.
pub fn parse_release_notes(markdown: &str) -> ReleaseNotes {
    let mut notes = ReleaseNotes::default();
    let mut section = Section::Ignored;

    for raw in markdown.lines() {
        let line = raw.trim_end();
        let trimmed = line.trim_start();
        if let Some(title) = trimmed.strip_prefix("### ") {
            section = classify_heading(title);
            continue;
        }
        if trimmed.starts_with("## ") || trimmed.starts_with("# ") {
            section = Section::Ignored;
            continue;
        }
        let list = match section {
            Section::Added => &mut notes.added,
            Section::Fixed => &mut notes.fixed,
            Section::Changed => &mut notes.changed,
            Section::Ignored => continue,
        };
        if trimmed.is_empty() {
            continue;
        }
        let indent = line.len() - trimmed.len();
        let bullet = trimmed
            .strip_prefix("- ")
            .or_else(|| trimmed.strip_prefix("* "));
        match bullet {
            Some(text) if indent == 0 => list.push(clean_inline(text)),
            Some(text) => list.push(format!("  {}", clean_inline(text))),
            None => {
                // Continuation line of the previous item.
                if let Some(last) = list.last_mut() {
                    last.push(' ');
                    last.push_str(&clean_inline(trimmed));
                }
            }
        }
    }
    notes
}

/// Splits a full CHANGELOG into its `## [x.y.z] — date` versions (newest first, as written).
pub fn parse_changelog(markdown: &str) -> Vec<VersionNotes> {
    let mut out = Vec::new();
    let mut current: Option<(String, Option<String>, String)> = None;

    let flush = |cur: Option<(String, Option<String>, String)>, out: &mut Vec<VersionNotes>| {
        if let Some((version, date, body)) = cur {
            out.push(VersionNotes {
                version,
                date,
                notes: parse_release_notes(&body),
            });
        }
    };

    for line in markdown.lines() {
        if let Some(rest) = line.trim_start().strip_prefix("## ") {
            if let Some(version) = rest
                .split(']')
                .next()
                .and_then(|v| v.trim().strip_prefix('['))
                .filter(|v| parse_semver(v).is_some())
            {
                flush(current.take(), &mut out);
                let date = rest
                    .split(']')
                    .nth(1)
                    .map(|d| {
                        d.trim()
                            .trim_start_matches(['—', '-', '–'])
                            .trim()
                            .to_string()
                    })
                    .filter(|d| !d.is_empty());
                current = Some((version.to_string(), date, String::new()));
                continue;
            }
        }
        if let Some((_, _, body)) = current.as_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    flush(current, &mut out);
    out
}

fn embedded_changelog(lang: Lang) -> &'static str {
    match lang {
        Lang::En => CHANGELOG_EN,
        Lang::Fr => CHANGELOG_FR,
        Lang::Ru => CHANGELOG_RU,
        Lang::Uk => CHANGELOG_UK,
        Lang::Es => CHANGELOG_ES,
        Lang::It => CHANGELOG_IT,
    }
}

fn changelog_file_name(lang: Lang) -> String {
    match lang {
        Lang::En => "CHANGELOG.md".to_string(),
        other => format!("CHANGELOG.{}.md", other.code()),
    }
}

/// Versions `v` with `from < v <= to` from a changelog, newest first.
fn versions_between(all: Vec<VersionNotes>, from: &str, to: &str) -> Vec<VersionNotes> {
    let (Some(from), Some(to)) = (parse_semver(from), parse_semver(to)) else {
        return Vec::new();
    };
    let mut selected: Vec<VersionNotes> = all
        .into_iter()
        .filter(|v| {
            parse_semver(&v.version)
                .map(|sv| sv > from && sv <= to)
                .unwrap_or(false)
        })
        .collect();
    selected.sort_by_key(|v| std::cmp::Reverse(parse_semver(&v.version)));
    selected
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
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        Some("ssha-macos-aarch64")
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        Some("ssha-macos-x86_64")
    }
    #[cfg(not(any(
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64")
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

fn user_agent() -> String {
    format!("ssha/{CURRENT_VERSION}")
}

/// Downloads `CHANGELOG.<lang>.md` (or the English one) at the release tag and keeps the
/// versions newer than the installed one. Falls back to the GitHub release body.
fn fetch_release_notes(agent: &ureq::Agent, tag: &str, release_body: &str) -> Vec<VersionNotes> {
    let lang = i18n::current_lang();
    let mut files = vec![changelog_file_name(lang)];
    if lang != Lang::En {
        files.push(changelog_file_name(Lang::En));
    }
    for file in files {
        let url = format!("https://raw.githubusercontent.com/{REPO}/{tag}/{file}");
        let Ok(mut resp) = agent.get(&url).header("User-Agent", &user_agent()).call() else {
            continue;
        };
        let Ok(text) = resp.body_mut().read_to_string() else {
            continue;
        };
        let notes = versions_between(parse_changelog(&text), CURRENT_VERSION, tag);
        if notes.iter().any(|n| !n.notes.is_empty()) {
            return notes;
        }
    }
    let notes = parse_release_notes(release_body);
    if notes.is_empty() {
        Vec::new()
    } else {
        vec![VersionNotes {
            version: tag.trim_start_matches(['v', 'V']).to_string(),
            date: None,
            notes,
        }]
    }
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
        .header("User-Agent", &user_agent())
        .header("Accept", "application/vnd.github+json")
        .call()
        .context(t!("update.err.contact").into_owned())?
        .body_mut()
        .read_json()
        .context(t!("update.err.invalid_response").into_owned())?;

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

    let notes_agent = build_agent(timeout.max(Duration::from_secs(3)));
    let notes = fetch_release_notes(&notes_agent, &release.tag_name, &release.body);

    Ok(Some(ReleaseInfo {
        version: release.tag_name,
        html_url: release.html_url,
        asset_name: asset.name,
        download_url: asset.browser_download_url,
        size: asset.size,
        notes,
    }))
}

/// Downloads the release binary and atomically replaces the currently running `ssha` executable.
pub fn download_and_install(release: &ReleaseInfo) -> Result<()> {
    let agent = build_agent(Duration::from_secs(120));

    println!(
        "\x1b[1;36m[ssha]\x1b[0m {}",
        t!(
            "update.downloading",
            version = format!("\x1b[1m{}\x1b[0m", release.version),
            asset = release.asset_name
        )
    );

    let mut response = agent
        .get(&release.download_url)
        .header("User-Agent", &user_agent())
        .call()
        .with_context(|| t!("update.err.download", url = release.download_url).into_owned())?;

    let tmp_path = env::temp_dir().join(format!(
        "ssha-update-{}-{}",
        std::process::id(),
        release.asset_name
    ));

    let mut tmp_file = File::create(&tmp_path)
        .with_context(|| t!("update.err.tmp_file", path = tmp_path.display()).into_owned())?;

    let mut reader = response.body_mut().as_reader();
    let mut buf = [0u8; 64 * 1024];
    let mut downloaded: u64 = 0;
    let mut magic = [0u8; 4];
    let mut magic_len = 0usize;

    loop {
        let n = reader
            .read(&mut buf)
            .context(t!("update.err.during_download").into_owned())?;
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
        bail!(t!("update.err.invalid_binary").into_owned());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o755))?;
    }

    self_replace::self_replace(&tmp_path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        anyhow!(t!("update.err.replace", error = e).into_owned())
    })?;

    let _ = fs::remove_file(&tmp_path);

    println!(
        "\x1b[1;32m✓\x1b[0m {}",
        t!(
            "update.done",
            version = format!("\x1b[1m{}\x1b[0m", release.version)
        )
    );
    println!("  {}", t!("update.restart", ssha = "\x1b[1;36mssha\x1b[0m"));
    Ok(())
}

fn is_valid_binary_header(header: &[u8]) -> bool {
    #[cfg(windows)]
    {
        header.len() >= 2 && header[0] == b'M' && header[1] == b'Z'
    }
    #[cfg(target_os = "macos")]
    {
        header.len() >= 4
            && matches!(
                header,
                [0xcf, 0xfa, 0xed, 0xfe]
                    | [0xfe, 0xed, 0xfa, 0xcf]
                    | [0xca, 0xfe, 0xba, 0xbe]
                    | [0xbe, 0xba, 0xfe, 0xca]
            )
    }
    #[cfg(all(unix, not(target_os = "macos")))]
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
        "\x1b[1;36m[ssha]\x1b[0m {}",
        t!("update.checking", version = CURRENT_VERSION)
    );

    let release = tokio::task::spawn_blocking(|| check_latest_release(Duration::from_secs(10)))
        .await
        .map_err(|e| anyhow!(t!("update.err.internal", error = e).into_owned()))??;

    let Some(release) = release else {
        println!(
            "\x1b[1;32m✓\x1b[0m {}",
            t!("update.up_to_date", version = CURRENT_VERSION)
        );
        return Ok(());
    };

    if force_yes {
        print_release_notes_limited(&release.notes, 12);
        tokio::task::spawn_blocking(move || download_and_install(&release))
            .await
            .map_err(|e| anyhow!(t!("update.err.internal", error = e).into_owned()))??;
        return Ok(());
    }

    if prompt_and_install(&release) {
        return Ok(());
    }
    println!("{}", t!("update.skipped"));
    Ok(())
}

fn prompt_and_install(release: &ReleaseInfo) -> bool {
    println!();
    println!(
        "\x1b[1;33m╭──────────────────────────────────────────────────────────────────╮\x1b[0m"
    );
    println!(
        "\x1b[1;33m│\x1b[0m  {}",
        t!(
            "update.available",
            ssha = "\x1b[1;36mssha\x1b[0m",
            version = format!("\x1b[1;32m{}\x1b[0m", release.version),
            current = format!("v{CURRENT_VERSION}")
        )
    );
    if !release.html_url.is_empty() {
        println!("\x1b[1;33m│\x1b[0m  \x1b[2m{}\x1b[0m", release.html_url);
    }
    println!(
        "\x1b[1;33m╰──────────────────────────────────────────────────────────────────╯\x1b[0m"
    );
    print_release_notes_limited(&release.notes, 12);
    print!("{} ", t!("update.prompt"));
    let _ = io::stdout().flush();

    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err() {
        return false;
    }

    if i18n::is_yes_default(&answer) {
        match download_and_install(release) {
            Ok(()) => return true,
            Err(err) => {
                eprintln!("\x1b[1;31m[ssha] {} :\x1b[0m {err:#}", t!("update.failed"));
                eprintln!("  {}\n", t!("update.continuing"));
            }
        }
    }
    false
}

/// Prints the notes of several versions (newest first) with the ✨ / 🐛 / 🔧 sections.
pub fn print_release_notes(versions: &[VersionNotes]) {
    print_release_notes_limited(versions, usize::MAX);
}

fn print_release_notes_limited(versions: &[VersionNotes], max_items_per_version: usize) {
    for v in versions.iter().filter(|v| !v.notes.is_empty()) {
        let title = match &v.date {
            Some(d) => format!("v{} ({})", v.version, d),
            None => format!("v{}", v.version),
        };
        let rule = "─".repeat(54usize.saturating_sub(title.chars().count()));
        println!("\n\x1b[1;36m── {title} {rule}\x1b[0m");

        let mut shown = 0usize;
        let mut hidden = 0usize;
        for (emoji, key, items) in [
            ("✨", "update.notes.added", &v.notes.added),
            ("🐛", "update.notes.fixed", &v.notes.fixed),
            ("🔧", "update.notes.changed", &v.notes.changed),
        ] {
            if items.is_empty() {
                continue;
            }
            if shown >= max_items_per_version {
                hidden += items.iter().filter(|i| !i.starts_with("  ")).count();
                continue;
            }
            println!("\x1b[1m{emoji} {}\x1b[0m", i18n::tr(key));
            for item in items {
                let is_sub = item.starts_with("  ");
                if shown >= max_items_per_version {
                    if !is_sub {
                        hidden += 1;
                    }
                    continue;
                }
                if is_sub {
                    println!("     \x1b[2m◦\x1b[0m {}", item.trim_start());
                } else {
                    println!("   • {item}");
                    shown += 1;
                }
            }
        }
        if hidden > 0 {
            println!(
                "   \x1b[2m{}\x1b[0m",
                t!("update.notes.more", count = hidden)
            );
        }
    }
    println!();
}

/// Returns the notes of the versions released since the last launch (once after an update),
/// and records the current version in `settings.json`.
pub fn whats_new_since_last_run(storage: &Storage) -> Option<Vec<VersionNotes>> {
    let mut settings = storage.load_settings();
    let previous = settings.last_version.clone();
    if previous.as_deref() != Some(CURRENT_VERSION) {
        settings.last_version = Some(CURRENT_VERSION.to_string());
        let _ = storage.save_settings(&settings);
    }
    let previous = previous?;
    if !is_newer_version(CURRENT_VERSION, &previous) {
        return None;
    }
    let lang = i18n::current_lang();
    let mut notes = versions_between(
        parse_changelog(embedded_changelog(lang)),
        &previous,
        CURRENT_VERSION,
    );
    if notes.is_empty() && lang != Lang::En {
        notes = versions_between(
            parse_changelog(embedded_changelog(Lang::En)),
            &previous,
            CURRENT_VERSION,
        );
    }
    notes.retain(|n| !n.notes.is_empty());
    (!notes.is_empty()).then_some(notes)
}

/// Notes of the latest `count` versions from the embedded changelog (for `/changelog`).
pub fn recent_notes(count: usize) -> Vec<VersionNotes> {
    let mut all = parse_changelog(embedded_changelog(i18n::current_lang()));
    if all.is_empty() {
        all = parse_changelog(embedded_changelog(Lang::En));
    }
    all.sort_by_key(|v| std::cmp::Reverse(parse_semver(&v.version)));
    all.into_iter()
        .filter(|v| !v.notes.is_empty())
        .take(count.max(1))
        .collect()
}

/// `ssha changelog [-n N]`.
pub fn cmd_changelog(count: Option<usize>) {
    println!(
        "\x1b[1;36m[ssha]\x1b[0m {}",
        t!("update.changelog_title", version = CURRENT_VERSION)
    );
    print_release_notes(&recent_notes(count.unwrap_or(3)));
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

    #[test]
    fn parses_keep_a_changelog_sections() {
        let md = "### Added\n- **Live CPU/RAM** monitoring\n  - sub item with `code`\n- Second\n  continued\n### Fixed\n- A bug\n### Changed\n- Docs\n";
        let notes = parse_release_notes(md);
        assert_eq!(
            notes.added,
            vec![
                "Live CPU/RAM monitoring".to_string(),
                "  sub item with code".to_string(),
                "Second continued".to_string()
            ]
        );
        assert_eq!(notes.fixed, vec!["A bug".to_string()]);
        assert_eq!(notes.changed, vec!["Docs".to_string()]);
    }

    #[test]
    fn parses_old_french_release_bodies_and_ignores_generated_notes() {
        let md = "### Ajouté\n- Truc\n### Corrigé\n- Bidule\n\n## What's Changed\n* feat: x by @someone in https://example.com/pull/1\n";
        let notes = parse_release_notes(md);
        assert_eq!(notes.added, vec!["Truc".to_string()]);
        assert_eq!(notes.fixed, vec!["Bidule".to_string()]);
        assert!(notes.changed.is_empty());

        let generated = "## What's Changed\n* feat: x by @someone\n\n**Full Changelog**: a...b";
        assert!(parse_release_notes(generated).is_empty());
    }

    #[test]
    fn parses_full_changelog_and_selects_range() {
        let md = "# Changelog\n\n## [0.10.0] — 2026-11-24\n### Added\n- New\n\n## [0.9.0] — 2026-11-20\n### Fixed\n- Old fix\n\n## [0.8.0] — 2026-11-19\n### Added\n- Older\n";
        let all = parse_changelog(md);
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].version, "0.10.0");
        assert_eq!(all[0].date.as_deref(), Some("2026-11-24"));
        let range = versions_between(all, "0.8.0", "v0.10.0");
        let versions: Vec<_> = range.iter().map(|v| v.version.as_str()).collect();
        assert_eq!(versions, vec!["0.10.0", "0.9.0"]);
    }

    /// Every translated changelog must describe the same versions as the English one,
    /// and the current version must be documented in all of them.
    #[test]
    fn embedded_changelogs_are_consistent() {
        let reference: Vec<String> = parse_changelog(CHANGELOG_EN)
            .into_iter()
            .map(|v| v.version)
            .collect();
        assert!(reference.contains(&CURRENT_VERSION.to_string()));
        for lang in Lang::ALL {
            let parsed = parse_changelog(embedded_changelog(lang));
            let versions: Vec<String> = parsed.iter().map(|v| v.version.clone()).collect();
            assert_eq!(versions, reference, "versions differ in {}", lang.code());
            for v in &parsed {
                assert!(
                    !v.notes.is_empty(),
                    "empty notes for {} in {}",
                    v.version,
                    lang.code()
                );
            }
        }
    }
}
