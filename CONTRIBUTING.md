# Contributing to `ssha`

Thanks for your interest in **`ssha`**! Every contribution (bug fix, new feature, documentation improvement, tests or translations) is welcome.

## Requirements

- **Rust** stable (`rustup`: https://rustup.rs)
- **Git**

## Getting started

```bash
git clone https://github.com/gigi74168/SSHA.git
cd SSHA
cargo test
cargo run
```

To avoid touching your personal vault while developing, use a temporary folder:

```bash
SSHA_CONFIG_DIR=/tmp/ssha-dev SSHA_NO_UPDATE_CHECK=1 cargo run
```

Add `SSHA_LANG=<code>` to try the interface in another language.

## Code architecture

| File | Role |
|---|---|
| `src/main.rs` | Entry point, language setup, CLI / TUI dispatch, main loop |
| `src/cli.rs` | Direct subcommands (`new`, `list`, `files`, `get`, `put`, `export`, `import`, `import-ssh`, `security`, `update`, `changelog`, `lang`, `info`) and translated `--help` |
| `src/tui.rs` | Main interactive interface (`ratatui`), live search, `Tab` autocompletion, `UP`/`DOWN` status, CPU/RAM column |
| `src/monitor.rs` | Live CPU/RAM monitoring (background SSH sessions reading `/proc`) |
| `src/files_tui.rs` | 100% CLI remote SFTP file explorer |
| `src/ssh.rs` | Native SSH client (`russh`), ProxyJump, LocalForward, PTY, TOFU, quiet background connections |
| `src/sftp.rs` | Native SFTP client (`russh-sftp`), recursive transfers, automatic SFTP installation |
| `src/ssh_config.rs` | `~/.ssh/config` (OpenSSH) parser and importer |
| `src/crypto.rs` | AES-256-GCM encryption (automatic DPAPI/`0600` key + optional Argon2id master password) |
| `src/storage.rs` | Atomic `vault.enc` persistence, portable export/import, `known_hosts.json`, `settings.json` |
| `src/picker.rs` | Native dialogs (Windows PowerShell Forms, macOS `osascript`, Linux `zenity`/`kdialog`) |
| `src/updater.rs` | GitHub release detection, release notes, "What's new", atomic update (`self-replace`) |
| `src/i18n.rs` | Languages, system language detection, language picker, plurals |
| `locales/*.yml` | All interface texts in the 6 languages |

## Translations

All user-facing texts live in `locales/*.yml` ([rust-i18n](https://github.com/longbridge/rust-i18n) format, version 2: every key lists its 6 translations together).

- **Every new key must be translated into the 6 languages** (`en`, `fr`, `ru`, `uk`, `es`, `it`) with the same `%{placeholders}`. `cargo test` fails otherwise.
- Use `t!("key", name = value)` in the code, never a hard-coded sentence.
- Counted texts use `.one` / `.few` / `.many` sub-keys and `i18n::tn()` (Russian and Ukrainian have three plural forms).
- English is the reference and the fallback language.

## Changelog

Every release must be documented in the **6 changelog files** — `CHANGELOG.md` (English, reference), `CHANGELOG.fr.md`, `CHANGELOG.ru.md`, `CHANGELOG.uk.md`, `CHANGELOG.es.md`, `CHANGELOG.it.md`:

- Same `## [x.y.z] — YYYY-MM-DD` headings in every file (checked by `cargo test`).
- Section titles stay in English (`### Added`, `### Fixed`, `### Changed`): `ssha` reads them to show the new features ✨, fixes 🐛 and changes 🔧 in the update prompt and the "What's new" screen.
- The GitHub release description is generated from the matching `CHANGELOG.md` section.

## Before opening a Pull Request

1. Check that the code builds without warnings:
   ```bash
   cargo check --all-targets
   ```
2. Run all unit and integration tests:
   ```bash
   cargo test
   ```
3. Format the code with `cargo fmt`.
4. Make sure the changes stay compatible with **Windows 10/11**, **Linux** and **macOS** (CI checks the 3 systems automatically).
5. Describe the change and the use case clearly in your Pull Request.

## Reporting a bug or suggesting an idea

Open a [GitHub issue](https://github.com/gigi74168/SSHA/issues) with your OS, your version (`ssha --version`) and the steps to reproduce the problem.
