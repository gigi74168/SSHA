#[macro_use]
extern crate rust_i18n;

// All interface texts live in `locales/*.yml` (en, fr, ru, uk, es, it) and are compiled into the binary.
i18n!("locales", fallback = "en");

mod cli;
mod crypto;
mod files_tui;
mod i18n;
mod models;
mod monitor;
mod picker;
mod sftp;
mod ssh;
mod ssh_config;
mod storage;
mod tui;
mod updater;

use anyhow::Result;
use cli::Commands;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;
use std::sync::Arc;
use storage::Storage;
use tui::TuiAction;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => ExitCode::from(code as u8),
        Err(err) => {
            eprintln!("\x1b[1;31m[ssha] {} :\x1b[0m {err:#}", t!("main.error"));
            ExitCode::FAILURE
        }
    }
}

/// Picks the interface language: `SSHA_LANG` > `settings.json` > system language > English.
fn init_language(storage: &Storage) -> i18n::Lang {
    let settings = storage.load_settings();
    let lang = i18n::env_override()
        .or_else(|| settings.language.as_deref().and_then(i18n::Lang::from_code))
        .unwrap_or_else(i18n::detect_system_lang);
    i18n::set_lang(lang);
    lang
}

/// First interactive start: let the user choose the language (pre-selected on the system one).
fn first_start_language_picker(storage: &Storage) {
    let mut settings = storage.load_settings();
    if settings.language.is_some() || i18n::env_override().is_some() {
        return;
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return;
    }
    let detected = i18n::detect_system_lang();
    if let Ok(Some(lang)) = i18n::run_first_start_picker(detected) {
        i18n::set_lang(lang);
        settings.language = Some(lang.code().to_string());
        let _ = storage.save_settings(&settings);
    }
}

async fn run() -> Result<i32> {
    // The language must be known before parsing the command line so that `--help` is translated.
    let storage = Arc::new(Storage::new()?);
    init_language(&storage);
    let cli = cli::parse_localized();

    if let Some(cmd) = cli.command {
        match cmd {
            Commands::Update { yes } => updater::cmd_update(yes).await?,
            Commands::New(args) => cli::cmd_new(&storage, args)?,
            Commands::List => cli::cmd_list(&storage).await?,
            Commands::Files { name, path } => {
                cli::cmd_files(storage, &name, path.as_deref()).await?
            }
            Commands::Get {
                name,
                remote,
                local,
            } => cli::cmd_get(storage, &name, &remote, local.as_deref()).await?,
            Commands::Put {
                name,
                local,
                remote,
                dir,
            } => cli::cmd_put(storage, &name, local.as_deref(), remote.as_deref(), dir).await?,
            Commands::Export { output } => cli::cmd_export(&storage, output.as_deref())?,
            Commands::Import {
                input,
                keep_existing,
            } => cli::cmd_import(&storage, input.as_deref(), keep_existing)?,
            Commands::ImportSsh { path, overwrite } => {
                cli::cmd_import_ssh(&storage, path.as_deref(), overwrite)?
            }
            Commands::Security { action } => cli::cmd_security(&storage, action)?,
            Commands::Rm { name, yes } => cli::cmd_rm(&storage, &name, yes)?,
            Commands::Test { name } => cli::cmd_test(&storage, &name).await?,
            Commands::Changelog { count } => updater::cmd_changelog(count),
            Commands::Lang { code } => cli::cmd_lang(&storage, code.as_deref())?,
            Commands::Info => cli::cmd_info(&storage)?,
        }
        return Ok(0);
    }

    // First interactive start: choose the interface language before anything else is shown.
    first_start_language_picker(&storage);

    // Automatic update detection at startup (fast timeout, prompts user if newer release exists)
    if updater::check_and_prompt_startup().await {
        return Ok(0);
    }

    // "What's new" screen, shown once after ssha has been updated.
    let whats_new = updater::whats_new_since_last_run(&storage);

    // Unlock vault once before entering TUI if optional Master Password mode is enabled
    storage.ensure_unlocked()?;

    if let Some(target) = cli.target {
        if let Some(notes) = whats_new {
            updater::print_release_notes(&notes);
        }
        return cli::cmd_direct_connect(storage, &target).await;
    }

    // Default mode: interactive 100% CLI interface (`ssha`)
    let mut next_status: Option<(bool, String)> = None;
    let mut pending_whats_new = whats_new;

    loop {
        match tui::run_tui(&storage, next_status.take(), pending_whats_new.take())? {
            TuiAction::Quit => return Ok(0),
            TuiAction::BrowseFiles(host) => {
                if let Ok(mut vault) = storage.load_vault() {
                    vault.mark_used(&host.name);
                    let _ = storage.save_vault(&vault);
                }

                match files_tui::run_files_tui(&host, Arc::clone(&storage), None).await {
                    Ok(()) => {
                        next_status =
                            Some((true, t!("main.files_closed", name = host.name).into_owned()));
                    }
                    Err(err) => {
                        next_status = Some((
                            false,
                            t!("main.sftp_failed", name = host.name, error = err).into_owned(),
                        ));
                    }
                }
            }
            TuiAction::TestHost(host) => {
                match ssh::test_tcp_connection(&host.host, host.port).await {
                    Ok(rtt) => {
                        next_status = Some((
                            true,
                            t!(
                                "main.test_ok",
                                name = host.name,
                                endpoint = format!("{}:{}", host.host, host.port),
                                ms = format!("{:.1}", rtt.as_secs_f64() * 1000.0)
                            )
                            .into_owned(),
                        ));
                    }
                    Err(e) => {
                        next_status = Some((
                            false,
                            t!("main.test_failed", name = host.name, error = e).into_owned(),
                        ));
                    }
                }
            }
            TuiAction::Connect(host) => {
                // Record last_used before connecting
                if let Ok(mut vault) = storage.load_vault() {
                    vault.mark_used(&host.name);
                    let _ = storage.save_vault(&vault);
                }

                match ssh::connect_interactive(&host, Arc::clone(&storage)).await {
                    Ok(code) => {
                        eprintln!(
                            "\n\x1b[1;36m[ssha]\x1b[0m {}",
                            t!(
                                "main.disconnected",
                                name = format!("\x1b[1m{}\x1b[0m", host.name),
                                code = code
                            )
                        );
                        if !wait_return_to_menu()? {
                            return Ok(code as i32);
                        }
                        next_status = Some((
                            true,
                            t!("main.session_ended", name = host.name, code = code).into_owned(),
                        ));
                    }
                    Err(err) => {
                        eprintln!(
                            "\n\x1b[1;31m[ssha] {} :\x1b[0m {err:#}",
                            t!("main.connect_failed_title")
                        );
                        if !wait_return_to_menu()? {
                            return Ok(1);
                        }
                        next_status = Some((
                            false,
                            t!("main.connect_failed", name = host.name, error = err).into_owned(),
                        ));
                    }
                }
            }
        }
    }
}

/// Pauses cleanly after an SSH session ends so the user can read final output,
/// then returns `true` to reopen the `ssha` menu or `false` to quit to the shell.
fn wait_return_to_menu() -> Result<bool> {
    eprint!("\x1b[2m{}\x1b[0m", t!("main.press_enter"));
    io::stderr().flush()?;

    enable_raw_mode()?;
    let decision = loop {
        if let Event::Key(key) = event::read()? {
            if !matches!(key.kind, KeyEventKind::Press) {
                continue;
            }
            match key.code {
                KeyCode::Enter | KeyCode::Char(' ') => break true,
                KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => break false,
                KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                    break false
                }
                _ => {}
            }
        }
    };
    let _ = disable_raw_mode();
    eprintln!();
    Ok(decision)
}
