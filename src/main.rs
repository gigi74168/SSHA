mod cli;
mod crypto;
mod files_tui;
mod models;
mod sftp;
mod ssh;
mod storage;
mod tui;
mod updater;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use std::io::{self, Write};
use std::process::ExitCode;
use std::sync::Arc;
use storage::Storage;
use tui::TuiAction;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => ExitCode::from(code as u8),
        Err(err) => {
            eprintln!("\x1b[1;31m[ssha] Erreur :\x1b[0m {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<i32> {
    let cli = Cli::parse();

    if let Some(Commands::Update { yes }) = cli.command {
        updater::cmd_update(yes).await?;
        return Ok(0);
    }

    let storage = Arc::new(Storage::new()?);

    if let Some(cmd) = cli.command {
        match cmd {
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
            } => cli::cmd_put(storage, &name, &local, remote.as_deref()).await?,
            Commands::Rm { name, yes } => cli::cmd_rm(&storage, &name, yes)?,
            Commands::Test { name } => cli::cmd_test(&storage, &name).await?,
            Commands::Update { .. } => unreachable!(),
            Commands::Info => cli::cmd_info(&storage)?,
        }
        return Ok(0);
    }

    // Automatic update detection at startup (fast 2s timeout, prompts user if newer release exists)
    if updater::check_and_prompt_startup().await {
        return Ok(0);
    }

    if let Some(target) = cli.target {
        return cli::cmd_direct_connect(storage, &target).await;
    }

    // Default mode: interactive 100% CLI interface (`ssha`)
    let mut next_status: Option<(bool, String)> = None;

    loop {
        match tui::run_tui(&storage, next_status.take())? {
            TuiAction::Quit => return Ok(0),
            TuiAction::BrowseFiles(host) => {
                if let Ok(mut vault) = storage.load_vault() {
                    vault.mark_used(&host.name);
                    let _ = storage.save_vault(&vault);
                }

                match files_tui::run_files_tui(&host, Arc::clone(&storage), None).await {
                    Ok(()) => {
                        next_status = Some((
                            true,
                            format!("Gestionnaire de fichiers '{}' fermé.", host.name),
                        ));
                    }
                    Err(err) => {
                        next_status = Some((
                            false,
                            format!("SFTP '{}' échoué : {err}", host.name),
                        ));
                    }
                }
            }
            TuiAction::TestHost(host) => {
                match ssh::test_tcp_connection(&host.host, host.port).await {
                    Ok(rtt) => {
                        next_status = Some((
                            true,
                            format!(
                                "{} ({}:{}) joignable en {:.1} ms.",
                                host.name,
                                host.host,
                                host.port,
                                rtt.as_secs_f64() * 1000.0
                            ),
                        ));
                    }
                    Err(e) => {
                        next_status = Some((
                            false,
                            format!("Test échoué pour '{}' : {e}", host.name),
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
                            "\n\x1b[1;36m[ssha]\x1b[0m Déconnecté de \x1b[1m{}\x1b[0m (code de sortie : {}).",
                            host.name, code
                        );
                        if !wait_return_to_menu()? {
                            return Ok(code as i32);
                        }
                        next_status = Some((
                            true,
                            format!("Session '{}' terminée (code {}).", host.name, code),
                        ));
                    }
                    Err(err) => {
                        eprintln!("\n\x1b[1;31m[ssha] Échec de connexion :\x1b[0m {err:#}");
                        if !wait_return_to_menu()? {
                            return Ok(1);
                        }
                        next_status = Some((
                            false,
                            format!("Connexion à '{}' échouée : {err}", host.name),
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
    eprint!("\x1b[2mAppuie sur Entrée pour revenir au menu ssha, ou 'q' pour quitter...\x1b[0m");
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
                KeyCode::Char('c')
                    if key.modifiers.contains(event::KeyModifiers::CONTROL) =>
                {
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
