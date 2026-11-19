use crate::models::SshHost;
use crate::sftp::{
    default_download_dir, format_mtime, format_permissions, format_size, join_remote_path,
    parent_remote_path, resolve_local_path, RemoteEntry, SftpClient,
};
use crate::storage::Storage;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table, TableState, Wrap,
};
use ratatui::{Frame, Terminal};
use std::io;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy)]
struct FileSlashCmd {
    cmd: &'static str,
    usage: &'static str,
    desc: &'static str,
}

const FILE_SLASH_COMMANDS: &[FileSlashCmd] = &[
    FileSlashCmd {
        cmd: "/download",
        usage: "/download",
        desc: "Télécharger le fichier/dossier sélectionné sur ce PC",
    },
    FileSlashCmd {
        cmd: "/upload",
        usage: "/upload",
        desc: "Envoyer un fichier/dossier local vers le PC distant",
    },
    FileSlashCmd {
        cmd: "/mkdir",
        usage: "/mkdir [nom]",
        desc: "Créer un nouveau dossier distant",
    },
    FileSlashCmd {
        cmd: "/rename",
        usage: "/rename [nom]",
        desc: "Renommer l'élément sélectionné",
    },
    FileSlashCmd {
        cmd: "/del",
        usage: "/del",
        desc: "Supprimer l'élément sélectionné",
    },
    FileSlashCmd {
        cmd: "/view",
        usage: "/view",
        desc: "Afficher l'aperçu du fichier sélectionné",
    },
    FileSlashCmd {
        cmd: "/cd",
        usage: "/cd <chemin>",
        desc: "Aller directement vers un dossier distant",
    },
    FileSlashCmd {
        cmd: "/hidden",
        usage: "/hidden",
        desc: "Afficher / masquer les fichiers cachés",
    },
    FileSlashCmd {
        cmd: "/refresh",
        usage: "/refresh",
        desc: "Rafraîchir la liste des fichiers",
    },
    FileSlashCmd {
        cmd: "/help",
        usage: "/help",
        desc: "Afficher l'aide et les raccourcis",
    },
    FileSlashCmd {
        cmd: "/quit",
        usage: "/quit",
        desc: "Fermer et revenir au menu ssha",
    },
];

#[derive(Clone)]
enum StatusLevel {
    Info,
    Success,
    Error,
}

#[derive(Clone)]
struct StatusMsg {
    level: StatusLevel,
    text: String,
}

enum PromptKind {
    Download { remote_path: String, remote_name: String, is_dir: bool },
    Upload,
    Mkdir,
    Rename { old_path: String, old_name: String },
}

enum FileModal {
    None,
    Input {
        kind: PromptKind,
        title: String,
        label: String,
        hint: String,
        value: String,
        error: Option<String>,
    },
    ConfirmDelete {
        path: String,
        name: String,
        is_dir: bool,
    },
    Preview {
        title: String,
        lines: Vec<String>,
        scroll: u16,
        truncated: bool,
    },
    Help,
}

enum DisplayRow<'a> {
    ParentDir,
    Entry(&'a RemoteEntry),
}

struct FileExplorerState {
    host_name: String,
    host_endpoint: String,
    cwd: String,
    entries: Vec<RemoteEntry>,
    show_hidden: bool,
    input: String,
    selected: usize,
    slash_selected: usize,
    modal: FileModal,
    status: Option<StatusMsg>,
}

impl FileExplorerState {
    fn new(host: &SshHost, cwd: String, entries: Vec<RemoteEntry>) -> Self {
        Self {
            host_name: host.name.clone(),
            host_endpoint: host.endpoint_display(),
            cwd,
            entries,
            show_hidden: false,
            input: String::new(),
            selected: 0,
            slash_selected: 0,
            modal: FileModal::None,
            status: Some(StatusMsg {
                level: StatusLevel::Success,
                text: "Connecté en SFTP. Appuie sur Ctrl+D pour télécharger un fichier/dossier.".into(),
            }),
        }
    }

    fn is_slash_mode(&self) -> bool {
        self.input.starts_with('/')
    }

    fn visible_rows(&self) -> Vec<DisplayRow<'_>> {
        let mut rows = Vec::new();
        let query = if self.is_slash_mode() {
            String::new()
        } else {
            self.input.trim().to_lowercase()
        };

        if self.cwd != "/" && query.is_empty() {
            rows.push(DisplayRow::ParentDir);
        }

        for entry in &self.entries {
            if !self.show_hidden && entry.is_hidden() && query.is_empty() {
                continue;
            }
            if !query.is_empty() && !entry.name.to_lowercase().contains(&query) {
                continue;
            }
            rows.push(DisplayRow::Entry(entry));
        }
        rows
    }

    fn filtered_slash_commands(&self) -> Vec<FileSlashCmd> {
        if !self.is_slash_mode() {
            return Vec::new();
        }
        let token = self
            .input
            .split_whitespace()
            .next()
            .unwrap_or("/")
            .to_lowercase();
        FILE_SLASH_COMMANDS
            .iter()
            .copied()
            .filter(|c| c.cmd.starts_with(&token))
            .collect()
    }

    fn clamp_selection(&mut self) {
        let count = self.visible_rows().len();
        if count == 0 {
            self.selected = 0;
        } else if self.selected >= count {
            self.selected = count - 1;
        }

        let sc = self.filtered_slash_commands().len();
        if sc == 0 {
            self.slash_selected = 0;
        } else if self.slash_selected >= sc {
            self.slash_selected = sc - 1;
        }
    }

    fn selected_entry_owned(&self) -> Option<RemoteEntry> {
        let rows = self.visible_rows();
        match rows.get(self.selected) {
            Some(DisplayRow::Entry(e)) => Some((*e).clone()),
            _ => None,
        }
    }

    fn is_parent_selected(&self) -> bool {
        let rows = self.visible_rows();
        matches!(rows.get(self.selected), Some(DisplayRow::ParentDir))
    }

    fn set_status(&mut self, level: StatusLevel, text: impl Into<String>) {
        self.status = Some(StatusMsg {
            level,
            text: text.into(),
        });
    }
}

struct TuiGuard;

impl TuiGuard {
    fn enter() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        Ok(terminal)
    }
}

impl Drop for TuiGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

/// Runs the interactive 100% CLI remote file manager over SFTP.
pub async fn run_files_tui(
    host: &SshHost,
    storage: Arc<Storage>,
    initial_path: Option<&str>,
) -> Result<()> {
    eprintln!(
        "\x1b[1;36m[ssha]\x1b[0m Ouverture du gestionnaire de fichiers SFTP sur \x1b[1m{}\x1b[0m ({})...",
        host.name,
        host.endpoint_display()
    );

    let client = SftpClient::connect(host, storage).await?;
    let start_dir = match initial_path {
        Some(p) => client.canonicalize(p).await.unwrap_or_else(|_| p.to_string()),
        None => client.canonicalize(".").await.unwrap_or_else(|_| "/".to_string()),
    };
    let entries = client.list_dir(&start_dir).await?;

    let mut state = FileExplorerState::new(host, start_dir, entries);
    let mut terminal = TuiGuard::enter()?;
    let _guard = TuiGuard;

    loop {
        state.clamp_selection();
        terminal.draw(|f| draw_files_ui(f, &state))?;

        if !event::poll(Duration::from_millis(80))? {
            continue;
        }

        match event::read()? {
            Event::Key(key) => {
                if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                    continue;
                }
                let should_quit = handle_file_key(&mut state, key, &client, &mut terminal).await?;
                if should_quit {
                    break;
                }
            }
            Event::Paste(text) => {
                let cleaned = text.replace(['\r', '\n'], "");
                match &mut state.modal {
                    FileModal::Input { value, error, .. } => {
                        value.push_str(&cleaned);
                        *error = None;
                    }
                    FileModal::None => {
                        state.input.push_str(&cleaned);
                        state.slash_selected = 0;
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    drop(_guard);
    client.close().await;
    Ok(())
}

async fn handle_file_key(
    state: &mut FileExplorerState,
    key: KeyEvent,
    client: &SftpClient,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> Result<bool> {
    match &mut state.modal {
        FileModal::None => handle_main_file_key(state, key, client, terminal).await,
        FileModal::Input { .. } => {
            handle_input_modal_key(state, key, client, terminal).await?;
            Ok(false)
        }
        FileModal::ConfirmDelete { .. } => {
            handle_delete_modal_key(state, key, client).await?;
            Ok(false)
        }
        FileModal::Preview { scroll, lines, .. } => {
            match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                    state.modal = FileModal::None;
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    let max_scroll = lines.len().saturating_sub(1) as u16;
                    *scroll = (*scroll + 1).min(max_scroll);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    *scroll = scroll.saturating_sub(1);
                }
                KeyCode::PageDown => {
                    let max_scroll = lines.len().saturating_sub(1) as u16;
                    *scroll = (*scroll + 15).min(max_scroll);
                }
                KeyCode::PageUp => {
                    *scroll = scroll.saturating_sub(15);
                }
                _ => {}
            }
            Ok(false)
        }
        FileModal::Help => {
            if matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::F(1))
                || (key.modifiers.contains(KeyModifiers::CONTROL)
                    && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('q')))
            {
                state.modal = FileModal::None;
            }
            Ok(false)
        }
    }
}

async fn handle_main_file_key(
    state: &mut FileExplorerState,
    key: KeyEvent,
    client: &SftpClient,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> Result<bool> {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);

    if ctrl && !alt {
        match key.code {
            KeyCode::Char('c') | KeyCode::Char('q') => return Ok(true),
            KeyCode::Char('d') => {
                open_download_modal(state);
                return Ok(false);
            }
            KeyCode::Char('u') => {
                open_upload_modal(state);
                return Ok(false);
            }
            KeyCode::Char('n') => {
                open_mkdir_modal(state, None);
                return Ok(false);
            }
            KeyCode::Char('e') => {
                open_rename_modal(state);
                return Ok(false);
            }
            KeyCode::Char('x') => {
                open_delete_modal(state);
                return Ok(false);
            }
            KeyCode::Char('h') => {
                state.show_hidden = !state.show_hidden;
                state.selected = 0;
                state.set_status(
                    StatusLevel::Info,
                    if state.show_hidden {
                        "Fichiers cachés affichés."
                    } else {
                        "Fichiers cachés masqués."
                    },
                );
                return Ok(false);
            }
            KeyCode::Char('r') => {
                refresh_dir(state, client).await;
                return Ok(false);
            }
            _ => {}
        }
    }

    match key.code {
        KeyCode::F(1) => state.modal = FileModal::Help,
        KeyCode::F(2) => open_rename_modal(state),
        KeyCode::F(5) => refresh_dir(state, client).await,
        KeyCode::Delete => open_delete_modal(state),
        KeyCode::Esc => {
            if !state.input.is_empty() {
                state.input.clear();
            } else {
                return Ok(true);
            }
        }
        KeyCode::Up => {
            if state.is_slash_mode() && !state.input.contains(' ') {
                let c = state.filtered_slash_commands().len();
                if c > 0 {
                    state.slash_selected = if state.slash_selected == 0 {
                        c - 1
                    } else {
                        state.slash_selected - 1
                    };
                }
            } else {
                let c = state.visible_rows().len();
                if c > 0 {
                    state.selected = if state.selected == 0 {
                        c - 1
                    } else {
                        state.selected - 1
                    };
                }
            }
        }
        KeyCode::Down => {
            if state.is_slash_mode() && !state.input.contains(' ') {
                let c = state.filtered_slash_commands().len();
                if c > 0 {
                    state.slash_selected = (state.slash_selected + 1) % c;
                }
            } else {
                let c = state.visible_rows().len();
                if c > 0 {
                    state.selected = (state.selected + 1) % c;
                }
            }
        }
        KeyCode::Tab => {
            if state.is_slash_mode() {
                let cmds = state.filtered_slash_commands();
                if let Some(cmd) = cmds.get(state.slash_selected) {
                    state.input = cmd.cmd.to_string();
                }
            }
        }
        KeyCode::Backspace => {
            if !state.input.is_empty() {
                state.input.pop();
                state.slash_selected = 0;
            } else if state.cwd != "/" {
                let parent = parent_remote_path(&state.cwd);
                navigate_to(state, client, &parent).await;
            }
        }
        KeyCode::Enter => {
            if state.is_slash_mode() {
                return execute_file_slash_command(state, client, terminal).await;
            } else if state.is_parent_selected() {
                let parent = parent_remote_path(&state.cwd);
                navigate_to(state, client, &parent).await;
            } else if let Some(entry) = state.selected_entry_owned() {
                if entry.is_dir {
                    navigate_to(state, client, &entry.path).await;
                } else {
                    open_preview(state, client, &entry).await;
                }
            }
        }
        KeyCode::Char(c) => {
            state.input.push(c);
            state.slash_selected = 0;
            if !state.is_slash_mode() {
                state.selected = 0;
            }
        }
        _ => {}
    }

    Ok(false)
}

async fn execute_file_slash_command(
    state: &mut FileExplorerState,
    client: &SftpClient,
    _terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> Result<bool> {
    let raw = state.input.trim().to_string();
    let mut parts = raw.splitn(2, char::is_whitespace);
    let typed = parts.next().unwrap_or("").to_lowercase();
    let arg = parts.next().map(|s| s.trim()).filter(|s| !s.is_empty());

    let resolved = match typed.as_str() {
        "/download" | "/get" | "/dl" => "/download",
        "/upload" | "/put" | "/up" => "/upload",
        "/mkdir" | "/new" => "/mkdir",
        "/rename" | "/mv" => "/rename",
        "/del" | "/rm" | "/delete" => "/del",
        "/view" | "/cat" | "/open" => "/view",
        "/cd" => "/cd",
        "/hidden" => "/hidden",
        "/refresh" | "/ls" => "/refresh",
        "/help" | "/?" => "/help",
        "/quit" | "/exit" | "/q" => "/quit",
        _ => {
            let matches = state.filtered_slash_commands();
            if let Some(m) = matches.get(state.slash_selected) {
                m.cmd
            } else {
                state.set_status(
                    StatusLevel::Error,
                    format!("Commande inconnue '{}'. Tape /help pour la liste.", typed),
                );
                return Ok(false);
            }
        }
    };

    state.input.clear();
    state.slash_selected = 0;

    match resolved {
        "/download" => open_download_modal(state),
        "/upload" => open_upload_modal(state),
        "/mkdir" => open_mkdir_modal(state, arg),
        "/rename" => {
            if let Some(new_name) = arg {
                if let Some(entry) = state.selected_entry_owned() {
                    let target = join_remote_path(&state.cwd, new_name);
                    match client.rename(&entry.path, &target).await {
                        Ok(()) => {
                            refresh_dir(state, client).await;
                            state.set_status(
                                StatusLevel::Success,
                                format!("Renommé '{}' → '{}'.", entry.name, new_name),
                            );
                        }
                        Err(e) => state.set_status(StatusLevel::Error, format!("{e}")),
                    }
                } else {
                    state.set_status(StatusLevel::Info, "Sélectionne un élément à renommer.");
                }
            } else {
                open_rename_modal(state);
            }
        }
        "/del" => open_delete_modal(state),
        "/view" => {
            if let Some(entry) = state.selected_entry_owned() {
                if entry.is_dir {
                    state.set_status(StatusLevel::Info, "Impossible d'afficher l'aperçu d'un dossier.");
                } else {
                    open_preview(state, client, &entry).await;
                }
            } else {
                state.set_status(StatusLevel::Info, "Sélectionne un fichier pour l'aperçu.");
            }
        }
        "/cd" => {
            if let Some(dest) = arg {
                let expanded = client.expand_remote_path(dest).await;
                let target = if expanded.starts_with('/') {
                    expanded
                } else {
                    join_remote_path(&state.cwd, &expanded)
                };
                navigate_to(state, client, &target).await;
            } else {
                navigate_to(state, client, ".").await;
            }
        }
        "/hidden" => {
            state.show_hidden = !state.show_hidden;
            state.selected = 0;
            state.set_status(
                StatusLevel::Info,
                if state.show_hidden {
                    "Fichiers cachés affichés."
                } else {
                    "Fichiers cachés masqués."
                },
            );
        }
        "/refresh" => refresh_dir(state, client).await,
        "/help" => state.modal = FileModal::Help,
        "/quit" => return Ok(true),
        _ => {}
    }

    Ok(false)
}

fn open_download_modal(state: &mut FileExplorerState) {
    let Some(entry) = state.selected_entry_owned() else {
        state.set_status(StatusLevel::Info, "Sélectionne un fichier ou dossier à télécharger.");
        return;
    };
    let default_dest = default_download_dir().join(&entry.name);
    let kind_label = if entry.is_dir { "dossier" } else { "fichier" };
    state.modal = FileModal::Input {
        kind: PromptKind::Download {
            remote_path: entry.path,
            remote_name: entry.name.clone(),
            is_dir: entry.is_dir,
        },
        title: format!(" Télécharger le {kind_label} '{}' ", entry.name),
        label: "Destination locale : ".to_string(),
        hint: "Tu peux garder le chemin par défaut (Téléchargements) ou saisir un autre chemin.".to_string(),
        value: default_dest.to_string_lossy().to_string(),
        error: None,
    };
}

fn open_upload_modal(state: &mut FileExplorerState) {
    state.modal = FileModal::Input {
        kind: PromptKind::Upload,
        title: format!(" Envoyer vers {} ", state.cwd),
        label: "Fichier / dossier local : ".to_string(),
        hint: "Ex: ~/Desktop/rapport.pdf ou C:\\Users\\Moi\\fichier.txt".to_string(),
        value: String::new(),
        error: None,
    };
}

fn open_mkdir_modal(state: &mut FileExplorerState, prefill: Option<&str>) {
    state.modal = FileModal::Input {
        kind: PromptKind::Mkdir,
        title: " Créer un nouveau dossier distant ".to_string(),
        label: "Nom du dossier : ".to_string(),
        hint: format!("Sera créé dans {}", state.cwd),
        value: prefill.unwrap_or("").to_string(),
        error: None,
    };
}

fn open_rename_modal(state: &mut FileExplorerState) {
    let Some(entry) = state.selected_entry_owned() else {
        state.set_status(StatusLevel::Info, "Sélectionne un fichier ou dossier à renommer.");
        return;
    };
    state.modal = FileModal::Input {
        kind: PromptKind::Rename {
            old_path: entry.path,
            old_name: entry.name.clone(),
        },
        title: format!(" Renommer '{}' ", entry.name),
        label: "Nouveau nom : ".to_string(),
        hint: "Entrée pour valider, Esc pour annuler.".to_string(),
        value: entry.name,
        error: None,
    };
}

fn open_delete_modal(state: &mut FileExplorerState) {
    let Some(entry) = state.selected_entry_owned() else {
        state.set_status(StatusLevel::Info, "Sélectionne un fichier ou dossier à supprimer.");
        return;
    };
    state.modal = FileModal::ConfirmDelete {
        path: entry.path,
        name: entry.name,
        is_dir: entry.is_dir,
    };
}

async fn handle_input_modal_key(
    state: &mut FileExplorerState,
    key: KeyEvent,
    client: &SftpClient,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> Result<()> {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);

    if ctrl && !alt && key.code == KeyCode::Char('u') {
        if let FileModal::Input { value, error, .. } = &mut state.modal {
            value.clear();
            *error = None;
        }
        return Ok(());
    }

    match key.code {
        KeyCode::Esc => {
            state.modal = FileModal::None;
            return Ok(());
        }
        KeyCode::Backspace => {
            if let FileModal::Input { value, error, .. } = &mut state.modal {
                value.pop();
                *error = None;
            }
            return Ok(());
        }
        // On Windows AZERTY keyboards, AltGr (needed for `\`, `~`, `@`, `[`, `]`)
        // is reported as CONTROL + ALT; allow it as a normal character.
        KeyCode::Char(c) if !(ctrl && !alt) => {
            if let FileModal::Input { value, error, .. } = &mut state.modal {
                value.push(c);
                *error = None;
            }
            return Ok(());
        }
        KeyCode::Enter => {}
        _ => return Ok(()),
    }

    // Submit modal
    let modal = std::mem::replace(&mut state.modal, FileModal::None);
    let FileModal::Input {
        kind,
        title,
        label,
        hint,
        value,
        ..
    } = modal
    else {
        return Ok(());
    };

    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        state.modal = FileModal::Input {
            kind,
            title,
            label,
            hint,
            value,
            error: Some("Ce champ ne peut pas être vide.".to_string()),
        };
        return Ok(());
    }

    match kind {
        PromptKind::Download {
            remote_path,
            remote_name,
            is_dir,
        } => {
            let local_dest = resolve_local_path(&trimmed);
            state.set_status(
                StatusLevel::Info,
                format!(
                    "Téléchargement de '{}'{}...",
                    remote_name,
                    if is_dir { " (dossier)" } else { "" }
                ),
            );
            let _ = terminal.draw(|f| draw_files_ui(f, state));

            match client.download(&remote_path, &local_dest, |_, _, _| {}).await {
                Ok((saved_path, stats)) => {
                    state.set_status(
                        StatusLevel::Success,
                        format!(
                            "Téléchargé ({} fichier(s), {}) → {}",
                            stats.files,
                            format_size(stats.bytes),
                            saved_path.display()
                        ),
                    );
                }
                Err(e) => {
                    state.set_status(StatusLevel::Error, format!("Échec téléchargement : {e:#}"));
                }
            }
        }
        PromptKind::Upload => {
            let local_src = resolve_local_path(&trimmed);
            state.set_status(
                StatusLevel::Info,
                format!("Envoi de '{}' vers {}...", local_src.display(), state.cwd),
            );
            let _ = terminal.draw(|f| draw_files_ui(f, state));

            match client.upload(&local_src, &state.cwd, |_, _, _| {}).await {
                Ok((remote_dest, stats)) => {
                    refresh_dir(state, client).await;
                    state.set_status(
                        StatusLevel::Success,
                        format!(
                            "Envoyé ({} fichier(s), {}) → {}",
                            stats.files,
                            format_size(stats.bytes),
                            remote_dest
                        ),
                    );
                }
                Err(e) => {
                    state.set_status(StatusLevel::Error, format!("Échec envoi : {e:#}"));
                }
            }
        }
        PromptKind::Mkdir => {
            let new_dir = join_remote_path(&state.cwd, &trimmed);
            match client.mkdir(&new_dir).await {
                Ok(()) => {
                    refresh_dir(state, client).await;
                    state.set_status(
                        StatusLevel::Success,
                        format!("Dossier '{}' créé.", trimmed),
                    );
                }
                Err(e) => state.set_status(StatusLevel::Error, format!("{e:#}")),
            }
        }
        PromptKind::Rename { old_path, old_name } => {
            let new_path = join_remote_path(&state.cwd, &trimmed);
            match client.rename(&old_path, &new_path).await {
                Ok(()) => {
                    refresh_dir(state, client).await;
                    state.set_status(
                        StatusLevel::Success,
                        format!("Renommé '{}' → '{}'.", old_name, trimmed),
                    );
                }
                Err(e) => state.set_status(StatusLevel::Error, format!("{e:#}")),
            }
        }
    }

    Ok(())
}

async fn handle_delete_modal_key(
    state: &mut FileExplorerState,
    key: KeyEvent,
    client: &SftpClient,
) -> Result<()> {
    match key.code {
        KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
            state.modal = FileModal::None;
        }
        KeyCode::Enter
        | KeyCode::Char('o')
        | KeyCode::Char('O')
        | KeyCode::Char('y')
        | KeyCode::Char('Y') => {
            let modal = std::mem::replace(&mut state.modal, FileModal::None);
            if let FileModal::ConfirmDelete { path, name, is_dir } = modal {
                match client.remove_recursive(&path, is_dir).await {
                    Ok(()) => {
                        refresh_dir(state, client).await;
                        state.set_status(
                            StatusLevel::Success,
                            format!("'{}' supprimé du PC distant.", name),
                        );
                    }
                    Err(e) => state.set_status(StatusLevel::Error, format!("{e}")),
                }
            }
        }
        _ => {}
    }
    Ok(())
}

async fn navigate_to(state: &mut FileExplorerState, client: &SftpClient, path: &str) {
    let resolved = client
        .canonicalize(path)
        .await
        .unwrap_or_else(|_| path.to_string());
    match client.list_dir(&resolved).await {
        Ok(entries) => {
            state.cwd = resolved;
            state.entries = entries;
            state.selected = 0;
            state.input.clear();
            state.status = None;
        }
        Err(e) => {
            state.set_status(StatusLevel::Error, format!("{e}"));
        }
    }
}

async fn refresh_dir(state: &mut FileExplorerState, client: &SftpClient) {
    match client.list_dir(&state.cwd).await {
        Ok(entries) => {
            state.entries = entries;
            state.set_status(StatusLevel::Info, "Dossier rafraîchi.");
        }
        Err(e) => {
            state.set_status(StatusLevel::Error, format!("{e}"));
        }
    }
}

async fn open_preview(state: &mut FileExplorerState, client: &SftpClient, entry: &RemoteEntry) {
    const MAX_PREVIEW_BYTES: usize = 64 * 1024;
    match client.read_preview(&entry.path, MAX_PREVIEW_BYTES).await {
        Ok((bytes, truncated)) => {
            let is_binary = bytes.iter().take(1024).any(|&b| b == 0);
            let lines = if is_binary {
                vec![
                    String::new(),
                    format!("  Fichier binaire ({}) — aperçu texte indisponible.", format_size(entry.size)),
                    String::new(),
                    "  Ferme cette fenêtre puis appuie sur Ctrl+D (ou /download) pour le télécharger.".to_string(),
                ]
            } else {
                String::from_utf8_lossy(&bytes)
                    .lines()
                    .map(|l| l.replace('\t', "    "))
                    .collect()
            };
            state.modal = FileModal::Preview {
                title: format!(" {} ({}) ", entry.name, format_size(entry.size)),
                lines,
                scroll: 0,
                truncated,
            };
        }
        Err(e) => {
            state.set_status(StatusLevel::Error, format!("Impossible de lire '{}' : {e}", entry.name));
        }
    }
}

fn draw_files_ui(frame: &mut Frame, state: &FileExplorerState) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(8),    // File list
            Constraint::Length(2), // Status / selected info
            Constraint::Length(3), // Search / Slash command bar
            Constraint::Length(1), // Footer
        ])
        .split(area);

    draw_files_header(frame, chunks[0], state);
    draw_files_table(frame, chunks[1], state);
    draw_files_status(frame, chunks[2], state);
    draw_files_input(frame, chunks[3], state);
    draw_files_footer(frame, chunks[4]);

    if matches!(state.modal, FileModal::None) && state.is_slash_mode() && !state.input.contains(' ') {
        draw_file_slash_popup(frame, chunks[3], state);
    }

    match &state.modal {
        FileModal::None => {}
        FileModal::Input {
            title,
            label,
            hint,
            value,
            error,
            ..
        } => draw_input_modal(frame, area, title, label, hint, value, error.as_deref()),
        FileModal::ConfirmDelete { name, is_dir, .. } => {
            draw_delete_modal(frame, area, name, *is_dir)
        }
        FileModal::Preview {
            title,
            lines,
            scroll,
            truncated,
        } => draw_preview_modal(frame, area, title, lines, *scroll, *truncated),
        FileModal::Help => draw_files_help_modal(frame, area),
    }
}

fn draw_files_header(frame: &mut Frame, area: Rect, state: &FileExplorerState) {
    let total = state.entries.len();
    let hidden_tag = if state.show_hidden { "cachés: ON" } else { "cachés: OFF" };

    let line = Line::from(vec![
        Span::styled(
            " ssha files ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  {} ", state.host_name),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("({})  ", state.host_endpoint),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled("│  ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            state.cwd.as_str(),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  │  {total} éléments  │  {hidden_tag}"),
            Style::default().fg(Color::DarkGray),
        ),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    frame.render_widget(Paragraph::new(line).block(block), area);
}

fn draw_files_table(frame: &mut Frame, area: Rect, state: &FileExplorerState) {
    let rows_data = state.visible_rows();

    let block = Block::default()
        .title(Span::styled(
            format!(" Fichiers distants — {} ", state.cwd),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    if rows_data.is_empty() {
        let msg = if state.input.is_empty() {
            "Ce dossier est vide."
        } else {
            "Aucun fichier ne correspond au filtre."
        };
        let p = Paragraph::new(vec![
            Line::raw(""),
            Line::from(Span::styled(msg, Style::default().fg(Color::Yellow))),
        ])
        .alignment(Alignment::Center)
        .block(block);
        frame.render_widget(p, area);
        return;
    }

    let header = Row::new(vec![
        Cell::from("  Nom"),
        Cell::from("Type"),
        Cell::from("Taille"),
        Cell::from("Droits"),
        Cell::from("Modifié"),
    ])
    .style(
        Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .bottom_margin(1);

    let rows: Vec<Row> = rows_data
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let selected = i == state.selected;
            let prefix = if selected { "▸ " } else { "  " };

            match row {
                DisplayRow::ParentDir => Row::new(vec![
                    Cell::from(format!("{prefix}..")).style(
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Cell::from("PARENT").style(Style::default().fg(Color::DarkGray)),
                    Cell::from("—").style(Style::default().fg(Color::DarkGray)),
                    Cell::from("—").style(Style::default().fg(Color::DarkGray)),
                    Cell::from("—").style(Style::default().fg(Color::DarkGray)),
                ]),
                DisplayRow::Entry(e) => {
                    let display_name = if e.is_dir {
                        format!("{prefix}{}/", e.name)
                    } else if e.is_symlink {
                        format!("{prefix}{} ↗", e.name)
                    } else {
                        format!("{prefix}{}", e.name)
                    };

                    let name_style = if e.is_dir {
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else if e.is_symlink {
                        Style::default().fg(Color::Magenta)
                    } else if selected {
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };

                    let (type_label, type_style) = if e.is_dir {
                        ("DOSSIER", Style::default().fg(Color::Cyan))
                    } else if e.is_symlink {
                        ("LIEN", Style::default().fg(Color::Magenta))
                    } else {
                        ("FICHIER", Style::default().fg(Color::Gray))
                    };

                    let size_str = if e.is_dir {
                        "—".to_string()
                    } else {
                        format_size(e.size)
                    };

                    Row::new(vec![
                        Cell::from(display_name).style(name_style),
                        Cell::from(type_label).style(type_style),
                        Cell::from(size_str).style(Style::default().fg(Color::Yellow)),
                        Cell::from(format_permissions(e.permissions, e.is_dir, e.is_symlink))
                            .style(Style::default().fg(Color::DarkGray)),
                        Cell::from(format_mtime(e.mtime))
                            .style(Style::default().fg(Color::DarkGray)),
                    ])
                }
            }
        })
        .collect();

    let widths = [
        Constraint::Percentage(42),
        Constraint::Length(10),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Min(18),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .row_highlight_style(
            Style::default()
                .bg(Color::Rgb(30, 42, 58))
                .add_modifier(Modifier::BOLD),
        );

    let mut table_state = TableState::default();
    table_state.select(Some(state.selected));
    frame.render_stateful_widget(table, area, &mut table_state);
}

fn draw_files_status(frame: &mut Frame, area: Rect, state: &FileExplorerState) {
    let mut lines = Vec::new();
    if let Some(ref st) = state.status {
        let (icon, color) = match st.level {
            StatusLevel::Success => ("✓", Color::Green),
            StatusLevel::Error => ("✗", Color::Red),
            StatusLevel::Info => ("ℹ", Color::Cyan),
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {icon} "),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(st.text.as_str(), Style::default().fg(color)),
        ]));
    } else if let Some(entry) = state.selected_entry_owned() {
        lines.push(Line::from(vec![
            Span::styled(" Chemin : ", Style::default().fg(Color::DarkGray)),
            Span::styled(entry.path, Style::default().fg(Color::Cyan)),
            Span::styled(
                if entry.is_dir {
                    "  │  Entrée: ouvrir  │  Ctrl+D: télécharger le dossier"
                } else {
                    "  │  Entrée: aperçu  │  Ctrl+D: télécharger"
                },
                Style::default().fg(Color::DarkGray),
            ),
        ]));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

fn draw_files_input(frame: &mut Frame, area: Rect, state: &FileExplorerState) {
    let is_cmd = state.is_slash_mode();
    let border_color = if is_cmd { Color::Yellow } else { Color::Green };
    let title = if is_cmd {
        " Commande SFTP "
    } else {
        " Filtre / Commande (/download, /upload, /mkdir, /rename, /del, /cd) "
    };

    let content = if state.input.is_empty() {
        Line::from(vec![
            Span::styled(
                "> ",
                Style::default()
                    .fg(border_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Filtre un fichier ou tape /download, /upload, /mkdir...",
                Style::default().fg(Color::DarkGray),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled(
                "> ",
                Style::default()
                    .fg(border_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                state.input.as_str(),
                Style::default()
                    .fg(if is_cmd { Color::Yellow } else { Color::White })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("▏", Style::default().fg(border_color)),
        ])
    };

    let block = Block::default()
        .title(Span::styled(title, Style::default().fg(border_color)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    frame.render_widget(Paragraph::new(content).block(block), area);
}

fn draw_file_slash_popup(frame: &mut Frame, input_area: Rect, state: &FileExplorerState) {
    let cmds = state.filtered_slash_commands();
    if cmds.is_empty() {
        return;
    }

    let height = (cmds.len() as u16 + 2).min(input_area.y);
    if height < 3 {
        return;
    }
    let width = 70u16.min(input_area.width);
    let popup_area = Rect {
        x: input_area.x,
        y: input_area.y.saturating_sub(height),
        width,
        height,
    };

    frame.render_widget(Clear, popup_area);

    let items: Vec<ListItem> = cmds
        .iter()
        .map(|c| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!(" {:<16}", c.usage),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(c.desc, Style::default().fg(Color::Gray)),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(Span::styled(
                    " Commandes fichiers (Tab: compléter, Entrée: exécuter) ",
                    Style::default().fg(Color::Yellow),
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(45, 45, 25))
                .add_modifier(Modifier::BOLD),
        );

    let mut list_state = ListState::default();
    list_state.select(Some(state.slash_selected));
    frame.render_stateful_widget(list, popup_area, &mut list_state);
}

fn draw_files_footer(frame: &mut Frame, area: Rect) {
    let hints = Line::from(vec![
        Span::styled(" Entrée", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(" Ouvrir/Voir  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Ctrl+D", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(" Télécharger  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Ctrl+U", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(" Envoyer  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Ctrl+N", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(" Nouveau dossier  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Ctrl+E", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(" Renommer  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Ctrl+X", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        Span::styled(" Supprimer  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Esc", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(" Retour", Style::default().fg(Color::DarkGray)),
    ]);
    frame.render_widget(Paragraph::new(hints), area);
}

fn draw_input_modal(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    label: &str,
    hint: &str,
    value: &str,
    error: Option<&str>,
) {
    let popup = centered_rect(78, 11, area);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .title(Span::styled(
            title,
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    let mut lines = vec![
        Line::raw(""),
        Line::from(vec![
            Span::styled(
                format!("  {label}"),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(value, Style::default().fg(Color::White)),
            Span::styled("▏", Style::default().fg(Color::Green)),
        ]),
        Line::raw(""),
    ];

    if let Some(err) = error {
        lines.push(Line::from(Span::styled(
            format!("  ✗ {err}"),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            format!("  {hint}"),
            Style::default().fg(Color::DarkGray),
        )));
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled("  Entrée", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(" Valider    ", Style::default().fg(Color::DarkGray)),
        Span::styled("Esc", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        Span::styled(" Annuler", Style::default().fg(Color::DarkGray)),
    ]));

    let p = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(block);
    frame.render_widget(p, popup);
}

fn draw_delete_modal(frame: &mut Frame, area: Rect, name: &str, is_dir: bool) {
    let popup = centered_rect(64, 9, area);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .title(Span::styled(
            " Confirmer la suppression distante ",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));

    let kind = if is_dir {
        "le dossier (et tout son contenu)"
    } else {
        "le fichier"
    };

    let lines = vec![
        Line::raw(""),
        Line::from(vec![
            Span::raw(format!("Supprimer définitivement {kind} ")),
            Span::styled(
                name,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" ?"),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled(
                "Entrée / o",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" : Supprimer    "),
            Span::styled(
                "Esc / n",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" : Annuler"),
        ]),
    ];

    frame.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .block(block),
        popup,
    );
}

fn draw_preview_modal(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    lines: &[String],
    scroll: u16,
    truncated: bool,
) {
    let width = area.width.saturating_sub(6).min(104);
    let height = area.height.saturating_sub(4).min(30);
    let popup = centered_rect(width, height, area);
    frame.render_widget(Clear, popup);

    let footer_hint = if truncated {
        " Aperçu limité à 64 Ko — ↑↓: défiler, Esc: fermer "
    } else {
        " ↑↓ / PgUp / PgDn: défiler — Esc: fermer "
    };

    let block = Block::default()
        .title(Span::styled(
            title,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .title_bottom(
            Line::from(Span::styled(footer_hint, Style::default().fg(Color::DarkGray)))
                .alignment(Alignment::Center),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let text_lines: Vec<Line> = lines
        .iter()
        .enumerate()
        .map(|(i, l)| {
            Line::from(vec![
                Span::styled(format!("{:>4} │ ", i + 1), Style::default().fg(Color::DarkGray)),
                Span::styled(l.as_str(), Style::default().fg(Color::White)),
            ])
        })
        .collect();

    let p = Paragraph::new(text_lines)
        .scroll((scroll, 0))
        .block(block);
    frame.render_widget(p, popup);
}

fn draw_files_help_modal(frame: &mut Frame, area: Rect) {
    let popup = centered_rect(72, 22, area);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .title(Span::styled(
            " Aide — Gestionnaire de fichiers SFTP ",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    let lines = vec![
        Line::raw(""),
        Line::from(Span::styled(
            "  Raccourcis clavier :",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("    ↑ / ↓            Naviguer dans les fichiers"),
        Line::from("    Entrée           Ouvrir un dossier ou afficher l'aperçu d'un fichier"),
        Line::from("    Backspace        Remonter au dossier parent (..)"),
        Line::from("    Ctrl+D           Télécharger le fichier/dossier sur ce PC"),
        Line::from("    Ctrl+U           Envoyer un fichier/dossier local vers ce PC distant"),
        Line::from("    Ctrl+N           Créer un nouveau dossier distant"),
        Line::from("    Ctrl+E / F2      Renommer le fichier/dossier sélectionné"),
        Line::from("    Ctrl+X / Suppr   Supprimer sur le PC distant"),
        Line::from("    Ctrl+H           Afficher / masquer les fichiers cachés"),
        Line::from("    Ctrl+R / F5      Rafraîchir la liste"),
        Line::from("    Esc / Ctrl+Q     Revenir au menu ssha"),
        Line::raw(""),
        Line::from(Span::styled(
            "  Commandes directes depuis ton terminal :",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("    ssha files <nom>                 Ouvrir l'explorateur distant"),
        Line::from("    ssha get <nom> <distant> [local] Télécharger un fichier/dossier"),
        Line::from("    ssha put <nom> <local> [distant] Envoyer un fichier/dossier"),
        Line::raw(""),
        Line::from(Span::styled(
            "  Appuie sur Esc ou Entrée pour fermer.",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    frame.render_widget(Paragraph::new(lines).block(block), popup);
}

fn centered_rect(max_width: u16, max_height: u16, area: Rect) -> Rect {
    let width = max_width.min(area.width.saturating_sub(2));
    let height = max_height.min(area.height.saturating_sub(2));
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    Rect {
        x,
        y,
        width,
        height,
    }
}
