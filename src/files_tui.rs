use crate::i18n::{self, tn, tr};
use crate::models::SshHost;
use crate::picker::{self, PickerResult};
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
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy)]
struct FileSlashCmd {
    cmd: &'static str,
    /// Translation key of the optional argument placeholder.
    arg_key: Option<&'static str>,
    /// Translation key of the description.
    desc_key: &'static str,
}

impl FileSlashCmd {
    fn usage(&self) -> String {
        match self.arg_key {
            Some(k) => format!("{} [{}]", self.cmd, tr(k)),
            None => self.cmd.to_string(),
        }
    }
}

const FILE_SLASH_COMMANDS: &[FileSlashCmd] = &[
    FileSlashCmd {
        cmd: "/download",
        arg_key: None,
        desc_key: "files.slash.download",
    },
    FileSlashCmd {
        cmd: "/upload",
        arg_key: None,
        desc_key: "files.slash.upload",
    },
    FileSlashCmd {
        cmd: "/upload-dir",
        arg_key: None,
        desc_key: "files.slash.upload_dir",
    },
    FileSlashCmd {
        cmd: "/mkdir",
        arg_key: Some("tui.arg.name"),
        desc_key: "files.slash.mkdir",
    },
    FileSlashCmd {
        cmd: "/rename",
        arg_key: Some("tui.arg.name"),
        desc_key: "files.slash.rename",
    },
    FileSlashCmd {
        cmd: "/del",
        arg_key: None,
        desc_key: "files.slash.del",
    },
    FileSlashCmd {
        cmd: "/view",
        arg_key: None,
        desc_key: "files.slash.view",
    },
    FileSlashCmd {
        cmd: "/cd",
        arg_key: Some("tui.arg.path"),
        desc_key: "files.slash.cd",
    },
    FileSlashCmd {
        cmd: "/hidden",
        arg_key: None,
        desc_key: "files.slash.hidden",
    },
    FileSlashCmd {
        cmd: "/refresh",
        arg_key: None,
        desc_key: "files.slash.refresh",
    },
    FileSlashCmd {
        cmd: "/help",
        arg_key: None,
        desc_key: "tui.slash.help",
    },
    FileSlashCmd {
        cmd: "/quit",
        arg_key: None,
        desc_key: "files.slash.quit",
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
    Download {
        remote_path: String,
        remote_name: String,
        is_dir: bool,
    },
    Upload,
    Mkdir,
    Rename {
        old_path: String,
        old_name: String,
    },
}

enum FileModal {
    None,
    UploadChoice,
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
                text: t!("files.status.connected").into_owned(),
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
        "\x1b[1;36m[ssha]\x1b[0m {}",
        t!(
            "files.opening",
            name = format!("\x1b[1m{}\x1b[0m", host.name),
            endpoint = host.endpoint_display()
        )
    );

    let client = SftpClient::connect(host, storage).await?;
    let start_dir = match initial_path {
        Some(p) => client
            .canonicalize(p)
            .await
            .unwrap_or_else(|_| p.to_string()),
        None => client
            .canonicalize(".")
            .await
            .unwrap_or_else(|_| "/".to_string()),
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
        FileModal::UploadChoice => {
            handle_upload_choice_key(state, key, client, terminal).await?;
            Ok(false)
        }
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
            if matches!(
                key.code,
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::F(1)
            ) || (key.modifiers.contains(KeyModifiers::CONTROL)
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
                        t!("files.status.hidden_shown")
                    } else {
                        t!("files.status.hidden_masked")
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
        "/upload-dir" | "/uploaddir" | "/put-dir" => "/upload-dir",
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
                    t!("tui.status.unknown_command", cmd = typed),
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
        "/upload-dir" => {
            pick_and_upload(state, true, client, _terminal).await;
        }
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
                                t!("files.status.renamed", from = entry.name, to = new_name),
                            );
                        }
                        Err(e) => state.set_status(StatusLevel::Error, format!("{e}")),
                    }
                } else {
                    state.set_status(StatusLevel::Info, t!("files.status.select_first"));
                }
            } else {
                open_rename_modal(state);
            }
        }
        "/del" => open_delete_modal(state),
        "/view" => {
            if let Some(entry) = state.selected_entry_owned() {
                if entry.is_dir {
                    state.set_status(StatusLevel::Info, t!("files.status.no_dir_preview"));
                } else {
                    open_preview(state, client, &entry).await;
                }
            } else {
                state.set_status(StatusLevel::Info, t!("files.status.select_first"));
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
                    t!("files.status.hidden_shown")
                } else {
                    t!("files.status.hidden_masked")
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
        state.set_status(StatusLevel::Info, t!("files.status.select_first"));
        return;
    };
    let default_dest = default_download_dir().join(&entry.name);
    let title = if entry.is_dir {
        t!("files.download.title_dir", name = entry.name)
    } else {
        t!("files.download.title_file", name = entry.name)
    };
    state.modal = FileModal::Input {
        kind: PromptKind::Download {
            remote_path: entry.path,
            remote_name: entry.name.clone(),
            is_dir: entry.is_dir,
        },
        title: format!(" {title} "),
        label: format!("{} : ", t!("files.download.label")),
        hint: t!("files.download.hint").into_owned(),
        value: default_dest.to_string_lossy().to_string(),
        error: None,
    };
}

fn open_upload_modal(state: &mut FileExplorerState) {
    state.modal = FileModal::UploadChoice;
}

fn open_manual_upload_modal(state: &mut FileExplorerState) {
    state.modal = FileModal::Input {
        kind: PromptKind::Upload,
        title: format!(" {} ", t!("files.upload.title", path = state.cwd)),
        label: format!("{} : ", t!("files.upload.label")),
        hint: t!("files.upload.hint").into_owned(),
        value: String::new(),
        error: None,
    };
}

async fn handle_upload_choice_key(
    state: &mut FileExplorerState,
    key: KeyEvent,
    client: &SftpClient,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> Result<()> {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => {
            state.modal = FileModal::None;
        }
        KeyCode::Enter | KeyCode::Char('f') | KeyCode::Char('F') | KeyCode::Char('1') => {
            state.modal = FileModal::None;
            pick_and_upload(state, false, client, terminal).await;
        }
        KeyCode::Char('d') | KeyCode::Char('D') | KeyCode::Char('2') => {
            state.modal = FileModal::None;
            pick_and_upload(state, true, client, terminal).await;
        }
        KeyCode::Char('s') | KeyCode::Char('S') | KeyCode::Char('3') => {
            open_manual_upload_modal(state);
        }
        _ => {}
    }
    Ok(())
}

async fn pick_and_upload(
    state: &mut FileExplorerState,
    pick_dir: bool,
    client: &SftpClient,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) {
    let title = if pick_dir {
        t!("cli.sftp.pick_folder_title", name = state.cwd).into_owned()
    } else {
        t!("cli.sftp.pick_file_title", name = state.cwd).into_owned()
    };
    state.set_status(
        StatusLevel::Info,
        if pick_dir {
            t!("files.status.opening_folder_picker")
        } else {
            t!("files.status.opening_file_picker")
        },
    );
    let _ = terminal.draw(|f| draw_files_ui(f, state));

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
        PickerResult::Selected(path) => {
            perform_upload(state, &path, client, terminal).await;
        }
        PickerResult::Cancelled => {
            state.set_status(StatusLevel::Info, t!("cli.sftp.upload_cancelled"));
        }
        PickerResult::Unavailable => {
            open_manual_upload_modal(state);
            state.set_status(StatusLevel::Info, t!("files.status.no_gui"));
        }
    }
}

async fn perform_upload(
    state: &mut FileExplorerState,
    local_src: &Path,
    client: &SftpClient,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) {
    state.set_status(
        StatusLevel::Info,
        t!(
            "files.status.uploading",
            path = local_src.display(),
            dest = state.cwd
        ),
    );
    let _ = terminal.draw(|f| draw_files_ui(f, state));

    match client.upload(local_src, &state.cwd, |_, _, _| {}).await {
        Ok((remote_dest, stats)) => {
            refresh_dir(state, client).await;
            state.set_status(
                StatusLevel::Success,
                t!(
                    "files.status.uploaded",
                    files = tn("common.files", stats.files as u64, &[]),
                    size = format_size(stats.bytes),
                    dest = remote_dest
                ),
            );
        }
        Err(e) => {
            state.set_status(
                StatusLevel::Error,
                t!("files.status.upload_failed", error = format!("{e:#}")),
            );
        }
    }
}

fn open_mkdir_modal(state: &mut FileExplorerState, prefill: Option<&str>) {
    state.modal = FileModal::Input {
        kind: PromptKind::Mkdir,
        title: format!(" {} ", t!("files.mkdir.title")),
        label: format!("{} : ", t!("files.mkdir.label")),
        hint: t!("files.mkdir.hint", path = state.cwd).into_owned(),
        value: prefill.unwrap_or("").to_string(),
        error: None,
    };
}

fn open_rename_modal(state: &mut FileExplorerState) {
    let Some(entry) = state.selected_entry_owned() else {
        state.set_status(StatusLevel::Info, t!("files.status.select_first"));
        return;
    };
    state.modal = FileModal::Input {
        kind: PromptKind::Rename {
            old_path: entry.path,
            old_name: entry.name.clone(),
        },
        title: format!(" {} ", t!("files.rename.title", name = entry.name)),
        label: format!("{} : ", t!("files.rename.label")),
        hint: t!("files.rename.hint").into_owned(),
        value: entry.name,
        error: None,
    };
}

fn open_delete_modal(state: &mut FileExplorerState) {
    let Some(entry) = state.selected_entry_owned() else {
        state.set_status(StatusLevel::Info, t!("files.status.select_first"));
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

    // Ctrl+P or F3 inside Download modal opens native OS folder picker
    if (ctrl && !alt && key.code == KeyCode::Char('p')) || key.code == KeyCode::F(3) {
        if let FileModal::Input {
            kind: PromptKind::Download { remote_name, .. },
            value,
            error,
            ..
        } = &mut state.modal
        {
            let name = remote_name.clone();
            let title = t!("files.download.pick_title", name = name).into_owned();
            let res = tokio::task::spawn_blocking(move || picker::pick_folder(&title))
                .await
                .unwrap_or(PickerResult::Unavailable);
            match res {
                PickerResult::Selected(dir) => {
                    *value = dir.join(&name).to_string_lossy().to_string();
                    *error = None;
                }
                PickerResult::Unavailable => {
                    *error = Some(t!("files.status.no_gui").into_owned());
                }
                PickerResult::Cancelled => {}
            }
            return Ok(());
        }
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
            error: Some(t!("files.err.empty").into_owned()),
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
                if is_dir {
                    t!("files.status.downloading_dir", name = remote_name)
                } else {
                    t!("files.status.downloading", name = remote_name)
                },
            );
            let _ = terminal.draw(|f| draw_files_ui(f, state));

            match client
                .download(&remote_path, &local_dest, |_, _, _| {})
                .await
            {
                Ok((saved_path, stats)) => {
                    state.set_status(
                        StatusLevel::Success,
                        t!(
                            "files.status.downloaded",
                            files = tn("common.files", stats.files as u64, &[]),
                            size = format_size(stats.bytes),
                            dest = saved_path.display()
                        ),
                    );
                }
                Err(e) => {
                    state.set_status(
                        StatusLevel::Error,
                        t!("files.status.download_failed", error = format!("{e:#}")),
                    );
                }
            }
        }
        PromptKind::Upload => {
            let local_src = resolve_local_path(&trimmed);
            state.set_status(
                StatusLevel::Info,
                t!(
                    "files.status.uploading",
                    path = local_src.display(),
                    dest = state.cwd
                ),
            );
            let _ = terminal.draw(|f| draw_files_ui(f, state));

            match client.upload(&local_src, &state.cwd, |_, _, _| {}).await {
                Ok((remote_dest, stats)) => {
                    refresh_dir(state, client).await;
                    state.set_status(
                        StatusLevel::Success,
                        t!(
                            "files.status.uploaded",
                            files = tn("common.files", stats.files as u64, &[]),
                            size = format_size(stats.bytes),
                            dest = remote_dest
                        ),
                    );
                }
                Err(e) => {
                    state.set_status(
                        StatusLevel::Error,
                        t!("files.status.upload_failed", error = format!("{e:#}")),
                    );
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
                        t!("files.status.mkdir_done", name = trimmed),
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
                        t!("files.status.renamed", from = old_name, to = trimmed),
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
        KeyCode::Char(c) if !i18n::is_yes(&c.to_string()) => {}
        KeyCode::Enter | KeyCode::Char(_) => {
            let modal = std::mem::replace(&mut state.modal, FileModal::None);
            if let FileModal::ConfirmDelete { path, name, is_dir } = modal {
                match client.remove_recursive(&path, is_dir).await {
                    Ok(()) => {
                        refresh_dir(state, client).await;
                        state.set_status(
                            StatusLevel::Success,
                            t!("files.status.deleted", name = name),
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
            state.set_status(StatusLevel::Info, t!("files.status.refreshed"));
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
                    format!(
                        "  {}",
                        t!("files.preview.binary", size = format_size(entry.size))
                    ),
                    String::new(),
                    format!("  {}", t!("files.preview.binary_hint")),
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
            state.set_status(
                StatusLevel::Error,
                t!("files.status.read_failed", name = entry.name, error = e),
            );
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

    if matches!(state.modal, FileModal::None) && state.is_slash_mode() && !state.input.contains(' ')
    {
        draw_file_slash_popup(frame, chunks[3], state);
    }

    match &state.modal {
        FileModal::None => {}
        FileModal::UploadChoice => draw_upload_choice_modal(frame, area, &state.cwd),
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
    let hidden_tag = if state.show_hidden {
        format!("{}: ON", t!("files.header.hidden"))
    } else {
        format!("{}: OFF", t!("files.header.hidden"))
    };
    let items = tn("files.header.items", total as u64, &[]);

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
            format!("  │  {items}  │  {hidden_tag}"),
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
            format!(" {} — {} ", t!("files.table.title"), state.cwd),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    if rows_data.is_empty() {
        let msg = if state.input.is_empty() {
            t!("files.table.empty")
        } else {
            t!("files.table.no_match")
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
        Cell::from(format!("  {}", t!("cli.list.col_name"))),
        Cell::from(t!("files.table.col_type")),
        Cell::from(t!("files.table.col_size")),
        Cell::from(t!("files.table.col_perms")),
        Cell::from(t!("files.table.col_modified")),
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
                    Cell::from(t!("files.table.type_parent"))
                        .style(Style::default().fg(Color::DarkGray)),
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
                        (t!("files.table.type_dir"), Style::default().fg(Color::Cyan))
                    } else if e.is_symlink {
                        (
                            t!("files.table.type_link"),
                            Style::default().fg(Color::Magenta),
                        )
                    } else {
                        (
                            t!("files.table.type_file"),
                            Style::default().fg(Color::Gray),
                        )
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
            Span::styled(
                format!(" {} : ", t!("files.status.path")),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(entry.path, Style::default().fg(Color::Cyan)),
            Span::styled(
                if entry.is_dir {
                    format!("  │  {}", t!("files.status.dir_hint"))
                } else {
                    format!("  │  {}", t!("files.status.file_hint"))
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
        format!(" {} ", t!("files.input.title_command"))
    } else {
        format!(" {} ", t!("files.input.title"))
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
                t!("files.input.placeholder"),
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
                    format!(" {:<18}", c.usage()),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(tr(c.desc_key), Style::default().fg(Color::Gray)),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(Span::styled(
                    format!(" {} ", t!("files.popup.commands")),
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
    let key = |k: &'static str, c: Color| {
        Span::styled(k, Style::default().fg(c).add_modifier(Modifier::BOLD))
    };
    let label = |l: std::borrow::Cow<'static, str>| {
        Span::styled(format!(" {l}  "), Style::default().fg(Color::DarkGray))
    };
    let hints = Line::from(vec![
        Span::raw(" "),
        key("Enter", Color::Green),
        label(t!("files.footer.open")),
        key("Ctrl+D", Color::Green),
        label(t!("files.footer.download")),
        key("Ctrl+U", Color::Green),
        label(t!("files.footer.upload")),
        key("Ctrl+N", Color::Green),
        label(t!("files.footer.mkdir")),
        key("Ctrl+E", Color::Green),
        label(t!("files.footer.rename")),
        key("Ctrl+X", Color::Red),
        label(t!("files.footer.delete")),
        key("Esc", Color::Cyan),
        Span::styled(
            format!(" {}", t!("files.footer.back")),
            Style::default().fg(Color::DarkGray),
        ),
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
        Span::styled(
            "  Enter",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {}    ", t!("files.modal.confirm")),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            "Esc",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {}", t!("tui.form.hint_cancel")),
            Style::default().fg(Color::DarkGray),
        ),
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
            format!(" {} ", t!("files.delete.title")),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));

    let question = if is_dir {
        t!("files.delete.question_dir")
    } else {
        t!("files.delete.question_file")
    };

    let lines = vec![
        Line::raw(""),
        Line::from(vec![
            Span::raw(format!("{question} ")),
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
                format!("Enter / {}", t!("tui.delete.yes_key")),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" : {}    ", t!("tui.delete.confirm"))),
            Span::styled(
                "Esc / n",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" : {}", t!("tui.form.hint_cancel"))),
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
        format!(" {} ", t!("files.preview.hint_truncated"))
    } else {
        format!(" {} ", t!("files.preview.hint"))
    };

    let block = Block::default()
        .title(Span::styled(
            title,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .title_bottom(
            Line::from(Span::styled(
                footer_hint,
                Style::default().fg(Color::DarkGray),
            ))
            .alignment(Alignment::Center),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let text_lines: Vec<Line> = lines
        .iter()
        .enumerate()
        .map(|(i, l)| {
            Line::from(vec![
                Span::styled(
                    format!("{:>4} │ ", i + 1),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(l.as_str(), Style::default().fg(Color::White)),
            ])
        })
        .collect();

    let p = Paragraph::new(text_lines).scroll((scroll, 0)).block(block);
    frame.render_widget(p, popup);
}

fn draw_files_help_modal(frame: &mut Frame, area: Rect) {
    let popup = centered_rect(84, 24, area);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .title(Span::styled(
            format!(" {} ", t!("files.help.title")),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    let heading = |text: std::borrow::Cow<'static, str>| {
        Line::from(Span::styled(
            format!("  {text}"),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ))
    };
    let row = |left: String, right: String| Line::from(format!("   {left:<22} {right}"));

    let mut lines = vec![Line::raw(""), heading(t!("tui.help.section_keys"))];
    for (keys, desc) in [
        ("↑ / ↓", "files.help.navigate"),
        ("Enter", "files.help.open"),
        ("Backspace", "files.help.parent"),
        ("Ctrl+D", "files.slash.download"),
        ("Ctrl+U", "files.help.upload"),
        ("Ctrl+N", "files.slash.mkdir"),
        ("Ctrl+E / F2", "files.slash.rename"),
        ("Ctrl+X / Del", "files.slash.del"),
        ("Ctrl+H", "files.slash.hidden"),
        ("Ctrl+R / F5", "files.slash.refresh"),
        ("Esc / Ctrl+Q", "files.slash.quit"),
    ] {
        lines.push(row(keys.to_string(), tr(desc)));
    }
    lines.push(Line::raw(""));
    lines.push(heading(t!("tui.help.section_terminal")));
    let name = tr("tui.arg.name");
    for (cmd, desc) in [
        (format!("ssha files <{name}>"), "cli.help.files.about"),
        (
            format!("ssha get <{name}> <remote> [local]"),
            "cli.help.get.about",
        ),
        (
            format!("ssha put <{name}> <local> [remote]"),
            "cli.help.put.about",
        ),
    ] {
        lines.push(row(cmd, tr(desc)));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        format!("  {}", t!("tui.help.close")),
        Style::default().fg(Color::DarkGray),
    )));

    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn draw_upload_choice_modal(frame: &mut Frame, area: Rect, cwd: &str) {
    let popup = centered_rect(72, 13, area);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .title(Span::styled(
            format!(" {} ", t!("files.upload.title", path = cwd)),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    let lines = vec![
        Line::raw(""),
        Line::from(Span::styled(
            format!("  {}", t!("files.upload_choice.question")),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Line::raw(""),
        Line::from(vec![
            Span::styled(
                "    [1] F / Enter  ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                t!("files.upload_choice.file"),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" ({})", t!("files.upload_choice.file_hint")),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "    [2] D          ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                t!("files.upload_choice.dir"),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" ({})", t!("files.upload_choice.dir_hint")),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                "    [3] S          ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(t!("files.upload_choice.manual")),
        ]),
        Line::raw(""),
        Line::from(Span::styled(
            format!("    Esc : {}", t!("tui.form.hint_cancel")),
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
