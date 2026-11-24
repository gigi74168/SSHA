use crate::i18n::{self, tn, tr, Lang};
use crate::models::{format_relative_time, AuthMethod, SshHost, VaultData};
use crate::monitor::{self, MetricsState, MonitorManager};
use crate::picker::{self, PickerResult};
use crate::sftp::{default_download_dir, resolve_local_path};
use crate::ssh::{probe_host, PingState};
use crate::ssh_config;
use crate::storage::{export_vault_to_file, import_vault_from_file, Storage};
use crate::updater::{self, VersionNotes};
use anyhow::Result;
use chrono::Utc;
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
use std::collections::HashMap;
use std::io;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub enum TuiAction {
    Connect(SshHost),
    BrowseFiles(SshHost),
    TestHost(SshHost),
    Quit,
}

#[derive(Clone, Copy)]
struct SlashCommandDef {
    cmd: &'static str,
    /// Translation key of the optional argument placeholder (e.g. `[name]`).
    arg_key: Option<&'static str>,
    /// Translation key of the description.
    desc_key: &'static str,
}

impl SlashCommandDef {
    fn usage(&self) -> String {
        match self.arg_key {
            Some(k) => format!("{} [{}]", self.cmd, tr(k)),
            None => self.cmd.to_string(),
        }
    }
}

const SLASH_COMMANDS: &[SlashCommandDef] = &[
    SlashCommandDef {
        cmd: "/new",
        arg_key: None,
        desc_key: "tui.slash.new",
    },
    SlashCommandDef {
        cmd: "/files",
        arg_key: Some("tui.arg.name"),
        desc_key: "tui.slash.files",
    },
    SlashCommandDef {
        cmd: "/edit",
        arg_key: Some("tui.arg.name"),
        desc_key: "tui.slash.edit",
    },
    SlashCommandDef {
        cmd: "/del",
        arg_key: Some("tui.arg.name"),
        desc_key: "tui.slash.del",
    },
    SlashCommandDef {
        cmd: "/connect",
        arg_key: Some("tui.arg.name"),
        desc_key: "tui.slash.connect",
    },
    SlashCommandDef {
        cmd: "/test",
        arg_key: Some("tui.arg.name"),
        desc_key: "tui.slash.test",
    },
    SlashCommandDef {
        cmd: "/monitor",
        arg_key: Some("tui.arg.name"),
        desc_key: "tui.slash.monitor",
    },
    SlashCommandDef {
        cmd: "/refresh",
        arg_key: None,
        desc_key: "tui.slash.refresh",
    },
    SlashCommandDef {
        cmd: "/export",
        arg_key: Some("tui.arg.file"),
        desc_key: "tui.slash.export",
    },
    SlashCommandDef {
        cmd: "/import",
        arg_key: Some("tui.arg.file"),
        desc_key: "tui.slash.import",
    },
    SlashCommandDef {
        cmd: "/import-ssh",
        arg_key: Some("tui.arg.path"),
        desc_key: "tui.slash.import_ssh",
    },
    SlashCommandDef {
        cmd: "/lang",
        arg_key: Some("tui.arg.code"),
        desc_key: "tui.slash.lang",
    },
    SlashCommandDef {
        cmd: "/changelog",
        arg_key: None,
        desc_key: "tui.slash.changelog",
    },
    SlashCommandDef {
        cmd: "/clear",
        arg_key: None,
        desc_key: "tui.slash.clear",
    },
    SlashCommandDef {
        cmd: "/help",
        arg_key: None,
        desc_key: "tui.slash.help",
    },
    SlashCommandDef {
        cmd: "/quit",
        arg_key: None,
        desc_key: "tui.slash.quit",
    },
];

/// Slash commands whose argument is a machine name (autocompletion of names).
const HOST_ARG_COMMANDS: &[&str] = &[
    "/connect", "/c", "/open", "/files", "/sftp", "/f", "/edit", "/e", "/del", "/delete", "/rm",
    "/remove", "/test", "/ping", "/monitor", "/mon", "/m",
];

#[derive(Clone)]
enum StatusLevel {
    Info,
    Success,
    Error,
}

#[derive(Clone)]
struct StatusMessage {
    level: StatusLevel,
    text: String,
}

enum Modal {
    None,
    Form(Box<HostForm>),
    ConfirmDelete {
        host_name: String,
        endpoint: String,
    },
    Help {
        scroll: u16,
    },
    LangPicker {
        selected: usize,
    },
    WhatsNew {
        notes: Vec<VersionNotes>,
        scroll: u16,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FormAuthKind {
    Password,
    Key,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FormField {
    Name,
    Host,
    Port,
    Username,
    AuthKind,
    Password,
    KeyPath,
    KeyPassphrase,
    Monitor,
    Group,
    Note,
}

struct HostForm {
    editing_original_name: Option<String>,
    name: String,
    host: String,
    port: String,
    username: String,
    auth_kind: FormAuthKind,
    password: String,
    key_path: String,
    key_passphrase: String,
    group: String,
    note: String,
    monitor: bool,
    focused_index: usize,
    show_secret: bool,
    error: Option<String>,
}

impl HostForm {
    fn new_empty() -> Self {
        Self {
            editing_original_name: None,
            name: String::new(),
            host: String::new(),
            port: "22".to_string(),
            username: default_username(),
            auth_kind: FormAuthKind::Password,
            password: String::new(),
            key_path: "~/.ssh/id_ed25519".to_string(),
            key_passphrase: String::new(),
            group: String::new(),
            note: String::new(),
            monitor: false,
            focused_index: 0,
            show_secret: false,
            error: None,
        }
    }

    fn from_host(h: &SshHost) -> Self {
        let (auth_kind, password, key_path, key_passphrase) = match &h.auth {
            AuthMethod::Password { password } => (
                FormAuthKind::Password,
                password.clone(),
                "~/.ssh/id_ed25519".to_string(),
                String::new(),
            ),
            AuthMethod::Key { path, passphrase } => (
                FormAuthKind::Key,
                String::new(),
                path.clone(),
                passphrase.clone().unwrap_or_default(),
            ),
        };

        Self {
            editing_original_name: Some(h.name.clone()),
            name: h.name.clone(),
            host: h.host.clone(),
            port: h.port.to_string(),
            username: h.username.clone(),
            auth_kind,
            password,
            key_path,
            key_passphrase,
            group: h.group.clone().unwrap_or_default(),
            note: h.note.clone().unwrap_or_default(),
            monitor: h.monitor,
            focused_index: 0,
            show_secret: false,
            error: None,
        }
    }

    fn fields(&self) -> Vec<FormField> {
        match self.auth_kind {
            FormAuthKind::Password => vec![
                FormField::Name,
                FormField::Host,
                FormField::Port,
                FormField::Username,
                FormField::AuthKind,
                FormField::Password,
                FormField::Monitor,
                FormField::Group,
                FormField::Note,
            ],
            FormAuthKind::Key => vec![
                FormField::Name,
                FormField::Host,
                FormField::Port,
                FormField::Username,
                FormField::AuthKind,
                FormField::KeyPath,
                FormField::KeyPassphrase,
                FormField::Monitor,
                FormField::Group,
                FormField::Note,
            ],
        }
    }

    fn current_field(&self) -> FormField {
        let fields = self.fields();
        fields[self.focused_index.min(fields.len() - 1)]
    }

    fn active_buffer_mut(&mut self) -> Option<&mut String> {
        match self.current_field() {
            FormField::Name => Some(&mut self.name),
            FormField::Host => Some(&mut self.host),
            FormField::Port => Some(&mut self.port),
            FormField::Username => Some(&mut self.username),
            FormField::AuthKind | FormField::Monitor => None,
            FormField::Password => Some(&mut self.password),
            FormField::KeyPath => Some(&mut self.key_path),
            FormField::KeyPassphrase => Some(&mut self.key_passphrase),
            FormField::Group => Some(&mut self.group),
            FormField::Note => Some(&mut self.note),
        }
    }

    fn next_field(&mut self) {
        let len = self.fields().len();
        self.focused_index = (self.focused_index + 1) % len;
    }

    fn prev_field(&mut self) {
        let len = self.fields().len();
        self.focused_index = if self.focused_index == 0 {
            len - 1
        } else {
            self.focused_index - 1
        };
    }

    fn toggle_auth_kind(&mut self) {
        self.auth_kind = match self.auth_kind {
            FormAuthKind::Password => FormAuthKind::Key,
            FormAuthKind::Key => FormAuthKind::Password,
        };
    }

    fn build_host(&self, vault: &VaultData) -> Result<SshHost, String> {
        let name = self.name.trim().to_string();
        if name.is_empty() {
            return Err(t!("tui.form.err.name_required").into_owned());
        }
        if name.starts_with('/') {
            return Err(t!("common.err.name_slash").into_owned());
        }

        // Check duplicate name unless editing the same entry
        if let Some(existing) = vault.find_by_name(&name) {
            let is_same = self
                .editing_original_name
                .as_deref()
                .map(|orig| orig.eq_ignore_ascii_case(&existing.name))
                .unwrap_or(false);
            if !is_same {
                return Err(t!("common.err.name_exists", name = name).into_owned());
            }
        }

        let host = self.host.trim().to_string();
        if host.is_empty() {
            return Err(t!("tui.form.err.host_required").into_owned());
        }

        let port_str = self.port.trim();
        let port: u16 = if port_str.is_empty() {
            22
        } else {
            port_str
                .parse::<u16>()
                .ok()
                .filter(|&p| p > 0)
                .ok_or_else(|| t!("tui.form.err.port").into_owned())?
        };

        let username = self.username.trim().to_string();
        if username.is_empty() {
            return Err(t!("tui.form.err.user_required").into_owned());
        }

        let auth = match self.auth_kind {
            FormAuthKind::Password => {
                if self.password.is_empty() {
                    return Err(t!("tui.form.err.password_required").into_owned());
                }
                AuthMethod::Password {
                    password: self.password.clone(),
                }
            }
            FormAuthKind::Key => {
                let path = self.key_path.trim().to_string();
                if path.is_empty() {
                    return Err(t!("tui.form.err.key_required").into_owned());
                }
                let passphrase = if self.key_passphrase.is_empty() {
                    None
                } else {
                    Some(self.key_passphrase.clone())
                };
                AuthMethod::Key { path, passphrase }
            }
        };

        let group = non_empty_trimmed(&self.group);
        let note = non_empty_trimmed(&self.note);

        let existing_meta = self
            .editing_original_name
            .as_deref()
            .and_then(|orig| vault.find_by_name(orig));

        Ok(SshHost {
            name,
            host,
            port,
            username,
            auth,
            group,
            note,
            proxy_jump: existing_meta.and_then(|e| e.proxy_jump.clone()),
            local_forwards: existing_meta
                .map(|e| e.local_forwards.clone())
                .unwrap_or_default(),
            extra_keys: existing_meta
                .map(|e| e.extra_keys.clone())
                .unwrap_or_default(),
            forward_agent: existing_meta.map(|e| e.forward_agent).unwrap_or(false),
            monitor: self.monitor,
            created_at: existing_meta.map(|e| e.created_at).unwrap_or_else(Utc::now),
            last_used: existing_meta.and_then(|e| e.last_used),
        })
    }
}

fn non_empty_trimmed(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

fn default_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "root".to_string())
}

const PING_REFRESH_INTERVAL: Duration = Duration::from_secs(15);

struct AppState {
    vault: VaultData,
    input: String,
    selected_row: usize,
    slash_selected: usize,
    modal: Modal,
    status: Option<StatusMessage>,
    ping_states: HashMap<String, PingState>,
    ping_tx: Option<mpsc::Sender<(String, PingState)>>,
    ping_rx: Option<mpsc::Receiver<(String, PingState)>>,
    last_ping_all: Instant,
    metrics: HashMap<String, MetricsState>,
    metrics_rx: Option<mpsc::Receiver<(String, MetricsState)>>,
    monitor: Option<MonitorManager>,
}

impl AppState {
    fn new(vault: VaultData, initial_status: Option<(bool, String)>) -> Self {
        let status = initial_status.map(|(ok, text)| StatusMessage {
            level: if ok {
                StatusLevel::Success
            } else {
                StatusLevel::Error
            },
            text,
        });
        Self {
            vault,
            input: String::new(),
            selected_row: 0,
            slash_selected: 0,
            modal: Modal::None,
            status,
            ping_states: HashMap::new(),
            ping_tx: None,
            ping_rx: None,
            last_ping_all: Instant::now(),
            metrics: HashMap::new(),
            metrics_rx: None,
            monitor: None,
        }
    }

    /// Starts live CPU/RAM monitoring of the machines that have it enabled.
    fn enable_monitoring(&mut self, storage: Arc<Storage>) {
        if monitor::globally_disabled() || tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.metrics_rx = Some(rx);
        self.monitor = Some(MonitorManager::new(storage, tx));
        self.sync_monitoring();
    }

    /// Restarts / stops monitoring tasks after the machine list changed.
    fn sync_monitoring(&mut self) {
        if let Some(manager) = self.monitor.as_mut() {
            manager.sync(&self.vault.hosts);
            let monitored: Vec<String> = self
                .vault
                .hosts
                .iter()
                .filter(|h| h.monitor)
                .map(|h| h.name.clone())
                .collect();
            self.metrics.retain(|name, _| monitored.contains(name));
        }
    }

    fn poll_metrics(&mut self) {
        if let Some(ref rx) = self.metrics_rx {
            while let Ok((name, state)) = rx.try_recv() {
                let still_monitored = self
                    .monitor
                    .as_ref()
                    .map(|m| m.is_running(&name))
                    .unwrap_or(false);
                if still_monitored {
                    self.metrics.insert(name, state);
                }
            }
        }
    }

    /// Toggles CPU/RAM monitoring of a machine and saves the vault.
    fn toggle_monitor(&mut self, name: &str, storage: &Storage) -> Result<()> {
        let Some(idx) = self.vault.find_index_by_name(name) else {
            self.set_status(StatusLevel::Error, t!("tui.status.not_found"));
            return Ok(());
        };
        let enabled = !self.vault.hosts[idx].monitor;
        self.vault.hosts[idx].monitor = enabled;
        let host_name = self.vault.hosts[idx].name.clone();
        storage.save_vault(&self.vault)?;
        self.sync_monitoring();
        if enabled {
            let note = if monitor::globally_disabled() {
                format!(" {}", t!("tui.status.monitor_env_off"))
            } else {
                String::new()
            };
            self.set_status(
                StatusLevel::Success,
                format!("{}{note}", t!("tui.status.monitor_on", name = host_name)),
            );
        } else {
            self.set_status(
                StatusLevel::Info,
                t!("tui.status.monitor_off", name = host_name),
            );
        }
        Ok(())
    }

    fn metrics_for(&self, name: &str) -> Option<&MetricsState> {
        self.metrics.get(name)
    }

    fn enable_live_ping(&mut self) {
        let (tx, rx) = mpsc::channel();
        self.ping_tx = Some(tx);
        self.ping_rx = Some(rx);
        self.trigger_ping_all(true);
    }

    fn trigger_ping_all(&mut self, mark_checking: bool) {
        let Some(ref tx) = self.ping_tx else {
            return;
        };
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };

        self.last_ping_all = Instant::now();
        for h in &self.vault.hosts {
            if mark_checking || !self.ping_states.contains_key(&h.name) {
                self.ping_states.insert(h.name.clone(), PingState::Checking);
            }
            let tx = tx.clone();
            let name = h.name.clone();
            let host = h.host.clone();
            let port = h.port;
            handle.spawn(async move {
                let state = probe_host(&host, port).await;
                let _ = tx.send((name, state));
            });
        }
    }

    fn trigger_ping_one(&mut self, h: &SshHost) {
        let Some(ref tx) = self.ping_tx else {
            return;
        };
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };

        self.ping_states.insert(h.name.clone(), PingState::Checking);
        let tx = tx.clone();
        let name = h.name.clone();
        let host = h.host.clone();
        let port = h.port;
        handle.spawn(async move {
            let state = probe_host(&host, port).await;
            let _ = tx.send((name, state));
        });
    }

    fn poll_ping_results(&mut self) {
        if let Some(ref rx) = self.ping_rx {
            while let Ok((name, state)) = rx.try_recv() {
                self.ping_states.insert(name, state);
            }
        }
        if self.ping_tx.is_some()
            && !self.vault.hosts.is_empty()
            && self.last_ping_all.elapsed() >= PING_REFRESH_INTERVAL
        {
            self.trigger_ping_all(false);
        }
    }

    fn ping_state_for(&self, name: &str) -> PingState {
        self.ping_states
            .get(name)
            .copied()
            .unwrap_or(PingState::Checking)
    }

    fn is_slash_mode(&self) -> bool {
        self.input.starts_with('/')
    }

    /// If the user typed a slash command that accepts a host name followed by a space
    /// (e.g. `/files mo`, `/connect pc`, `/edit `, `/del `, `/test `), returns `Some((cmd, query))`.
    fn slash_host_arg_prefix(&self) -> Option<(&str, &str)> {
        if !self.is_slash_mode() {
            return None;
        }
        let idx = self.input.find(' ')?;
        let cmd = &self.input[..idx];
        let query = self.input[idx + 1..].trim_start();
        let takes_host = HOST_ARG_COMMANDS.contains(&cmd.to_lowercase().as_str());
        if takes_host {
            Some((cmd, query))
        } else {
            None
        }
    }

    /// Returns matching hosts for the autocomplete popup above the input bar.
    fn host_suggestions(&self) -> Vec<&SshHost> {
        let query = if let Some((_, q)) = self.slash_host_arg_prefix() {
            q
        } else if !self.is_slash_mode() && !self.input.is_empty() {
            self.input.as_str()
        } else {
            return Vec::new();
        };

        let q_lower = query.trim().to_lowercase();
        let mut matches: Vec<&SshHost> = self
            .vault
            .hosts
            .iter()
            .filter(|h| h.matches_query(query))
            .collect();

        // Hide popup if user already typed the exact unique host name
        if matches.len() == 1 && matches[0].name.to_lowercase() == q_lower {
            return Vec::new();
        }

        // Prioritize hosts whose name starts with the typed prefix
        if !q_lower.is_empty() {
            matches.sort_by_key(|h| {
                let name_l = h.name.to_lowercase();
                if name_l.starts_with(&q_lower) {
                    0
                } else if name_l.contains(&q_lower) {
                    1
                } else {
                    2
                }
            });
        }
        matches
    }

    fn filtered_hosts(&self) -> Vec<&SshHost> {
        if self.is_slash_mode() {
            self.vault.hosts.iter().collect()
        } else {
            self.vault
                .hosts
                .iter()
                .filter(|h| h.matches_query(&self.input))
                .collect()
        }
    }

    fn filtered_slash_commands(&self) -> Vec<SlashCommandDef> {
        if !self.is_slash_mode() {
            return Vec::new();
        }
        let token = self
            .input
            .split_whitespace()
            .next()
            .unwrap_or("/")
            .to_lowercase();
        SLASH_COMMANDS
            .iter()
            .copied()
            .filter(|c| c.cmd.starts_with(&token))
            .collect()
    }

    fn clamp_selection(&mut self) {
        let count = if self.slash_host_arg_prefix().is_some() {
            self.host_suggestions().len()
        } else {
            self.filtered_hosts().len()
        };
        if count == 0 {
            self.selected_row = 0;
        } else if self.selected_row >= count {
            self.selected_row = count - 1;
        }

        let slash_count = self.filtered_slash_commands().len();
        if slash_count == 0 {
            self.slash_selected = 0;
        } else if self.slash_selected >= slash_count {
            self.slash_selected = slash_count - 1;
        }
    }

    fn selected_host(&self) -> Option<SshHost> {
        let hosts = self.filtered_hosts();
        hosts.get(self.selected_row).map(|h| (*h).clone())
    }

    fn set_status(&mut self, level: StatusLevel, text: impl Into<String>) {
        self.status = Some(StatusMessage {
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

/// Runs the interactive 100% CLI interface until the user picks a host to connect,
/// asks to test a host, or exits.
pub fn run_tui(
    storage: &Arc<Storage>,
    initial_status: Option<(bool, String)>,
    whats_new: Option<Vec<VersionNotes>>,
) -> Result<TuiAction> {
    let vault = storage.load_vault()?;
    let mut app = AppState::new(vault, initial_status);
    app.enable_live_ping();
    app.enable_monitoring(Arc::clone(storage));
    if let Some(notes) = whats_new {
        app.modal = Modal::WhatsNew { notes, scroll: 0 };
    }
    let storage: &Storage = storage;

    let mut terminal = TuiGuard::enter()?;
    let _guard = TuiGuard;

    loop {
        app.poll_ping_results();
        app.poll_metrics();
        app.clamp_selection();
        terminal.draw(|frame| draw_ui(frame, &app))?;

        if !event::poll(Duration::from_millis(80))? {
            continue;
        }

        let Event::Key(key) = event::read()? else {
            continue;
        };

        // Important for Windows 10/11: ignore key release events to avoid duplicate input.
        if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
            continue;
        }

        if let Some(action) = handle_key(&mut app, key, storage)? {
            return Ok(action);
        }
    }
}

fn handle_key(app: &mut AppState, key: KeyEvent, storage: &Storage) -> Result<Option<TuiAction>> {
    match &mut app.modal {
        Modal::None => handle_main_key(app, key, storage),
        Modal::Form(_) => {
            handle_form_key(app, key, storage)?;
            Ok(None)
        }
        Modal::ConfirmDelete { .. } => {
            handle_delete_confirm_key(app, key, storage)?;
            Ok(None)
        }
        Modal::Help { scroll } => {
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => *scroll = scroll.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => *scroll = scroll.saturating_add(1),
                KeyCode::PageUp => *scroll = scroll.saturating_sub(10),
                KeyCode::PageDown | KeyCode::Char(' ') => *scroll = scroll.saturating_add(10),
                _ => {}
            }
            if matches!(
                key.code,
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::F(1)
            ) || (key.modifiers.contains(KeyModifiers::CONTROL)
                && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('h')))
            {
                app.modal = Modal::None;
            }
            Ok(None)
        }
        Modal::LangPicker { selected } => {
            if let Some(choice) = i18n::handle_lang_picker_key(selected, key.code, key.modifiers) {
                app.modal = Modal::None;
                if let Some(lang) = choice {
                    apply_language(app, storage, lang);
                }
            }
            Ok(None)
        }
        Modal::WhatsNew { scroll, .. } => {
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => *scroll = scroll.saturating_sub(1),
                KeyCode::Down | KeyCode::Char('j') => *scroll = scroll.saturating_add(1),
                KeyCode::PageUp => *scroll = scroll.saturating_sub(10),
                KeyCode::PageDown | KeyCode::Char(' ') => *scroll = scroll.saturating_add(10),
                KeyCode::Home => *scroll = 0,
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => app.modal = Modal::None,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    app.modal = Modal::None
                }
                _ => {}
            }
            Ok(None)
        }
    }
}

/// Saves and applies a new interface language (from `/lang`).
fn apply_language(app: &mut AppState, storage: &Storage, lang: Lang) {
    i18n::set_lang(lang);
    let mut settings = storage.load_settings();
    settings.language = Some(lang.code().to_string());
    match storage.save_settings(&settings) {
        Ok(()) => {
            let mut text = t!("lang.changed", lang = lang.native_name()).into_owned();
            if i18n::env_override().is_some() {
                text.push(' ');
                text.push_str(&t!("cli.lang.env_override"));
            }
            app.set_status(StatusLevel::Success, text);
        }
        Err(e) => app.set_status(StatusLevel::Error, format!("{e:#}")),
    }
}

fn handle_main_key(
    app: &mut AppState,
    key: KeyEvent,
    storage: &Storage,
) -> Result<Option<TuiAction>> {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);

    if ctrl && !alt {
        match key.code {
            KeyCode::Char('c') | KeyCode::Char('q') => return Ok(Some(TuiAction::Quit)),
            KeyCode::Char('n') => {
                app.modal = Modal::Form(Box::new(HostForm::new_empty()));
                return Ok(None);
            }
            KeyCode::Char('e') => {
                if let Some(host) = app.selected_host() {
                    app.modal = Modal::Form(Box::new(HostForm::from_host(&host)));
                } else {
                    app.set_status(StatusLevel::Info, t!("tui.status.none_selected"));
                }
                return Ok(None);
            }
            KeyCode::Char('d') => {
                if let Some(host) = app.selected_host() {
                    app.modal = Modal::ConfirmDelete {
                        host_name: host.name.clone(),
                        endpoint: host.endpoint_display(),
                    };
                } else {
                    app.set_status(StatusLevel::Info, t!("tui.status.none_selected"));
                }
                return Ok(None);
            }
            KeyCode::Char('t') => {
                if let Some(host) = app.selected_host() {
                    return Ok(Some(TuiAction::TestHost(host)));
                } else {
                    app.set_status(StatusLevel::Info, t!("tui.status.none_selected"));
                }
                return Ok(None);
            }
            KeyCode::Char('f') => {
                if let Some(host) = app.selected_host() {
                    return Ok(Some(TuiAction::BrowseFiles(host)));
                } else {
                    app.set_status(StatusLevel::Info, t!("tui.status.none_selected"));
                }
                return Ok(None);
            }
            KeyCode::Char('h') => {
                app.modal = Modal::Help { scroll: 0 };
                return Ok(None);
            }
            KeyCode::Char('p') => {
                if let Some(host) = app.selected_host() {
                    app.toggle_monitor(&host.name, storage)?;
                } else {
                    app.set_status(StatusLevel::Info, t!("tui.status.none_selected"));
                }
                return Ok(None);
            }
            KeyCode::Char('r') => {
                app.trigger_ping_all(true);
                app.set_status(StatusLevel::Info, t!("tui.status.refreshing"));
                return Ok(None);
            }
            KeyCode::Char('u') => {
                app.input.clear();
                return Ok(None);
            }
            _ => {}
        }
    }

    match key.code {
        KeyCode::F(1) => {
            app.modal = Modal::Help { scroll: 0 };
        }
        KeyCode::F(2) => {
            app.modal = Modal::Form(Box::new(HostForm::new_empty()));
        }
        KeyCode::F(5) => {
            app.trigger_ping_all(true);
            app.set_status(StatusLevel::Info, t!("tui.status.refreshing"));
        }
        KeyCode::Esc => {
            if !app.input.is_empty() {
                app.input.clear();
            } else {
                return Ok(Some(TuiAction::Quit));
            }
        }
        KeyCode::Up => {
            if app.is_slash_mode() && !app.input.contains(' ') {
                let count = app.filtered_slash_commands().len();
                if count > 0 {
                    app.slash_selected = if app.slash_selected == 0 {
                        count - 1
                    } else {
                        app.slash_selected - 1
                    };
                }
            } else {
                let count = if app.slash_host_arg_prefix().is_some() {
                    app.host_suggestions().len()
                } else {
                    app.filtered_hosts().len()
                };
                if count > 0 {
                    app.selected_row = if app.selected_row == 0 {
                        count - 1
                    } else {
                        app.selected_row - 1
                    };
                }
            }
        }
        KeyCode::Down => {
            if app.is_slash_mode() && !app.input.contains(' ') {
                let count = app.filtered_slash_commands().len();
                if count > 0 {
                    app.slash_selected = (app.slash_selected + 1) % count;
                }
            } else {
                let count = if app.slash_host_arg_prefix().is_some() {
                    app.host_suggestions().len()
                } else {
                    app.filtered_hosts().len()
                };
                if count > 0 {
                    app.selected_row = (app.selected_row + 1) % count;
                }
            }
        }
        KeyCode::Tab => {
            if let Some((cmd_prefix, _)) = app.slash_host_arg_prefix() {
                let cmd_owned = cmd_prefix.to_string();
                let suggestions = app.host_suggestions();
                if let Some(host) = suggestions.get(app.selected_row) {
                    app.input = format!("{cmd_owned} {}", host.name);
                }
            } else if app.is_slash_mode() {
                let cmds = app.filtered_slash_commands();
                if let Some(cmd) = cmds.get(app.slash_selected) {
                    app.input = if cmd.arg_key.is_some() {
                        format!("{} ", cmd.cmd)
                    } else {
                        cmd.cmd.to_string()
                    };
                    app.selected_row = 0;
                }
            } else if !app.input.is_empty() {
                let suggestions = app.host_suggestions();
                if let Some(host) = suggestions.get(app.selected_row) {
                    app.input = host.name.clone();
                    app.selected_row = 0;
                }
            }
        }
        KeyCode::Backspace => {
            app.input.pop();
            app.slash_selected = 0;
            app.selected_row = 0;
        }
        KeyCode::Enter => {
            if app.is_slash_mode() {
                return execute_slash_command(app, storage);
            } else if let Some(host) = app.selected_host() {
                return Ok(Some(TuiAction::Connect(host)));
            } else {
                app.set_status(StatusLevel::Info, t!("tui.status.no_machine"));
            }
        }
        KeyCode::Char(c) => {
            app.input.push(c);
            app.slash_selected = 0;
            if !app.is_slash_mode() || app.slash_host_arg_prefix().is_some() {
                app.selected_row = 0;
            }
        }
        _ => {}
    }

    Ok(None)
}

fn execute_slash_command(app: &mut AppState, storage: &Storage) -> Result<Option<TuiAction>> {
    let raw = app.input.trim().to_string();
    let mut parts = raw.splitn(2, char::is_whitespace);
    let typed_cmd = parts.next().unwrap_or("").to_lowercase();
    let arg = parts.next().map(|s| s.trim()).filter(|s| !s.is_empty());

    // Resolve partial slash command via highlighted suggestion if no exact match
    let resolved = match typed_cmd.as_str() {
        "/new" | "/add" | "/n" => "/new",
        "/files" | "/sftp" | "/f" => "/files",
        "/edit" | "/e" => "/edit",
        "/del" | "/delete" | "/rm" | "/remove" => "/del",
        "/connect" | "/c" | "/open" => "/connect",
        "/test" | "/ping" => "/test",
        "/monitor" | "/mon" | "/m" => "/monitor",
        "/refresh" | "/r" => "/refresh",
        "/export" | "/backup" => "/export",
        "/import" | "/restore" => "/import",
        "/import-ssh" | "/ssh-config" => "/import-ssh",
        "/lang" | "/language" | "/langue" => "/lang",
        "/changelog" | "/whatsnew" | "/news" => "/changelog",
        "/clear" => "/clear",
        "/help" | "/?" => "/help",
        "/quit" | "/exit" | "/q" => "/quit",
        _ => {
            let matches = app.filtered_slash_commands();
            if let Some(m) = matches.get(app.slash_selected) {
                m.cmd
            } else {
                app.set_status(
                    StatusLevel::Error,
                    t!("tui.status.unknown_command", cmd = typed_cmd),
                );
                return Ok(None);
            }
        }
    };

    app.input.clear();
    app.slash_selected = 0;

    match resolved {
        "/new" => {
            let mut form = HostForm::new_empty();
            if let Some(a) = arg {
                // Allow quick `/new 192.168.1.192` or `/new my-pc`
                if a.contains('.') || a.contains(':') {
                    form.host = a.to_string();
                } else {
                    form.name = a.to_string();
                }
            }
            app.modal = Modal::Form(Box::new(form));
        }
        "/files" => {
            let target = match arg {
                Some(name) => app.vault.find_by_name(name).cloned(),
                None => app.selected_host(),
            };
            if let Some(host) = target {
                return Ok(Some(TuiAction::BrowseFiles(host)));
            } else {
                app.set_status(StatusLevel::Error, t!("tui.status.not_found"));
            }
        }
        "/edit" => {
            let target = match arg {
                Some(name) => app.vault.find_by_name(name).cloned(),
                None => app.selected_host(),
            };
            if let Some(host) = target {
                app.modal = Modal::Form(Box::new(HostForm::from_host(&host)));
            } else {
                app.set_status(StatusLevel::Error, t!("tui.status.not_found"));
            }
        }
        "/del" => {
            let target = match arg {
                Some(name) => app.vault.find_by_name(name).cloned(),
                None => app.selected_host(),
            };
            if let Some(host) = target {
                app.modal = Modal::ConfirmDelete {
                    host_name: host.name.clone(),
                    endpoint: host.endpoint_display(),
                };
            } else {
                app.set_status(StatusLevel::Error, t!("tui.status.not_found"));
            }
        }
        "/connect" => {
            let target = match arg {
                Some(name) => app.vault.find_by_name(name).cloned(),
                None => app.selected_host(),
            };
            if let Some(host) = target {
                return Ok(Some(TuiAction::Connect(host)));
            } else {
                app.set_status(StatusLevel::Error, t!("tui.status.not_found"));
            }
        }
        "/test" => {
            let target = match arg {
                Some(name) => app.vault.find_by_name(name).cloned(),
                None => app.selected_host(),
            };
            if let Some(host) = target {
                return Ok(Some(TuiAction::TestHost(host)));
            } else {
                app.set_status(StatusLevel::Error, t!("tui.status.not_found"));
            }
        }
        "/monitor" => {
            let target = match arg {
                Some(name) => app.vault.find_by_name(name).cloned(),
                None => app.selected_host(),
            };
            if let Some(host) = target {
                app.toggle_monitor(&host.name, storage)?;
            } else {
                app.set_status(StatusLevel::Error, t!("tui.status.not_found"));
            }
        }
        "/refresh" => {
            app.trigger_ping_all(true);
            app.set_status(StatusLevel::Info, t!("tui.status.refreshing"));
        }
        "/lang" => match arg {
            Some(code) => match Lang::from_code(code) {
                Some(lang) => apply_language(app, storage, lang),
                None => app.set_status(
                    StatusLevel::Error,
                    t!(
                        "cli.lang.unknown",
                        code = code,
                        list = Lang::ALL
                            .iter()
                            .map(|l| l.code())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ),
            },
            None => {
                app.modal = Modal::LangPicker {
                    selected: i18n::current_lang().index(),
                };
            }
        },
        "/changelog" => {
            app.modal = Modal::WhatsNew {
                notes: updater::recent_notes(5),
                scroll: 0,
            };
        }
        "/export" => {
            let dest = match arg {
                Some(p) => Some(resolve_local_path(p)),
                None => match picker::pick_save_file(
                    &t!("common.export_title"),
                    "ssha-config.json",
                    Some((&t!("common.json_filter"), "*.json")),
                ) {
                    PickerResult::Selected(p) => Some(p),
                    PickerResult::Cancelled => {
                        app.set_status(StatusLevel::Info, t!("common.export_cancelled"));
                        None
                    }
                    PickerResult::Unavailable => {
                        Some(default_download_dir().join("ssha-config.json"))
                    }
                },
            };
            if let Some(path) = dest {
                match export_vault_to_file(&app.vault, &path) {
                    Ok(count) => app.set_status(
                        StatusLevel::Success,
                        tn(
                            "common.exported",
                            count as u64,
                            &[("path", &path.display().to_string())],
                        ),
                    ),
                    Err(e) => app.set_status(
                        StatusLevel::Error,
                        t!("tui.status.export_failed", error = format!("{e:#}")),
                    ),
                }
            }
        }
        "/import" => {
            let src = match arg {
                Some(p) => Some(resolve_local_path(p)),
                None => match picker::pick_file(
                    &t!("common.import_title"),
                    Some((&t!("common.json_filter"), "*.json")),
                ) {
                    PickerResult::Selected(p) => Some(p),
                    PickerResult::Cancelled => {
                        app.set_status(StatusLevel::Info, t!("common.import_cancelled"));
                        None
                    }
                    PickerResult::Unavailable => {
                        app.set_status(StatusLevel::Info, t!("tui.status.import_hint"));
                        None
                    }
                },
            };
            if let Some(path) = src {
                match import_vault_from_file(storage, &path, true) {
                    Ok(report) => {
                        if let Ok(reloaded) = storage.load_vault() {
                            app.vault = reloaded;
                            app.trigger_ping_all(true);
                            app.sync_monitoring();
                        }
                        app.set_status(
                            StatusLevel::Success,
                            t!(
                                "tui.status.import_done",
                                report = crate::cli::import_report_text(
                                    report.added,
                                    report.updated,
                                    report.skipped
                                )
                            ),
                        );
                    }
                    Err(e) => app.set_status(
                        StatusLevel::Error,
                        t!("tui.status.import_failed", error = format!("{e:#}")),
                    ),
                }
            }
        }
        "/import-ssh" => {
            let target = match arg {
                Some(p) => Some(resolve_local_path(p)),
                None => ssh_config::default_ssh_config_path(),
            };
            if let Some(path) = target {
                match ssh_config::import_from_ssh_config(storage, &path, false) {
                    Ok(report) => {
                        if let Ok(reloaded) = storage.load_vault() {
                            app.vault = reloaded;
                            app.trigger_ping_all(true);
                            app.sync_monitoring();
                        }
                        app.set_status(
                            StatusLevel::Success,
                            t!(
                                "tui.status.import_ssh_done",
                                report = crate::cli::import_report_text(
                                    report.added,
                                    report.updated,
                                    report.skipped
                                )
                            ),
                        );
                    }
                    Err(e) => app.set_status(StatusLevel::Error, format!("{e:#}")),
                }
            } else {
                app.set_status(StatusLevel::Error, t!("common.err.no_ssh_config"));
            }
        }
        "/clear" => {
            app.status = None;
        }
        "/help" => {
            app.modal = Modal::Help { scroll: 0 };
        }
        "/quit" => {
            return Ok(Some(TuiAction::Quit));
        }
        _ => {}
    }

    Ok(None)
}

fn handle_form_key(app: &mut AppState, key: KeyEvent, storage: &Storage) -> Result<()> {
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);

    if key.code == KeyCode::Esc {
        app.modal = Modal::None;
        return Ok(());
    }

    if ctrl && !alt && key.code == KeyCode::Char('s') {
        try_submit_form(app, storage)?;
        return Ok(());
    }

    if ctrl && !alt && key.code == KeyCode::Char('r') {
        if let Modal::Form(ref mut form) = app.modal {
            form.show_secret = !form.show_secret;
        }
        return Ok(());
    }

    let mut should_submit = false;
    if let Modal::Form(ref mut form) = app.modal {
        form.error = None;
        let field = form.current_field();
        let last_idx = form.fields().len() - 1;

        match key.code {
            KeyCode::Tab | KeyCode::Down => form.next_field(),
            KeyCode::BackTab | KeyCode::Up => form.prev_field(),
            KeyCode::Enter => {
                if form.focused_index == last_idx {
                    should_submit = true;
                } else {
                    form.next_field();
                }
            }
            KeyCode::Left | KeyCode::Right if field == FormField::AuthKind => {
                form.toggle_auth_kind();
            }
            KeyCode::Char(' ') if field == FormField::AuthKind => {
                form.toggle_auth_kind();
            }
            KeyCode::Left | KeyCode::Right | KeyCode::Char(' ') if field == FormField::Monitor => {
                form.monitor = !form.monitor;
            }
            KeyCode::Backspace => {
                if let Some(buf) = form.active_buffer_mut() {
                    buf.pop();
                }
            }
            KeyCode::Char(c) if !(ctrl && !alt) => {
                if field == FormField::Port && !c.is_ascii_digit() {
                    return Ok(());
                }
                if let Some(buf) = form.active_buffer_mut() {
                    buf.push(c);
                }
            }
            _ => {}
        }
    }

    if should_submit {
        try_submit_form(app, storage)?;
    }
    Ok(())
}

fn try_submit_form(app: &mut AppState, storage: &Storage) -> Result<()> {
    let built = match &app.modal {
        Modal::Form(form) => (
            form.editing_original_name.clone(),
            form.build_host(&app.vault),
        ),
        _ => return Ok(()),
    };

    match built {
        (original_name, Ok(new_host)) => {
            let saved_name = new_host.name.clone();
            let host_to_ping = new_host.clone();
            let was_edit = original_name.is_some();

            if let Some(orig) = original_name {
                if let Some(idx) = app.vault.find_index_by_name(&orig) {
                    app.vault.hosts[idx] = new_host;
                    app.selected_row = idx;
                } else {
                    app.vault.hosts.push(new_host);
                    app.selected_row = app.vault.hosts.len() - 1;
                }
            } else {
                app.vault.hosts.push(new_host);
                app.selected_row = app.vault.hosts.len() - 1;
            }

            storage.save_vault(&app.vault)?;
            app.trigger_ping_one(&host_to_ping);
            app.sync_monitoring();
            app.modal = Modal::None;
            app.set_status(
                StatusLevel::Success,
                if was_edit {
                    t!("tui.status.updated", name = saved_name)
                } else {
                    t!("tui.status.added", name = saved_name)
                },
            );
        }
        (_, Err(err_msg)) => {
            if let Modal::Form(ref mut form) = app.modal {
                form.error = Some(err_msg);
            }
        }
    }
    Ok(())
}

fn handle_delete_confirm_key(app: &mut AppState, key: KeyEvent, storage: &Storage) -> Result<()> {
    match key.code {
        KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
            app.modal = Modal::None;
        }
        KeyCode::Char(c) if !i18n::is_yes(&c.to_string()) => {}
        KeyCode::Enter | KeyCode::Char(_) => {
            let host_name = match &app.modal {
                Modal::ConfirmDelete { host_name, .. } => host_name.clone(),
                _ => return Ok(()),
            };
            app.vault.remove_by_name(&host_name);
            storage.save_vault(&app.vault)?;
            app.sync_monitoring();
            app.modal = Modal::None;
            app.set_status(StatusLevel::Success, t!("cli.rm.done", name = host_name));
        }
        _ => {}
    }
    Ok(())
}

fn draw_ui(frame: &mut Frame, app: &AppState) {
    let area = frame.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(8),    // Host list
            Constraint::Length(2), // Selected host details / status
            Constraint::Length(3), // Command / Search bar
            Constraint::Length(1), // Footer hints
        ])
        .split(area);

    draw_header(frame, chunks[0], app);
    draw_host_table(frame, chunks[1], app);
    draw_status_strip(frame, chunks[2], app);
    draw_input_bar(frame, chunks[3], app);
    draw_footer(frame, chunks[4]);

    // Autocomplete popup right above the input bar (slash commands OR machine names)
    if matches!(app.modal, Modal::None) {
        if app.is_slash_mode() && !app.input.contains(' ') {
            draw_slash_popup(frame, chunks[3], app);
        } else if !app.host_suggestions().is_empty() {
            draw_host_autocomplete_popup(frame, chunks[3], app);
        }
    }

    match &app.modal {
        Modal::None => {}
        Modal::Form(form) => draw_form_modal(frame, area, form),
        Modal::ConfirmDelete {
            host_name,
            endpoint,
        } => draw_delete_modal(frame, area, host_name, endpoint),
        Modal::Help { scroll } => draw_help_modal(frame, area, *scroll),
        Modal::LangPicker { selected } => {
            i18n::draw_lang_picker(frame, area, *selected, i18n::detect_system_lang())
        }
        Modal::WhatsNew { notes, scroll } => draw_whats_new_modal(frame, area, notes, *scroll),
    }
}

fn draw_header(frame: &mut Frame, area: Rect, app: &AppState) {
    let count = app.vault.hosts.len();
    let label = tn("tui.header.connections", count as u64, &[]);
    let monitored = app.vault.hosts.iter().filter(|h| h.monitor).count();

    let title = Line::from(vec![
        Span::styled(
            " ssha ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("  {}  ", t!("tui.header.subtitle"))),
        Span::styled("│", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("  {label}  "), Style::default().fg(Color::White)),
        Span::styled("│", Style::default().fg(Color::DarkGray)),
        Span::styled("  AES-256-GCM auto  ", Style::default().fg(Color::Green)),
        Span::styled("│", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("  📊 {}", tn("tui.header.monitored", monitored as u64, &[])),
            Style::default().fg(if monitored > 0 {
                Color::Magenta
            } else {
                Color::DarkGray
            }),
        ),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let p = Paragraph::new(title).block(block);
    frame.render_widget(p, area);
}

fn draw_host_table(frame: &mut Frame, area: Rect, app: &AppState) {
    let hosts = app.filtered_hosts();

    let block = Block::default()
        .title(Span::styled(
            format!(" {} ", t!("tui.table.title")),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    if app.vault.hosts.is_empty() {
        let empty = Paragraph::new(vec![
            Line::raw(""),
            Line::from(Span::styled(
                t!("tui.table.empty"),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::raw(""),
            Line::from(Span::raw(t!("tui.table.empty_hint"))),
            Line::from(Span::styled(
                t!("tui.table.empty_example"),
                Style::default().fg(Color::DarkGray),
            )),
        ])
        .alignment(Alignment::Center)
        .block(block);
        frame.render_widget(empty, area);
        return;
    }

    if hosts.is_empty() {
        let no_match = Paragraph::new(vec![
            Line::raw(""),
            Line::from(Span::styled(
                t!("tui.table.no_match", query = app.input),
                Style::default().fg(Color::Yellow),
            )),
            Line::from(Span::styled(
                t!("tui.table.no_match_hint"),
                Style::default().fg(Color::DarkGray),
            )),
        ])
        .alignment(Alignment::Center)
        .block(block);
        frame.render_widget(no_match, area);
        return;
    }

    // Narrow terminals (e.g. 80 columns): hide the Group and Last used columns
    // so that the live CPU/RAM column stays readable.
    let compact = area.width < 118;

    let mut header_cells = vec![
        Cell::from(format!("  {}", t!("cli.list.col_name"))),
        Cell::from(t!("cli.list.col_address")),
        Cell::from(t!("tui.table.col_resources")),
        Cell::from(t!("cli.list.col_auth")),
    ];
    if !compact {
        header_cells.push(Cell::from(t!("cli.list.col_group")));
        header_cells.push(Cell::from(t!("cli.list.col_last_used")));
    }
    header_cells.push(Cell::from(
        Line::from(t!("cli.list.col_state")).alignment(Alignment::Right),
    ));
    let header = Row::new(header_cells)
    .style(
        Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .bottom_margin(1);

    let rows: Vec<Row> = hosts
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let selected = i == app.selected_row;
            let prefix = if selected { "▸ " } else { "  " };
            let auth_style = if h.auth.is_password() {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Green)
            };
            let auth_cell = Cell::from(format!("● {}", h.auth.label())).style(auth_style);

            let ping = app.ping_state_for(&h.name);
            let (status_label, status_style, dot_style) = match ping {
                PingState::Up(_) => (
                    "UP",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                    Style::default().fg(Color::Green),
                ),
                PingState::Down => (
                    "DOWN",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    Style::default().fg(Color::Red),
                ),
                PingState::Checking => (
                    "...",
                    Style::default().fg(Color::DarkGray),
                    Style::default().fg(Color::Yellow),
                ),
            };

            let addr_cell = Cell::from(Line::from(vec![
                Span::styled(h.endpoint_display(), Style::default().fg(Color::Gray)),
                Span::raw("  "),
                Span::styled(status_label, status_style),
            ]));

            let dot_cell =
                Cell::from(Line::from(Span::styled("● ", dot_style)).alignment(Alignment::Right));

            let resources_cell = Cell::from(resources_line(app, h, ping));

            let mut cells = vec![
                Cell::from(format!("{prefix}{}", h.name)).style(if selected {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                }),
                addr_cell,
                resources_cell,
                auth_cell,
            ];
            if !compact {
                cells.push(
                    Cell::from(h.group.as_deref().unwrap_or("—").to_string())
                        .style(Style::default().fg(Color::Magenta)),
                );
                cells.push(
                    Cell::from(format_relative_time(h.last_used))
                        .style(Style::default().fg(Color::DarkGray)),
                );
            }
            cells.push(dot_cell);
            Row::new(cells)
        })
        .collect();

    let widths: Vec<Constraint> = if compact {
        vec![
            Constraint::Percentage(22),
            Constraint::Min(18),
            Constraint::Length(33),
            Constraint::Length(7),
            Constraint::Length(5),
        ]
    } else {
        vec![
            Constraint::Percentage(16),
            Constraint::Percentage(26),
            Constraint::Length(33),
            Constraint::Length(7),
            Constraint::Percentage(11),
            Constraint::Percentage(16),
            Constraint::Length(5),
        ]
    };

    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .row_highlight_style(
            Style::default()
                .bg(Color::Rgb(30, 42, 58))
                .add_modifier(Modifier::BOLD),
        );

    let mut state = TableState::default();
    state.select(Some(app.selected_row));
    frame.render_stateful_widget(table, area, &mut state);
}

fn load_color(pct: f32) -> Color {
    if pct < 60.0 {
        Color::Green
    } else if pct < 85.0 {
        Color::Yellow
    } else {
        Color::Red
    }
}

/// `CPU 34% · RAM 71% (2.8/4 GB)` — or a short state when no metrics are available.
fn resources_line<'a>(app: &AppState, h: &SshHost, ping: PingState) -> Line<'a> {
    let dim = Style::default().fg(Color::DarkGray);
    if !h.monitor || app.monitor.is_none() {
        return Line::from(Span::styled("—", dim));
    }
    if matches!(ping, PingState::Down) {
        return Line::from(Span::styled("—", dim));
    }
    match app.metrics_for(&h.name) {
        None | Some(MetricsState::Connecting) => {
            Line::from(Span::styled(format!("… {}", t!("monitor.connecting")), dim))
        }
        Some(MetricsState::Unsupported) => Line::from(Span::styled(t!("monitor.na"), dim)),
        Some(MetricsState::KeyChanged) => Line::from(Span::styled(
            format!("⚠ {}", t!("monitor.key_changed")),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Some(MetricsState::Failed(_)) => Line::from(Span::styled(
            format!("✗ {}", t!("monitor.failed")),
            Style::default().fg(Color::Red),
        )),
        Some(MetricsState::Ok(m)) => {
            let cpu = match m.cpu_pct {
                Some(pct) => Span::styled(
                    format!("{:>3.0}%", pct),
                    Style::default()
                        .fg(load_color(pct))
                        .add_modifier(Modifier::BOLD),
                ),
                None => Span::styled("  …%", dim),
            };
            let mem_pct = m.mem_pct();
            Line::from(vec![
                Span::styled("CPU ", dim),
                cpu,
                Span::styled(" · RAM ", dim),
                Span::styled(
                    format!("{:>3.0}%", mem_pct),
                    Style::default()
                        .fg(load_color(mem_pct))
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(
                        " ({}/{} {})",
                        monitor::format_gib(m.mem_used),
                        monitor::format_gib(m.mem_total),
                        t!("monitor.gb")
                    ),
                    Style::default().fg(Color::Gray),
                ),
            ])
        }
    }
}

fn draw_status_strip(frame: &mut Frame, area: Rect, app: &AppState) {
    let mut lines = Vec::new();

    if let Some(ref st) = app.status {
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
    } else if let Some(host) = app.selected_host() {
        let endpoint = host.endpoint_display();
        let ping_span = match app.ping_state_for(&host.name) {
            PingState::Up(ms) => Span::styled(
                format!("  │  ● UP ({ms} ms)"),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            PingState::Down => Span::styled(
                "  │  ● DOWN",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            PingState::Checking => Span::styled("  │  ● ...", Style::default().fg(Color::Yellow)),
        };
        let note_str = host
            .note
            .as_deref()
            .map(|n| format!("  │  {}: {n}", t!("tui.status.note")))
            .unwrap_or_default();
        let monitor_span = match app.metrics_for(&host.name) {
            Some(MetricsState::Failed(err)) => Span::styled(
                format!("  │  CPU/RAM ✗ {err}"),
                Style::default().fg(Color::Red),
            ),
            Some(MetricsState::KeyChanged) => Span::styled(
                format!("  │  ⚠ {}", t!("ssh.key.changed_short")),
                Style::default().fg(Color::Red),
            ),
            _ if !host.monitor => Span::styled(
                format!("  │  {}", t!("tui.status.monitor_hint")),
                Style::default().fg(Color::DarkGray),
            ),
            _ => Span::raw(""),
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {} : ", t!("tui.status.selection")),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(host.name, Style::default().fg(Color::Cyan)),
            Span::raw(format!(" ({endpoint})")),
            ping_span,
            monitor_span,
            Span::styled(note_str, Style::default().fg(Color::DarkGray)),
        ]));
    }

    let p = Paragraph::new(lines);
    frame.render_widget(p, area);
}

fn draw_input_bar(frame: &mut Frame, area: Rect, app: &AppState) {
    let is_cmd = app.is_slash_mode();
    let border_color = if is_cmd { Color::Yellow } else { Color::Cyan };

    let title = if is_cmd {
        format!(" {} ", t!("tui.input.title_command"))
    } else {
        format!(" {} ", t!("tui.input.title"))
    };

    let content = if app.input.is_empty() {
        Line::from(vec![
            Span::styled(
                "> ",
                Style::default()
                    .fg(border_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                t!("tui.input.placeholder"),
                Style::default().fg(Color::DarkGray),
            ),
        ])
    } else {
        let mut spans = vec![
            Span::styled(
                "> ",
                Style::default()
                    .fg(border_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                app.input.as_str(),
                Style::default()
                    .fg(if is_cmd { Color::Yellow } else { Color::White })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("▏", Style::default().fg(border_color)),
        ];

        // Inline ghost-text suffix when the highlighted machine name starts with the typed prefix
        let suggestions = app.host_suggestions();
        if let Some(best) = suggestions.get(app.selected_row) {
            let typed_part = app
                .slash_host_arg_prefix()
                .map(|(_, q)| q)
                .unwrap_or(app.input.as_str());
            let typed_chars = typed_part.chars().count();
            if typed_chars > 0
                && best
                    .name
                    .to_lowercase()
                    .starts_with(&typed_part.to_lowercase())
            {
                let suffix: String = best.name.chars().skip(typed_chars).collect();
                if !suffix.is_empty() {
                    spans.push(Span::styled(suffix, Style::default().fg(Color::DarkGray)));
                }
            }
        }

        Line::from(spans)
    };

    let block = Block::default()
        .title(Span::styled(title, Style::default().fg(border_color)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    frame.render_widget(Paragraph::new(content).block(block), area);
}

fn draw_host_autocomplete_popup(frame: &mut Frame, input_area: Rect, app: &AppState) {
    let suggestions = app.host_suggestions();
    if suggestions.is_empty() {
        return;
    }

    let visible_count = suggestions.len().min(6);
    let height = (visible_count as u16 + 2).min(input_area.y);
    if height < 3 {
        return;
    }
    let width = 66u16.min(input_area.width);
    let popup_area = Rect {
        x: input_area.x,
        y: input_area.y.saturating_sub(height),
        width,
        height,
    };

    frame.render_widget(Clear, popup_area);

    let items: Vec<ListItem> = suggestions
        .iter()
        .take(visible_count)
        .map(|h| {
            let (dot, dot_style) = match app.ping_state_for(&h.name) {
                PingState::Up(_) => ("● UP", Style::default().fg(Color::Green)),
                PingState::Down => ("● DOWN", Style::default().fg(Color::Red)),
                PingState::Checking => ("● ...", Style::default().fg(Color::Yellow)),
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!(" {:<18}", h.name),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{:<28} ", h.endpoint_display()),
                    Style::default().fg(Color::Gray),
                ),
                Span::styled(dot, dot_style),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(Span::styled(
                    format!(" {} ", t!("tui.popup.machines")),
                    Style::default().fg(Color::Cyan),
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(30, 46, 64))
                .add_modifier(Modifier::BOLD),
        );

    let mut state = ListState::default();
    state.select(Some(app.selected_row.min(visible_count.saturating_sub(1))));
    frame.render_stateful_widget(list, popup_area, &mut state);
}

fn draw_slash_popup(frame: &mut Frame, input_area: Rect, app: &AppState) {
    let cmds = app.filtered_slash_commands();
    if cmds.is_empty() {
        return;
    }

    let height = (cmds.len() as u16 + 2).min(input_area.y);
    if height < 3 {
        return;
    }
    let width = 72u16.min(input_area.width);
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
                    format!(" {:<20}", c.usage()),
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
                    format!(" {} ", t!("tui.popup.commands")),
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

    let mut state = ListState::default();
    state.select(Some(app.slash_selected));
    frame.render_stateful_widget(list, popup_area, &mut state);
}

fn draw_footer(frame: &mut Frame, area: Rect) {
    let key = |k: &'static str, c: Color| {
        Span::styled(k, Style::default().fg(c).add_modifier(Modifier::BOLD))
    };
    let label = |l: std::borrow::Cow<'static, str>| {
        Span::styled(format!(" {l}  "), Style::default().fg(Color::DarkGray))
    };
    let hints = Line::from(vec![
        Span::raw(" "),
        key("Enter", Color::Cyan),
        label(t!("tui.footer.ssh")),
        key("Ctrl+F", Color::Green),
        label(t!("tui.footer.files")),
        key("/new", Color::Cyan),
        label(t!("tui.footer.add")),
        key("Ctrl+E", Color::Cyan),
        label(t!("tui.footer.edit")),
        key("Ctrl+D", Color::Cyan),
        label(t!("tui.footer.delete")),
        key("Ctrl+P", Color::Magenta),
        label(t!("tui.footer.monitor")),
        key("/help", Color::Cyan),
        label(t!("tui.footer.help")),
        key("Esc", Color::Cyan),
        Span::styled(
            format!(" {}", t!("tui.footer.quit")),
            Style::default().fg(Color::DarkGray),
        ),
    ]);

    frame.render_widget(Paragraph::new(hints), area);
}

fn draw_form_modal(frame: &mut Frame, area: Rect, form: &HostForm) {
    let popup = centered_rect(86, 23, area);
    frame.render_widget(Clear, popup);

    let title = if let Some(ref orig) = form.editing_original_name {
        format!(" {} ", t!("tui.form.title_edit", name = orig))
    } else {
        format!(" {} ", t!("tui.form.title_new"))
    };

    let block = Block::default()
        .title(Span::styled(
            title,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let fields = form.fields();
    let current = form.current_field();

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::raw(""));

    for f in fields {
        let active = f == current;
        let marker = if active { "▸ " } else { "  " };
        let label_style = if active {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };

        let toggle_style = |on: bool, color: Color| {
            if on {
                Style::default()
                    .fg(Color::Black)
                    .bg(color)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::DarkGray)
            }
        };
        let toggle_hint = Span::styled(
            if active {
                format!("  ({})", t!("tui.form.toggle_hint"))
            } else {
                String::new()
            },
            Style::default().fg(Color::DarkGray),
        );

        let (label_key, value_spans): (&str, Vec<Span>) = match f {
            FormField::Name => (
                "tui.form.name",
                render_text_value(&form.name, tr("tui.form.ph_name"), active),
            ),
            FormField::Host => (
                "tui.form.host",
                render_text_value(&form.host, "192.168.1.192".to_string(), active),
            ),
            FormField::Port => (
                "tui.form.port",
                render_text_value(&form.port, "22".to_string(), active),
            ),
            FormField::Username => (
                "tui.form.user",
                render_text_value(&form.username, tr("tui.form.ph_user"), active),
            ),
            FormField::AuthKind => (
                "tui.form.auth",
                vec![
                    Span::styled(
                        format!(" {} ", t!("tui.form.auth_password")),
                        toggle_style(form.auth_kind == FormAuthKind::Password, Color::Yellow),
                    ),
                    Span::raw("  "),
                    Span::styled(
                        format!(" {} ", t!("tui.form.auth_key")),
                        toggle_style(form.auth_kind == FormAuthKind::Key, Color::Green),
                    ),
                    toggle_hint,
                ],
            ),
            FormField::Password => (
                "tui.form.password",
                render_secret_value(
                    &form.password,
                    form.show_secret,
                    tr("tui.form.ph_password"),
                    active,
                ),
            ),
            FormField::KeyPath => (
                "tui.form.key_path",
                render_text_value(&form.key_path, "~/.ssh/id_ed25519".to_string(), active),
            ),
            FormField::KeyPassphrase => (
                "tui.form.passphrase",
                render_secret_value(
                    &form.key_passphrase,
                    form.show_secret,
                    tr("tui.form.ph_passphrase"),
                    active,
                ),
            ),
            FormField::Monitor => (
                "tui.form.monitor",
                vec![
                    Span::styled(
                        if form.monitor { "[x] " } else { "[ ] " },
                        if form.monitor {
                            Style::default()
                                .fg(Color::Magenta)
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(Color::DarkGray)
                        },
                    ),
                    Span::styled(
                        tr("tui.form.monitor_desc"),
                        Style::default().fg(if active { Color::White } else { Color::Gray }),
                    ),
                    toggle_hint,
                ],
            ),
            FormField::Group => (
                "tui.form.group",
                render_text_value(&form.group, tr("tui.form.ph_group"), active),
            ),
            FormField::Note => (
                "tui.form.note",
                render_text_value(&form.note, tr("tui.form.ph_note"), active),
            ),
        };
        let label = tr(label_key);
        let pad = 19usize.saturating_sub(label.chars().count());
        let label = format!("{label}{}", " ".repeat(pad));

        let mut spans = vec![Span::styled(format!("{marker}{label}: "), label_style)];
        spans.extend(value_spans);
        lines.push(Line::from(spans));
    }

    lines.push(Line::raw(""));
    if let Some(ref err) = form.error {
        lines.push(Line::from(Span::styled(
            format!("  ✗ {err}"),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            format!("  {}", t!("tui.form.stored")),
            Style::default().fg(Color::DarkGray),
        )));
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled(
            "  Tab/↑↓",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {}  ", t!("tui.form.hint_field")),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            "Ctrl+R",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {}  ", t!("tui.form.hint_show")),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            "Ctrl+S",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {}  ", t!("tui.form.hint_save")),
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

    let p = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(p, inner);
}

fn render_text_value(value: &str, placeholder: String, active: bool) -> Vec<Span<'_>> {
    if value.is_empty() {
        let mut spans = vec![Span::styled(
            placeholder,
            Style::default().fg(Color::DarkGray),
        )];
        if active {
            spans.insert(0, Span::styled("▏", Style::default().fg(Color::Cyan)));
        }
        spans
    } else {
        let mut spans = vec![Span::styled(
            value,
            Style::default().fg(if active { Color::White } else { Color::Gray }),
        )];
        if active {
            spans.push(Span::styled("▏", Style::default().fg(Color::Cyan)));
        }
        spans
    }
}

fn render_secret_value(
    value: &str,
    show: bool,
    placeholder: String,
    active: bool,
) -> Vec<Span<'_>> {
    if value.is_empty() {
        return render_text_value(value, placeholder, active);
    }
    let display = if show {
        value.to_string()
    } else {
        "•".repeat(value.chars().count())
    };
    let mut spans = vec![Span::styled(
        display,
        Style::default().fg(if active { Color::Yellow } else { Color::Gray }),
    )];
    if active {
        spans.push(Span::styled("▏", Style::default().fg(Color::Cyan)));
    }
    spans
}

fn draw_delete_modal(frame: &mut Frame, area: Rect, host_name: &str, endpoint: &str) {
    let popup = centered_rect(58, 9, area);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .title(Span::styled(
            format!(" {} ", t!("tui.delete.title")),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));

    let text = vec![
        Line::raw(""),
        Line::from(vec![
            Span::raw(format!("{} ", t!("tui.delete.question"))),
            Span::styled(
                host_name,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" ({endpoint}) ?")),
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

    let p = Paragraph::new(text)
        .alignment(Alignment::Center)
        .block(block);
    frame.render_widget(p, popup);
}

fn draw_help_modal(frame: &mut Frame, area: Rect, scroll: u16) {
    let popup = centered_rect(96, 40, area);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .title(Span::styled(
            format!(" {} ", t!("tui.help.title")),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let heading = |text: std::borrow::Cow<'static, str>| {
        Line::from(Span::styled(
            format!("  {text}"),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ))
    };
    let row = |left: String, right: String| Line::from(format!("   {left:<22} {right}"));

    let mut lines = vec![Line::raw(""), heading(t!("tui.help.section_commands"))];
    for c in SLASH_COMMANDS {
        if matches!(c.cmd, "/clear") {
            continue;
        }
        lines.push(row(c.usage(), tr(c.desc_key)));
    }
    lines.push(Line::raw(""));
    lines.push(heading(t!("tui.help.section_keys")));
    for (keys, desc) in [
        ("↑ / ↓", "tui.help.key_select"),
        ("Enter", "tui.help.key_connect"),
        ("Ctrl+F", "tui.slash.files"),
        ("Ctrl+N / F2", "tui.slash.new"),
        ("Ctrl+E · Ctrl+D", "tui.help.key_edit_delete"),
        ("Ctrl+T", "tui.slash.test"),
        ("Ctrl+P", "tui.slash.monitor"),
        ("Ctrl+R / F5", "tui.slash.refresh"),
        ("Esc", "tui.help.key_esc"),
    ] {
        lines.push(row(keys.to_string(), tr(desc)));
    }
    lines.push(Line::raw(""));
    lines.push(heading(t!("tui.help.section_terminal")));
    for (cmd, desc) in [
        (
            format!("ssha <{}>", tr("tui.arg.name")),
            "tui.help.term_connect",
        ),
        (
            format!("ssha files <{}> [path]", tr("tui.arg.name")),
            "cli.help.files.about",
        ),
        (
            format!("ssha get <{}> <remote> [local]", tr("tui.arg.name")),
            "cli.help.get.about",
        ),
        (
            format!("ssha put <{}> <local> [remote]", tr("tui.arg.name")),
            "cli.help.put.about",
        ),
        ("ssha lang <code>".to_string(), "cli.help.lang.about"),
    ] {
        lines.push(row(cmd, tr(desc)));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        format!("  {}", t!("tui.help.close")),
        Style::default().fg(Color::DarkGray),
    )));

    let block = block.title_bottom(Line::from(Span::styled(
        " ↑/↓ PgUp/PgDn · Esc ",
        Style::default().fg(Color::DarkGray),
    )));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        popup,
    );
}

/// "What's new" screen: new features ✨, fixes 🐛 and changes 🔧 of recent versions.
fn draw_whats_new_modal(frame: &mut Frame, area: Rect, notes: &[VersionNotes], scroll: u16) {
    let popup = centered_rect(92, 30, area);
    frame.render_widget(Clear, popup);

    let title = match notes.first() {
        Some(v) => format!(" ✨ {} ", t!("update.whats_new_title", version = v.version)),
        None => format!(" ✨ {} ", t!("update.notes.added")),
    };
    let block = Block::default()
        .title(Span::styled(
            title,
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Line::from(Span::styled(
            format!(" {} ", t!("update.whats_new_hint")),
            Style::default().fg(Color::DarkGray),
        )))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta));

    let mut lines: Vec<Line> = Vec::new();
    for v in notes {
        lines.push(Line::raw(""));
        let header = match &v.date {
            Some(d) => format!(" v{} — {}", v.version, d),
            None => format!(" v{}", v.version),
        };
        lines.push(Line::from(Span::styled(
            header,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        for (emoji, key, items, color) in [
            ("✨", "update.notes.added", &v.notes.added, Color::Green),
            ("🐛", "update.notes.fixed", &v.notes.fixed, Color::Yellow),
            ("🔧", "update.notes.changed", &v.notes.changed, Color::Blue),
        ] {
            if items.is_empty() {
                continue;
            }
            lines.push(Line::from(Span::styled(
                format!("  {emoji} {}", tr(key)),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            )));
            for item in items {
                if let Some(sub) = item.strip_prefix("  ") {
                    lines.push(Line::from(vec![
                        Span::styled("       ◦ ", Style::default().fg(Color::DarkGray)),
                        Span::styled(sub.to_string(), Style::default().fg(Color::Gray)),
                    ]));
                } else {
                    lines.push(Line::from(vec![
                        Span::styled("    • ", Style::default().fg(color)),
                        Span::raw(item.clone()),
                    ]));
                }
            }
        }
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        popup,
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn type_str(app: &mut AppState, storage: &Storage, s: &str) {
        for c in s.chars() {
            handle_key(app, press(KeyCode::Char(c)), storage).unwrap();
        }
    }

    #[test]
    fn slash_new_filter_connect_and_delete_workflow() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::with_dir(dir.path().to_path_buf()).unwrap();
        let mut app = AppState::new(storage.load_vault().unwrap(), None);

        // Type `/new` and press Enter to open creation modal
        type_str(&mut app, &storage, "/new");
        assert!(app.is_slash_mode());
        handle_key(&mut app, press(KeyCode::Enter), &storage).unwrap();
        assert!(matches!(app.modal, Modal::Form(_)));

        // Fill form: Name, Host, keep Port=22, Username, AuthKind=Password, Password, Ctrl+S
        type_str(&mut app, &storage, "my-laptop");
        handle_key(&mut app, press(KeyCode::Tab), &storage).unwrap();
        type_str(&mut app, &storage, "192.168.1.192");
        handle_key(&mut app, press(KeyCode::Tab), &storage).unwrap(); // Port
        handle_key(&mut app, press(KeyCode::Tab), &storage).unwrap(); // Username
                                                                      // Clear prefilled username and set custom one
        if let Modal::Form(ref mut f) = app.modal {
            f.username.clear();
        }
        type_str(&mut app, &storage, "gigi");
        handle_key(&mut app, press(KeyCode::Tab), &storage).unwrap(); // AuthKind (Password default)
        handle_key(&mut app, press(KeyCode::Tab), &storage).unwrap(); // Password
        type_str(&mut app, &storage, "secret-pass-123");
        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
            &storage,
        )
        .unwrap();

        assert!(matches!(app.modal, Modal::None));
        assert_eq!(app.vault.hosts.len(), 1);
        assert_eq!(app.vault.hosts[0].host, "192.168.1.192");

        // Reload from encrypted disk to confirm persistence
        let reloaded = storage.load_vault().unwrap();
        assert_eq!(reloaded.hosts.len(), 1);
        assert_eq!(reloaded.hosts[0].name, "my-laptop");

        // Live filter by IP and press Enter -> TuiAction::Connect
        type_str(&mut app, &storage, "192.168");
        let action = handle_key(&mut app, press(KeyCode::Enter), &storage).unwrap();
        match action {
            Some(TuiAction::Connect(h)) => {
                assert_eq!(h.name, "my-laptop");
                assert_eq!(h.username, "gigi");
            }
            _ => panic!("Expected TuiAction::Connect"),
        }

        // Clear filter and run `/del` + confirm
        handle_key(&mut app, press(KeyCode::Esc), &storage).unwrap();
        type_str(&mut app, &storage, "/del");
        handle_key(&mut app, press(KeyCode::Enter), &storage).unwrap();
        assert!(matches!(app.modal, Modal::ConfirmDelete { .. }));
        handle_key(&mut app, press(KeyCode::Char('o')), &storage).unwrap();
        assert!(app.vault.hosts.is_empty());
        assert!(storage.load_vault().unwrap().hosts.is_empty());
    }

    #[test]
    fn tab_autocompletes_machine_name_direct_and_after_slash_command() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::with_dir(dir.path().to_path_buf()).unwrap();
        let mut vault = VaultData::default();
        vault.hosts.push(SshHost {
            name: "my-laptop".into(),
            host: "192.168.1.192".into(),
            port: 22,
            username: "gigi".into(),
            auth: AuthMethod::Password {
                password: "secret".into(),
            },
            group: None,
            note: None,
            proxy_jump: None,
            local_forwards: Vec::new(),
            extra_keys: Vec::new(),
            forward_agent: false,
            monitor: false,
            created_at: Utc::now(),
            last_used: None,
        });
        vault.hosts.push(SshHost {
            name: "vps-prod".into(),
            host: "51.75.42.18".into(),
            port: 22,
            username: "deploy".into(),
            auth: AuthMethod::Password {
                password: "secret".into(),
            },
            group: None,
            note: None,
            proxy_jump: None,
            local_forwards: Vec::new(),
            extra_keys: Vec::new(),
            forward_agent: false,
            monitor: false,
            created_at: Utc::now(),
            last_used: None,
        });
        let mut app = AppState::new(vault, None);

        // 1. Direct typing `my` -> suggests `my-laptop` -> Tab completes to `my-laptop`
        type_str(&mut app, &storage, "my");
        assert_eq!(app.host_suggestions().len(), 1);
        assert_eq!(app.host_suggestions()[0].name, "my-laptop");
        handle_key(&mut app, press(KeyCode::Tab), &storage).unwrap();
        assert_eq!(app.input, "my-laptop");
        // Popup hides once exact unique match is completed
        assert!(app.host_suggestions().is_empty());

        // 2. Slash command `/files vp` -> suggests `vps-prod` -> Tab completes to `/files vps-prod`
        handle_key(&mut app, press(KeyCode::Esc), &storage).unwrap();
        type_str(&mut app, &storage, "/files vp");
        assert_eq!(app.host_suggestions().len(), 1);
        assert_eq!(app.host_suggestions()[0].name, "vps-prod");
        handle_key(&mut app, press(KeyCode::Tab), &storage).unwrap();
        assert_eq!(app.input, "/files vps-prod");
    }
}
