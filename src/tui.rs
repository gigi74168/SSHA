use crate::models::{format_relative_time, AuthMethod, SshHost, VaultData};
use crate::picker::{self, PickerResult};
use crate::sftp::{default_download_dir, resolve_local_path};
use crate::ssh::{probe_host, PingState};
use crate::ssh_config;
use crate::storage::{export_vault_to_file, import_vault_from_file, Storage};
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
    usage: &'static str,
    desc: &'static str,
}

const SLASH_COMMANDS: &[SlashCommandDef] = &[
    SlashCommandDef {
        cmd: "/new",
        usage: "/new",
        desc: "Ajouter une nouvelle connexion SSH",
    },
    SlashCommandDef {
        cmd: "/files",
        usage: "/files [nom]",
        desc: "Gérer et télécharger les fichiers à distance (SFTP)",
    },
    SlashCommandDef {
        cmd: "/edit",
        usage: "/edit [nom]",
        desc: "Modifier la connexion sélectionnée",
    },
    SlashCommandDef {
        cmd: "/del",
        usage: "/del [nom]",
        desc: "Supprimer la connexion sélectionnée",
    },
    SlashCommandDef {
        cmd: "/connect",
        usage: "/connect [nom]",
        desc: "Se connecter à la machine sélectionnée",
    },
    SlashCommandDef {
        cmd: "/test",
        usage: "/test [nom]",
        desc: "Tester la connexion réseau (ping TCP)",
    },
    SlashCommandDef {
        cmd: "/refresh",
        usage: "/refresh",
        desc: "Actualiser le statut UP/DOWN de toutes les machines",
    },
    SlashCommandDef {
        cmd: "/export",
        usage: "/export [fichier]",
        desc: "Exporter toutes les connexions (IP, users, mots de passe)",
    },
    SlashCommandDef {
        cmd: "/import",
        usage: "/import [fichier]",
        desc: "Importer une configuration depuis un autre ssha",
    },
    SlashCommandDef {
        cmd: "/import-ssh",
        usage: "/import-ssh [chemin]",
        desc: "Importer les machines depuis ~/.ssh/config (OpenSSH)",
    },
    SlashCommandDef {
        cmd: "/clear",
        usage: "/clear",
        desc: "Effacer la barre de recherche",
    },
    SlashCommandDef {
        cmd: "/help",
        usage: "/help",
        desc: "Afficher l'aide et les raccourcis",
    },
    SlashCommandDef {
        cmd: "/quit",
        usage: "/quit",
        desc: "Quitter ssha",
    },
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
    Form(HostForm),
    ConfirmDelete { host_name: String, endpoint: String },
    Help,
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
            FormField::AuthKind => None,
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
            return Err("Le nom / alias est obligatoire (ex: mon-pc).".to_string());
        }
        if name.starts_with('/') {
            return Err("Le nom ne peut pas commencer par '/'.".to_string());
        }

        // Check duplicate name unless editing the same entry
        if let Some(existing) = vault.find_by_name(&name) {
            let is_same = self
                .editing_original_name
                .as_deref()
                .map(|orig| orig.eq_ignore_ascii_case(&existing.name))
                .unwrap_or(false);
            if !is_same {
                return Err(format!("Une connexion nommée '{}' existe déjà.", name));
            }
        }

        let host = self.host.trim().to_string();
        if host.is_empty() {
            return Err("L'adresse IP ou le nom d'hôte est obligatoire (ex: 192.168.1.192).".to_string());
        }

        let port_str = self.port.trim();
        let port: u16 = if port_str.is_empty() {
            22
        } else {
            port_str
                .parse::<u16>()
                .ok()
                .filter(|&p| p > 0)
                .ok_or_else(|| "Le port doit être un nombre entre 1 et 65535.".to_string())?
        };

        let username = self.username.trim().to_string();
        if username.is_empty() {
            return Err("Le nom d'utilisateur SSH est obligatoire.".to_string());
        }

        let auth = match self.auth_kind {
            FormAuthKind::Password => {
                if self.password.is_empty() {
                    return Err("Le mot de passe SSH est obligatoire (ou choisis Clé SSH).".to_string());
                }
                AuthMethod::Password {
                    password: self.password.clone(),
                }
            }
            FormAuthKind::Key => {
                let path = self.key_path.trim().to_string();
                if path.is_empty() {
                    return Err("Le chemin vers la clé privée SSH est obligatoire.".to_string());
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
        }
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
        let takes_host = matches!(
            cmd.to_lowercase().as_str(),
            "/connect" | "/c" | "/open" | "/files" | "/sftp" | "/f" | "/edit" | "/e" | "/del"
                | "/delete" | "/rm" | "/remove" | "/test" | "/ping"
        );
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
    storage: &Storage,
    initial_status: Option<(bool, String)>,
) -> Result<TuiAction> {
    let vault = storage.load_vault()?;
    let mut app = AppState::new(vault, initial_status);
    app.enable_live_ping();

    let mut terminal = TuiGuard::enter()?;
    let _guard = TuiGuard;

    loop {
        app.poll_ping_results();
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

fn handle_key(
    app: &mut AppState,
    key: KeyEvent,
    storage: &Storage,
) -> Result<Option<TuiAction>> {
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
        Modal::Help => {
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
                app.modal = Modal::Form(HostForm::new_empty());
                return Ok(None);
            }
            KeyCode::Char('e') => {
                if let Some(host) = app.selected_host() {
                    app.modal = Modal::Form(HostForm::from_host(&host));
                } else {
                    app.set_status(StatusLevel::Info, "Aucune connexion sélectionnée à modifier.");
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
                    app.set_status(StatusLevel::Info, "Aucune connexion sélectionnée à supprimer.");
                }
                return Ok(None);
            }
            KeyCode::Char('t') => {
                if let Some(host) = app.selected_host() {
                    return Ok(Some(TuiAction::TestHost(host)));
                } else {
                    app.set_status(StatusLevel::Info, "Aucune connexion sélectionnée à tester.");
                }
                return Ok(None);
            }
            KeyCode::Char('f') => {
                if let Some(host) = app.selected_host() {
                    return Ok(Some(TuiAction::BrowseFiles(host)));
                } else {
                    app.set_status(StatusLevel::Info, "Aucune connexion sélectionnée pour les fichiers.");
                }
                return Ok(None);
            }
            KeyCode::Char('h') => {
                app.modal = Modal::Help;
                return Ok(None);
            }
            KeyCode::Char('r') => {
                app.trigger_ping_all(true);
                app.set_status(StatusLevel::Info, "Vérification UP/DOWN de toutes les machines...");
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
            app.modal = Modal::Help;
        }
        KeyCode::F(2) => {
            app.modal = Modal::Form(HostForm::new_empty());
        }
        KeyCode::F(5) => {
            app.trigger_ping_all(true);
            app.set_status(StatusLevel::Info, "Vérification UP/DOWN de toutes les machines...");
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
                    let takes_host = matches!(
                        cmd.cmd,
                        "/files" | "/edit" | "/del" | "/connect" | "/test"
                    );
                    app.input = if takes_host {
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
                app.set_status(
                    StatusLevel::Info,
                    "Aucune machine trouvée. Tape /new pour en ajouter une.",
                );
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
        "/refresh" | "/r" => "/refresh",
        "/export" | "/backup" => "/export",
        "/import" | "/restore" => "/import",
        "/import-ssh" | "/ssh-config" => "/import-ssh",
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
                    format!("Commande inconnue '{}'. Tape /help pour voir la liste.", typed_cmd),
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
                // Allow quick `/new 192.168.1.192` or `/new mon-pc`
                if a.contains('.') || a.contains(':') {
                    form.host = a.to_string();
                } else {
                    form.name = a.to_string();
                }
            }
            app.modal = Modal::Form(form);
        }
        "/files" => {
            let target = match arg {
                Some(name) => app.vault.find_by_name(name).cloned(),
                None => app.selected_host(),
            };
            if let Some(host) = target {
                return Ok(Some(TuiAction::BrowseFiles(host)));
            } else {
                app.set_status(StatusLevel::Error, "Connexion introuvable pour /files.");
            }
        }
        "/edit" => {
            let target = match arg {
                Some(name) => app.vault.find_by_name(name).cloned(),
                None => app.selected_host(),
            };
            if let Some(host) = target {
                app.modal = Modal::Form(HostForm::from_host(&host));
            } else {
                app.set_status(StatusLevel::Error, "Connexion introuvable pour /edit.");
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
                app.set_status(StatusLevel::Error, "Connexion introuvable pour /del.");
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
                app.set_status(StatusLevel::Error, "Connexion introuvable.");
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
                app.set_status(StatusLevel::Error, "Aucune connexion à tester.");
            }
        }
        "/refresh" => {
            app.trigger_ping_all(true);
            app.set_status(StatusLevel::Info, "Vérification UP/DOWN de toutes les machines...");
        }
        "/export" => {
            let dest = match arg {
                Some(p) => Some(resolve_local_path(p)),
                None => match picker::pick_save_file(
                    "Exporter la configuration ssha",
                    "ssha-config.json",
                    Some(("Configuration ssha (*.json)", "*.json")),
                ) {
                    PickerResult::Selected(p) => Some(p),
                    PickerResult::Cancelled => {
                        app.set_status(StatusLevel::Info, "Export annulé.");
                        None
                    }
                    PickerResult::Unavailable => Some(default_download_dir().join("ssha-config.json")),
                },
            };
            if let Some(path) = dest {
                match export_vault_to_file(&app.vault, &path) {
                    Ok(count) => app.set_status(
                        StatusLevel::Success,
                        format!("{count} connexion(s) exportée(s) → {}", path.display()),
                    ),
                    Err(e) => app.set_status(StatusLevel::Error, format!("Échec export : {e:#}")),
                }
            }
        }
        "/import" => {
            let src = match arg {
                Some(p) => Some(resolve_local_path(p)),
                None => match picker::pick_file(
                    "Importer une configuration ssha",
                    Some(("Configuration ssha (*.json)", "*.json")),
                ) {
                    PickerResult::Selected(p) => Some(p),
                    PickerResult::Cancelled => {
                        app.set_status(StatusLevel::Info, "Import annulé.");
                        None
                    }
                    PickerResult::Unavailable => {
                        app.set_status(
                            StatusLevel::Info,
                            "Tape `/import <chemin_du_fichier.json>` pour importer sans interface graphique.",
                        );
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
                        }
                        app.set_status(
                            StatusLevel::Success,
                            format!(
                                "Import terminé : {} ajoutée(s), {} mise(s) à jour.",
                                report.added, report.updated
                            ),
                        );
                    }
                    Err(e) => app.set_status(StatusLevel::Error, format!("Échec import : {e:#}")),
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
                        }
                        app.set_status(
                            StatusLevel::Success,
                            format!(
                                "Import ~/.ssh/config : {} ajoutée(s), {} ignorée(s).",
                                report.added, report.skipped
                            ),
                        );
                    }
                    Err(e) => app.set_status(StatusLevel::Error, format!("{e:#}")),
                }
            } else {
                app.set_status(StatusLevel::Error, "Impossible de localiser ~/.ssh/config.");
            }
        }
        "/clear" => {
            app.status = None;
        }
        "/help" => {
            app.modal = Modal::Help;
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
            app.modal = Modal::None;
            app.set_status(
                StatusLevel::Success,
                if was_edit {
                    format!("Connexion '{}' mise à jour et chiffrée.", saved_name)
                } else {
                    format!(
                        "Connexion '{}' ajoutée et chiffrée. Appuie sur Entrée pour te connecter !",
                        saved_name
                    )
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
        KeyCode::Enter | KeyCode::Char('o') | KeyCode::Char('O') | KeyCode::Char('y') | KeyCode::Char('Y') => {
            let host_name = match &app.modal {
                Modal::ConfirmDelete { host_name, .. } => host_name.clone(),
                _ => return Ok(()),
            };
            app.vault.remove_by_name(&host_name);
            storage.save_vault(&app.vault)?;
            app.modal = Modal::None;
            app.set_status(
                StatusLevel::Success,
                format!("Connexion '{}' supprimée.", host_name),
            );
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
        Modal::ConfirmDelete { host_name, endpoint } => {
            draw_delete_modal(frame, area, host_name, endpoint)
        }
        Modal::Help => draw_help_modal(frame, area),
    }
}

fn draw_header(frame: &mut Frame, area: Rect, app: &AppState) {
    let count = app.vault.hosts.len();
    let label = if count <= 1 {
        format!("{count} connexion")
    } else {
        format!("{count} connexions")
    };

    let title = Line::from(vec![
        Span::styled(
            " ssha ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  Gestionnaire SSH 100% CLI  "),
        Span::styled("│", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("  {label}  "), Style::default().fg(Color::White)),
        Span::styled("│", Style::default().fg(Color::DarkGray)),
        Span::styled("  AES-256-GCM auto", Style::default().fg(Color::Green)),
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
            " Connexions SSH enregistrées ",
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
                "Aucune connexion SSH enregistrée pour le moment.",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::raw(""),
            Line::from(vec![
                Span::raw("Tape "),
                Span::styled(
                    "/new",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" puis "),
                Span::styled("Entrée", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(" (ou "),
                Span::styled(
                    "Ctrl+N",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(") pour enregistrer ta première machine"),
            ]),
            Line::from(Span::styled(
                "(ex: 192.168.1.192 avec son mot de passe SSH).",
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
                format!("Aucun résultat pour « {} ».", app.input),
                Style::default().fg(Color::Yellow),
            )),
            Line::from(Span::styled(
                "Appuie sur Esc pour réinitialiser le filtre, ou tape /new pour ajouter une machine.",
                Style::default().fg(Color::DarkGray),
            )),
        ])
        .alignment(Alignment::Center)
        .block(block);
        frame.render_widget(no_match, area);
        return;
    }

    let header = Row::new(vec![
        Cell::from("  Nom"),
        Cell::from("Adresse"),
        Cell::from("Auth"),
        Cell::from("Groupe"),
        Cell::from("Dernière connexion"),
        Cell::from(Line::from("État").alignment(Alignment::Right)),
    ])
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
                    Style::default()
                        .fg(Color::Red)
                        .add_modifier(Modifier::BOLD),
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

            Row::new(vec![
                Cell::from(format!("{prefix}{}", h.name)).style(if selected {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                }),
                addr_cell,
                auth_cell,
                Cell::from(h.group.as_deref().unwrap_or("—"))
                    .style(Style::default().fg(Color::Magenta)),
                Cell::from(format_relative_time(h.last_used))
                    .style(Style::default().fg(Color::DarkGray)),
                dot_cell,
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(20),
        Constraint::Percentage(37),
        Constraint::Length(9),
        Constraint::Percentage(13),
        Constraint::Percentage(17),
        Constraint::Length(5),
    ];

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
            PingState::Checking => {
                Span::styled("  │  ● ...", Style::default().fg(Color::Yellow))
            }
        };
        let note_str = host
            .note
            .as_deref()
            .map(|n| format!("  │  Note: {n}"))
            .unwrap_or_default();
        lines.push(Line::from(vec![
            Span::styled(" Sélection : ", Style::default().fg(Color::DarkGray)),
            Span::styled(host.name, Style::default().fg(Color::Cyan)),
            Span::raw(format!(" ({endpoint})")),
            ping_span,
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
        " Commande "
    } else {
        " Recherche / Commande (/new, /edit, /del, /help) "
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
                "Filtre une machine ou tape /new pour ajouter...",
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
                    " Machines (Tab: compléter, ↑↓: choisir, Entrée: valider) ",
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
    let width = 58u16.min(input_area.width);
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
                    " Commandes (Tab: compléter, Entrée: exécuter) ",
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
    let hints = Line::from(vec![
        Span::styled(" Entrée", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(" SSH  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Ctrl+F", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(" Fichiers  ", Style::default().fg(Color::DarkGray)),
        Span::styled("/new", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(" Ajouter  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Ctrl+E", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(" Éditer  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Ctrl+D", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(" Suppr  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Ctrl+T", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(" Test  ", Style::default().fg(Color::DarkGray)),
        Span::styled("/help", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(" Aide  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Esc", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(" Quitter", Style::default().fg(Color::DarkGray)),
    ]);

    frame.render_widget(Paragraph::new(hints), area);
}

fn draw_form_modal(frame: &mut Frame, area: Rect, form: &HostForm) {
    let popup = centered_rect(72, 22, area);
    frame.render_widget(Clear, popup);

    let title = if let Some(ref orig) = form.editing_original_name {
        format!(" Modifier la connexion '{}' ", orig)
    } else {
        " Nouvelle connexion SSH (/new) ".to_string()
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

        let (label, value_spans) = match f {
            FormField::Name => (
                "Nom / Alias       ",
                render_text_value(&form.name, "ex: mon-pc, serveur-maison", active),
            ),
            FormField::Host => (
                "Hôte / IP         ",
                render_text_value(&form.host, "ex: 192.168.1.192", active),
            ),
            FormField::Port => (
                "Port              ",
                render_text_value(&form.port, "22", active),
            ),
            FormField::Username => (
                "Utilisateur       ",
                render_text_value(&form.username, "ex: root, ubuntu, admin", active),
            ),
            FormField::AuthKind => {
                let pwd_style = if form.auth_kind == FormAuthKind::Password {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::DarkGray)
                };
                let key_style = if form.auth_kind == FormAuthKind::Key {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Green)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::DarkGray)
                };
                (
                    "Authentification  ",
                    vec![
                        Span::styled(" Mot de passe ", pwd_style),
                        Span::raw("  "),
                        Span::styled(" Clé SSH ", key_style),
                        Span::styled(
                            if active { "  (←/→ ou Espace)" } else { "" },
                            Style::default().fg(Color::DarkGray),
                        ),
                    ],
                )
            }
            FormField::Password => (
                "Mot de passe SSH  ",
                render_secret_value(&form.password, form.show_secret, "saisir le mot de passe", active),
            ),
            FormField::KeyPath => (
                "Clé privée        ",
                render_text_value(&form.key_path, "~/.ssh/id_ed25519", active),
            ),
            FormField::KeyPassphrase => (
                "Passphrase (opt.) ",
                render_secret_value(&form.key_passphrase, form.show_secret, "(vide si aucune)", active),
            ),
            FormField::Group => (
                "Groupe (opt.)     ",
                render_text_value(&form.group, "ex: Maison, Prod, Lab", active),
            ),
            FormField::Note => (
                "Note (opt.)       ",
                render_text_value(&form.note, "description libre", active),
            ),
        };

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
            "  Stocké automatiquement dans vault.enc chiffré (AES-256-GCM).",
            Style::default().fg(Color::DarkGray),
        )));
    }

    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled("  Tab/↑↓", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(" Champ  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Ctrl+R", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(" Voir/Masquer mdp  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Ctrl+S", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(" Enregistrer  ", Style::default().fg(Color::DarkGray)),
        Span::styled("Esc", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        Span::styled(" Annuler", Style::default().fg(Color::DarkGray)),
    ]));

    let p = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(p, inner);
}

fn render_text_value<'a>(value: &'a str, placeholder: &'a str, active: bool) -> Vec<Span<'a>> {
    if value.is_empty() {
        let mut spans = vec![Span::styled(placeholder, Style::default().fg(Color::DarkGray))];
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

fn render_secret_value<'a>(
    value: &'a str,
    show: bool,
    placeholder: &'a str,
    active: bool,
) -> Vec<Span<'a>> {
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
            " Confirmer la suppression ",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red));

    let text = vec![
        Line::raw(""),
        Line::from(vec![
            Span::raw("Supprimer la connexion "),
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

    let p = Paragraph::new(text).alignment(Alignment::Center).block(block);
    frame.render_widget(p, popup);
}

fn draw_help_modal(frame: &mut Frame, area: Rect) {
    let popup = centered_rect(76, 25, area);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .title(Span::styled(
            " Aide — ssha ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let lines = vec![
        Line::raw(""),
        Line::from(Span::styled(
            "  Commandes interactives (dans la barre >) :",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("    /new             Ajouter une nouvelle machine SSH"),
        Line::from("    /files [nom]     Ouvrir le gestionnaire de fichiers distant (SFTP)"),
        Line::from("    /edit [nom]      Modifier la machine sélectionnée"),
        Line::from("    /del [nom]       Supprimer une machine"),
        Line::from("    /connect [nom]   Se connecter immédiatement"),
        Line::from("    /test [nom]      Vérifier si le port SSH répond"),
        Line::from("    /help            Afficher cette aide   │  /quit  Quitter"),
        Line::raw(""),
        Line::from(Span::styled(
            "  Raccourcis clavier :",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("    ↑ / ↓            Sélectionner une machine"),
        Line::from("    Entrée           Lancer la connexion SSH"),
        Line::from("    Ctrl+F           Gérer / télécharger les fichiers distants (SFTP)"),
        Line::from("    Ctrl+N / F2      Ajouter (/new)"),
        Line::from("    Ctrl+E           Modifier   │  Ctrl+D   Supprimer"),
        Line::from("    Ctrl+T           Tester     │  Esc      Effacer / Quitter"),
        Line::raw(""),
        Line::from(Span::styled(
            "  Commandes directes depuis ton terminal :",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("    ssha <nom>                        Connexion SSH directe"),
        Line::from("    ssha files <nom> [chemin]         Explorateur de fichiers distant"),
        Line::from("    ssha get <nom> <distant> [local]  Télécharger un fichier/dossier"),
        Line::from("    ssha put <nom> <local> [distant]  Envoyer un fichier/dossier"),
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
        type_str(&mut app, &storage, "mon-ordi");
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
        type_str(&mut app, &storage, "mdp-secret-123");
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
        assert_eq!(reloaded.hosts[0].name, "mon-ordi");

        // Live filter by IP and press Enter -> TuiAction::Connect
        type_str(&mut app, &storage, "192.168");
        let action = handle_key(&mut app, press(KeyCode::Enter), &storage).unwrap();
        match action {
            Some(TuiAction::Connect(h)) => {
                assert_eq!(h.name, "mon-ordi");
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
            name: "mon-ordi".into(),
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
            created_at: Utc::now(),
            last_used: None,
        });
        let mut app = AppState::new(vault, None);

        // 1. Direct typing `mon` -> suggests `mon-ordi` -> Tab completes to `mon-ordi`
        type_str(&mut app, &storage, "mon");
        assert_eq!(app.host_suggestions().len(), 1);
        assert_eq!(app.host_suggestions()[0].name, "mon-ordi");
        handle_key(&mut app, press(KeyCode::Tab), &storage).unwrap();
        assert_eq!(app.input, "mon-ordi");
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
