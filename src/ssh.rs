use crate::models::{AuthMethod, KnownHostEntry, SshHost};
use crate::storage::{expand_tilde, Storage};
use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use crossterm::terminal;
use russh::client::{self, KeyboardInteractiveAuthResponse};
use russh::keys::{load_secret_key, HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect};
use std::env;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(12);
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

struct RawModeGuard;

impl RawModeGuard {
    fn enter() -> Result<Self> {
        terminal::enable_raw_mode().context("Impossible d'activer le mode terminal brut")?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

enum TerminalInput {
    Data(Vec<u8>),
    #[cfg(windows)]
    Resize(u16, u16),
    Eof,
}

pub(crate) struct SshClientHandler {
    host_id: String,
    storage: Arc<Storage>,
}

impl client::Handler for SshClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let pub_key = server_public_key.public_key();
        let fingerprint = pub_key.fingerprint(HashAlg::Sha256).to_string();
        let algorithm = pub_key.algorithm().to_string();

        let mut known = self.storage.load_known_hosts().unwrap_or_default();

        if let Some(existing) = known.get(&self.host_id) {
            if existing.fingerprint == fingerprint {
                return Ok(true);
            }

            // Host key changed — warn loudly and ask confirmation before proceeding.
            eprintln!();
            eprintln!("\x1b[1;31m══════════════════════════════════════════════════════════════════\x1b[0m");
            eprintln!("\x1b[1;31m  ATTENTION : L'EMPREINTE SSH DU SERVEUR A CHANGÉ !\x1b[0m");
            eprintln!("\x1b[1;31m══════════════════════════════════════════════════════════════════\x1b[0m");
            eprintln!("  Hôte             : {}", self.host_id);
            eprintln!("  Ancienne clé     : {} ({})", existing.fingerprint, existing.algorithm);
            eprintln!("  Nouvelle clé     : {} ({})", fingerprint, algorithm);
            eprintln!("  Cela peut arriver après une réinstallation du serveur, ou indiquer");
            eprintln!("  une interception réseau (MITM).");
            eprint!("  Accepter et mettre à jour l'empreinte ? [o/N] : ");
            let _ = io::stderr().flush();

            let mut answer = String::new();
            if io::stdin().read_line(&mut answer).is_err() {
                return Ok(false);
            }
            let normalized = answer.trim().to_lowercase();
            if matches!(normalized.as_str(), "o" | "oui" | "y" | "yes") {
                known.insert(
                    self.host_id.clone(),
                    KnownHostEntry {
                        algorithm,
                        fingerprint,
                        first_seen: Utc::now(),
                    },
                );
                let _ = self.storage.save_known_hosts(&known);
                return Ok(true);
            }
            return Ok(false);
        }

        // Trust On First Use (TOFU)
        eprintln!(
            "\x1b[2m[ssha] Nouvelle empreinte enregistrée pour {} ({}, {})\x1b[0m",
            self.host_id, algorithm, fingerprint
        );
        known.insert(
            self.host_id.clone(),
            KnownHostEntry {
                algorithm,
                fingerprint,
                first_seen: Utc::now(),
            },
        );
        let _ = self.storage.save_known_hosts(&known);
        Ok(true)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PingState {
    Checking,
    Up(u128),
    Down,
}

/// Fast non-blocking reachability check (1.5s timeout) returning Up(rtt_ms) or Down.
pub async fn probe_host(host: &str, port: u16) -> PingState {
    let start = Instant::now();
    match tokio::time::timeout(
        Duration::from_millis(1500),
        TcpStream::connect((host, port)),
    )
    .await
    {
        Ok(Ok(_)) => PingState::Up(start.elapsed().as_millis()),
        _ => PingState::Down,
    }
}

/// Tests TCP reachability to an SSH endpoint and returns the connection latency.
pub async fn test_tcp_connection(host: &str, port: u16) -> Result<Duration> {
    let start = Instant::now();
    tokio::time::timeout(TEST_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .map_err(|_| anyhow!("Délai dépassé ({} s) vers {}:{}", TEST_TIMEOUT.as_secs(), host, port))?
        .with_context(|| format!("Impossible de joindre {}:{}", host, port))?;
    Ok(start.elapsed())
}

/// Opens an authenticated SSH session reusable for interactive shells or SFTP.
pub(crate) async fn connect_and_authenticate(
    host: &SshHost,
    storage: Arc<Storage>,
) -> Result<client::Handle<SshClientHandler>> {
    let config = Arc::new(client::Config {
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        nodelay: true,
        ..Default::default()
    });

    let handler = SshClientHandler {
        host_id: host.host_key_id(),
        storage,
    };

    let mut session = tokio::time::timeout(
        CONNECT_TIMEOUT,
        client::connect(config, (host.host.as_str(), host.port), handler),
    )
    .await
    .map_err(|_| {
        anyhow!(
            "Délai de connexion dépassé ({} s) vers {}:{}.",
            CONNECT_TIMEOUT.as_secs(),
            host.host,
            host.port
        )
    })?
    .with_context(|| {
        format!(
            "Impossible de se connecter à {}:{}",
            host.host, host.port
        )
    })?;

    authenticate(&mut session, host).await?;
    Ok(session)
}

/// Executes a single non-interactive command over an authenticated SSH session,
/// optionally piping `stdin_data` (e.g. for `sudo -S`) and returning `(exit_code, combined_output)`.
pub(crate) async fn exec_remote_command(
    session: &client::Handle<SshClientHandler>,
    command: &str,
    stdin_data: Option<&[u8]>,
) -> Result<(u32, String)> {
    let mut channel = session
        .channel_open_session()
        .await
        .context("Impossible d'ouvrir un canal SSH pour exécuter la commande distante")?;

    channel
        .exec(true, command)
        .await
        .context("Impossible de lancer la commande distante")?;

    if let Some(data) = stdin_data {
        if !data.is_empty() {
            channel.data(data).await?;
        }
        let _ = channel.eof().await;
    }

    let mut output = Vec::new();
    let mut exit_code: u32 = 0;

    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { ref data } => output.extend_from_slice(data),
            ChannelMsg::ExtendedData { ref data, .. } => output.extend_from_slice(data),
            ChannelMsg::ExitStatus { exit_status } => exit_code = exit_status,
            ChannelMsg::Eof | ChannelMsg::Close => break,
            _ => {}
        }
    }

    Ok((exit_code, String::from_utf8_lossy(&output).trim().to_string()))
}

/// Establishes an interactive SSH terminal session with automatic authentication.
pub async fn connect_interactive(host: &SshHost, storage: Arc<Storage>) -> Result<u32> {
    eprintln!(
        "\x1b[1;36m[ssha]\x1b[0m Connexion à \x1b[1m{}\x1b[0m ({})...",
        host.name,
        host.endpoint_display()
    );

    let session = connect_and_authenticate(host, storage).await?;

    let mut channel = session
        .channel_open_session()
        .await
        .context("Impossible d'ouvrir une session SSH")?;

    let (cols, rows) = terminal::size().unwrap_or((80, 24));
    let term = env::var("TERM")
        .ok()
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| "xterm-256color".to_string());

    channel
        .request_pty(true, &term, cols as u32, rows as u32, 0, 0, &[])
        .await
        .context("Impossible d'allouer un PTY distant")?;

    channel
        .request_shell(true)
        .await
        .context("Impossible de démarrer le shell distant")?;

    let exit_code = run_interactive_loop(&mut channel).await?;

    let _ = session
        .disconnect(Disconnect::ByApplication, "", "fr")
        .await;

    Ok(exit_code)
}

async fn authenticate(
    session: &mut client::Handle<SshClientHandler>,
    host: &SshHost,
) -> Result<()> {
    match &host.auth {
        AuthMethod::Password { password } => {
            let res = session
                .authenticate_password(&host.username, password)
                .await
                .context("Erreur pendant l'authentification par mot de passe")?;

            if res.success() {
                return Ok(());
            }

            // Fallback to keyboard-interactive (common with Linux PAM / OpenSSH defaults)
            let mut kbd = session
                .authenticate_keyboard_interactive_start(&host.username, None)
                .await
                .context("Erreur pendant l'authentification keyboard-interactive")?;

            let mut attempts = 0;
            loop {
                match kbd {
                    KeyboardInteractiveAuthResponse::Success => return Ok(()),
                    KeyboardInteractiveAuthResponse::Failure { .. } => {
                        bail!(
                            "Authentification refusée pour {}@{} (vérifie l'utilisateur et le mot de passe).",
                            host.username,
                            host.host
                        );
                    }
                    KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                        attempts += 1;
                        if attempts > 5 {
                            bail!("Trop de demandes d'authentification interactive.");
                        }
                        let responses = prompts
                            .iter()
                            .map(|p| {
                                if p.prompt.is_empty() {
                                    String::new()
                                } else {
                                    password.clone()
                                }
                            })
                            .collect();
                        kbd = session
                            .authenticate_keyboard_interactive_respond(responses)
                            .await
                            .context("Erreur lors de la réponse keyboard-interactive")?;
                    }
                }
            }
        }
        AuthMethod::Key { path, passphrase } => {
            let expanded = expand_tilde(path);
            let key_pair = load_secret_key(&expanded, passphrase.as_deref()).with_context(|| {
                format!(
                    "Impossible de charger la clé privée SSH '{}'. Vérifie le chemin ou la passphrase.",
                    expanded.display()
                )
            })?;

            let best_rsa_hash = session
                .best_supported_rsa_hash()
                .await
                .ok()
                .flatten()
                .flatten();

            let auth_res = session
                .authenticate_publickey(
                    &host.username,
                    PrivateKeyWithHashAlg::new(Arc::new(key_pair), best_rsa_hash),
                )
                .await
                .context("Erreur pendant l'authentification par clé SSH")?;

            if !auth_res.success() {
                bail!(
                    "Authentification par clé SSH refusée pour {}@{}.",
                    host.username,
                    host.host
                );
            }
            Ok(())
        }
    }
}

async fn run_interactive_loop(channel: &mut russh::Channel<client::Msg>) -> Result<u32> {
    let _raw_guard = RawModeGuard::enter()?;

    let stop = Arc::new(AtomicBool::new(false));
    let (tx, mut rx) = mpsc::channel::<TerminalInput>(128);
    let reader_handle = spawn_input_reader(tx, Arc::clone(&stop));

    #[cfg(unix)]
    let mut sigwinch = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
        .ok();

    let mut stdout = io::stdout();
    let mut exit_code: u32 = 0;
    let mut stdin_closed = false;

    loop {
        #[cfg(unix)]
        {
            tokio::select! {
                maybe_input = rx.recv(), if !stdin_closed => {
                    match maybe_input {
                        Some(TerminalInput::Data(bytes)) => {
                            if !bytes.is_empty() {
                                channel.data(&bytes[..]).await?;
                            }
                        }
                        Some(TerminalInput::Eof) | None => {
                            stdin_closed = true;
                            let _ = channel.eof().await;
                        }
                    }
                }
                _ = async {
                    if let Some(ref mut sig) = sigwinch {
                        sig.recv().await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    if let Ok((cols, rows)) = terminal::size() {
                        let _ = channel.window_change(cols as u32, rows as u32, 0, 0).await;
                    }
                }
                msg = channel.wait() => {
                    match msg {
                        Some(ChannelMsg::Data { ref data }) => {
                            stdout.write_all(data)?;
                            stdout.flush()?;
                        }
                        Some(ChannelMsg::ExtendedData { ref data, .. }) => {
                            stdout.write_all(data)?;
                            stdout.flush()?;
                        }
                        Some(ChannelMsg::ExitStatus { exit_status }) => {
                            exit_code = exit_status;
                        }
                        Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        #[cfg(not(unix))]
        {
            tokio::select! {
                maybe_input = rx.recv(), if !stdin_closed => {
                    match maybe_input {
                        Some(TerminalInput::Data(bytes)) => {
                            if !bytes.is_empty() {
                                channel.data(&bytes[..]).await?;
                            }
                        }
                        Some(TerminalInput::Resize(cols, rows)) => {
                            let _ = channel.window_change(cols as u32, rows as u32, 0, 0).await;
                        }
                        Some(TerminalInput::Eof) | None => {
                            stdin_closed = true;
                            let _ = channel.eof().await;
                        }
                    }
                }
                msg = channel.wait() => {
                    match msg {
                        Some(ChannelMsg::Data { ref data }) => {
                            stdout.write_all(data)?;
                            stdout.flush()?;
                        }
                        Some(ChannelMsg::ExtendedData { ref data, .. }) => {
                            stdout.write_all(data)?;
                            stdout.flush()?;
                        }
                        Some(ChannelMsg::ExitStatus { exit_status }) => {
                            exit_code = exit_status;
                        }
                        Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    stop.store(true, Ordering::Relaxed);
    let _ = reader_handle.join();
    Ok(exit_code)
}

#[cfg(unix)]
fn spawn_input_reader(
    tx: mpsc::Sender<TerminalInput>,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        use std::io::Read;

        let mut stdin = io::stdin();
        let mut buf = [0u8; 4096];

        while !stop.load(Ordering::Relaxed) {
            let mut pfd = libc::pollfd {
                fd: libc::STDIN_FILENO,
                events: libc::POLLIN,
                revents: 0,
            };

            let rc = unsafe { libc::poll(&mut pfd, 1, 40) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            if rc == 0 {
                continue;
            }

            if (pfd.revents & (libc::POLLIN | libc::POLLHUP)) != 0 {
                match stdin.read(&mut buf) {
                    Ok(0) => {
                        let _ = tx.blocking_send(TerminalInput::Eof);
                        break;
                    }
                    Ok(n) => {
                        if tx.blocking_send(TerminalInput::Data(buf[..n].to_vec())).is_err() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            } else if (pfd.revents & (libc::POLLERR | libc::POLLNVAL)) != 0 {
                break;
            }
        }
    })
}

#[cfg(windows)]
fn spawn_input_reader(
    tx: mpsc::Sender<TerminalInput>,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    use crossterm::event::{self, Event, KeyEventKind};

    std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            match event::poll(Duration::from_millis(40)) {
                Ok(true) => match event::read() {
                    Ok(Event::Key(key)) => {
                        if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                            let bytes = windows_key_event_to_vt_bytes(key);
                            if !bytes.is_empty()
                                && tx.blocking_send(TerminalInput::Data(bytes)).is_err()
                            {
                                break;
                            }
                        }
                    }
                    Ok(Event::Paste(text)) => {
                        if !text.is_empty()
                            && tx
                                .blocking_send(TerminalInput::Data(text.into_bytes()))
                                .is_err()
                        {
                            break;
                        }
                    }
                    Ok(Event::Resize(cols, rows)) => {
                        if tx.blocking_send(TerminalInput::Resize(cols, rows)).is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                },
                Ok(false) => continue,
                Err(_) => break,
            }
        }
    })
}

#[cfg(any(windows, test))]
fn windows_key_event_to_vt_bytes(key: crossterm::event::KeyEvent) -> Vec<u8> {
    use crossterm::event::{KeyCode, KeyModifiers};

    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    let shift = key.modifiers.contains(KeyModifiers::SHIFT);

    let xterm_mod = |shift: bool, alt: bool, ctrl: bool| -> u8 {
        1 + if shift { 1 } else { 0 } + if alt { 2 } else { 0 } + if ctrl { 4 } else { 0 }
    };

    let mut out = Vec::new();

    match key.code {
        KeyCode::Char(c) => {
            // Note: on Windows, AltGr is reported as CTRL + ALT; treat it as normal character.
            if ctrl && !alt {
                let b = match c {
                    'a'..='z' => Some((c as u8) - b'a' + 1),
                    'A'..='Z' => Some((c as u8) - b'A' + 1),
                    ' ' | '@' | '2' => Some(0x00),
                    '[' | '3' => Some(0x1b),
                    '\\' | '4' => Some(0x1c),
                    ']' | '5' => Some(0x1d),
                    '^' | '6' => Some(0x1e),
                    '_' | '/' | '7' => Some(0x1f),
                    '?' | '8' => Some(0x7f),
                    _ => None,
                };
                if let Some(ctrl_byte) = b {
                    out.push(ctrl_byte);
                }
            } else {
                if alt && !ctrl {
                    out.push(0x1b);
                }
                let mut utf8 = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut utf8).as_bytes());
            }
        }
        KeyCode::Enter => out.push(b'\r'),
        KeyCode::Tab => out.push(b'\t'),
        KeyCode::BackTab => out.extend_from_slice(b"\x1b[Z"),
        KeyCode::Backspace => {
            if alt {
                out.push(0x1b);
            }
            out.push(if ctrl { 0x08 } else { 0x7f });
        }
        KeyCode::Esc => out.push(0x1b),
        KeyCode::Up => push_csi_cursor(&mut out, b'A', xterm_mod(shift, alt, ctrl)),
        KeyCode::Down => push_csi_cursor(&mut out, b'B', xterm_mod(shift, alt, ctrl)),
        KeyCode::Right => push_csi_cursor(&mut out, b'C', xterm_mod(shift, alt, ctrl)),
        KeyCode::Left => push_csi_cursor(&mut out, b'D', xterm_mod(shift, alt, ctrl)),
        KeyCode::Home => push_csi_cursor(&mut out, b'H', xterm_mod(shift, alt, ctrl)),
        KeyCode::End => push_csi_cursor(&mut out, b'F', xterm_mod(shift, alt, ctrl)),
        KeyCode::Insert => push_csi_tilde(&mut out, 2, xterm_mod(shift, alt, ctrl)),
        KeyCode::Delete => push_csi_tilde(&mut out, 3, xterm_mod(shift, alt, ctrl)),
        KeyCode::PageUp => push_csi_tilde(&mut out, 5, xterm_mod(shift, alt, ctrl)),
        KeyCode::PageDown => push_csi_tilde(&mut out, 6, xterm_mod(shift, alt, ctrl)),
        KeyCode::F(n) => {
            let m = xterm_mod(shift, alt, ctrl);
            match n {
                1..=4 => {
                    let letter = [b'P', b'Q', b'R', b'S'][(n - 1) as usize];
                    if m == 1 {
                        out.extend_from_slice(&[0x1b, b'O', letter]);
                    } else {
                        out.extend_from_slice(format!("\x1b[1;{m}{}", letter as char).as_bytes());
                    }
                }
                5 => push_csi_tilde(&mut out, 15, m),
                6 => push_csi_tilde(&mut out, 17, m),
                7 => push_csi_tilde(&mut out, 18, m),
                8 => push_csi_tilde(&mut out, 19, m),
                9 => push_csi_tilde(&mut out, 20, m),
                10 => push_csi_tilde(&mut out, 21, m),
                11 => push_csi_tilde(&mut out, 23, m),
                12 => push_csi_tilde(&mut out, 24, m),
                _ => {}
            }
        }
        _ => {}
    }

    out
}

#[cfg(any(windows, test))]
fn push_csi_cursor(out: &mut Vec<u8>, code: u8, modifier: u8) {
    if modifier == 1 {
        out.extend_from_slice(&[0x1b, b'[', code]);
    } else {
        out.extend_from_slice(format!("\x1b[1;{modifier}{}", code as char).as_bytes());
    }
}

#[cfg(any(windows, test))]
fn push_csi_tilde(out: &mut Vec<u8>, num: u8, modifier: u8) {
    if modifier == 1 {
        out.extend_from_slice(format!("\x1b[{num}~").as_bytes());
    } else {
        out.extend_from_slice(format!("\x1b[{num};{modifier}~").as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use russh::server::{self, Auth, Server as _};
    use tokio::net::TcpListener;

    #[test]
    fn windows_vt_mapping_covers_common_keys() {
        assert_eq!(
            windows_key_event_to_vt_bytes(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            vec![0x03]
        );
        assert_eq!(
            windows_key_event_to_vt_bytes(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL)),
            vec![0x04]
        );
        assert_eq!(
            windows_key_event_to_vt_bytes(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE)),
            b"\x1b[A"
        );
        assert_eq!(
            windows_key_event_to_vt_bytes(KeyEvent::new(KeyCode::Right, KeyModifiers::CONTROL)),
            b"\x1b[1;5C"
        );
        assert_eq!(
            windows_key_event_to_vt_bytes(KeyEvent::new(KeyCode::Char('é'), KeyModifiers::NONE)),
            "é".as_bytes()
        );
    }

    #[derive(Clone)]
    struct TestSshServer {
        expected_user: String,
        expected_pass: String,
    }

    impl server::Server for TestSshServer {
        type Handler = Self;

        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
            self.clone()
        }
    }

    impl server::Handler for TestSshServer {
        type Error = russh::Error;

        async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
            if user == self.expected_user && password == self.expected_pass {
                Ok(Auth::Accept)
            } else {
                Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                })
            }
        }
    }

    #[tokio::test]
    async fn real_ssh_password_auth_and_tofu_known_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(Storage::with_dir(dir.path().to_path_buf()).unwrap());

        // Start an in-process SSH server on an ephemeral port
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let keypair = russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[7u8; 32]);
        let key = russh::keys::PrivateKey::from(keypair);
        let server_cfg = Arc::new(server::Config {
            auth_rejection_time: Duration::from_millis(10),
            auth_rejection_time_initial: Some(Duration::from_millis(0)),
            keys: vec![key],
            ..Default::default()
        });

        let mut srv = TestSshServer {
            expected_user: "alex".into(),
            expected_pass: "mon-mdp-secret".into(),
        };

        let server_task = tokio::spawn(async move {
            let _ = srv.run_on_socket(server_cfg, &listener).await;
        });

        // 1. TCP reachability test
        let rtt = test_tcp_connection("127.0.0.1", port).await.unwrap();
        assert!(rtt < Duration::from_secs(2));

        // 2. Authenticate with correct saved password + record TOFU host key
        let host = SshHost {
            name: "pc-test".into(),
            host: "127.0.0.1".into(),
            port,
            username: "alex".into(),
            auth: AuthMethod::Password {
                password: "mon-mdp-secret".into(),
            },
            group: None,
            note: None,
            created_at: Utc::now(),
            last_used: None,
        };

        let client_cfg = Arc::new(client::Config::default());
        let handler = SshClientHandler {
            host_id: host.host_key_id(),
            storage: Arc::clone(&storage),
        };
        let mut session = client::connect(client_cfg, ("127.0.0.1", port), handler)
            .await
            .unwrap();
        authenticate(&mut session, &host).await.unwrap();
        let _ = session
            .disconnect(Disconnect::ByApplication, "", "fr")
            .await;

        // Verify TOFU fingerprint was persisted
        let known = storage.load_known_hosts().unwrap();
        assert!(known.contains_key(&host.host_key_id()));

        // 3. Wrong password must fail cleanly
        let bad_host = SshHost {
            auth: AuthMethod::Password {
                password: "mauvais-mdp".into(),
            },
            ..host
        };
        let client_cfg2 = Arc::new(client::Config::default());
        let handler2 = SshClientHandler {
            host_id: bad_host.host_key_id(),
            storage: Arc::clone(&storage),
        };
        let mut session2 = client::connect(client_cfg2, ("127.0.0.1", port), handler2)
            .await
            .unwrap();
        assert!(authenticate(&mut session2, &bad_host).await.is_err());

        server_task.abort();
    }
}
