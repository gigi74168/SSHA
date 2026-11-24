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
        terminal::enable_raw_mode().context(t!("ssh.err.raw_mode").into_owned())?;
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
    /// Background (quiet) mode: never print nor prompt. A changed host key is refused
    /// and reported through this flag instead of asking the user.
    quiet_key_changed: Option<Arc<AtomicBool>>,
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

            // Background monitoring must never prompt: refuse and report.
            if let Some(flag) = &self.quiet_key_changed {
                flag.store(true, Ordering::SeqCst);
                return Ok(false);
            }

            // Host key changed — warn loudly and ask confirmation before proceeding.
            let label_old = t!("ssh.key.old");
            let label_new = t!("ssh.key.new");
            let label_host = t!("ssh.key.host");
            let width = [&label_old, &label_new, &label_host]
                .iter()
                .map(|l| l.chars().count())
                .max()
                .unwrap_or(0);
            let pad = |l: &str| format!("{l}{}", " ".repeat(width - l.chars().count()));
            eprintln!();
            eprintln!("\x1b[1;31m══════════════════════════════════════════════════════════════════\x1b[0m");
            eprintln!("\x1b[1;31m  {}\x1b[0m", t!("ssh.key.changed_title"));
            eprintln!("\x1b[1;31m══════════════════════════════════════════════════════════════════\x1b[0m");
            eprintln!("  {} : {}", pad(&label_host), self.host_id);
            eprintln!(
                "  {} : {} ({})",
                pad(&label_old),
                existing.fingerprint,
                existing.algorithm
            );
            eprintln!("  {} : {} ({})", pad(&label_new), fingerprint, algorithm);
            eprintln!("  {}", t!("ssh.key.changed_explain"));
            eprint!("  {} ", t!("ssh.key.accept_prompt"));
            let _ = io::stderr().flush();

            let mut answer = String::new();
            if io::stdin().read_line(&mut answer).is_err() {
                return Ok(false);
            }
            if crate::i18n::is_yes(&answer) {
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
        if self.quiet_key_changed.is_none() {
            eprintln!(
                "\x1b[2m[ssha] {}\x1b[0m",
                t!(
                    "ssh.key.tofu",
                    host = self.host_id,
                    algorithm = algorithm,
                    fingerprint = fingerprint
                )
            );
        }
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
        .map_err(|_| {
            anyhow!(t!(
                "ssh.err.timeout",
                secs = TEST_TIMEOUT.as_secs(),
                endpoint = format!("{host}:{port}")
            )
            .into_owned())
        })?
        .with_context(|| {
            t!("ssh.err.unreachable", endpoint = format!("{host}:{port}")).into_owned()
        })?;
    Ok(start.elapsed())
}

/// Opens an authenticated SSH session reusable for interactive shells or SFTP.
/// Supports `ProxyJump` (bastion) referencing either a saved `ssha` host name or `user@host[:port]`.
pub(crate) async fn connect_and_authenticate(
    host: &SshHost,
    storage: Arc<Storage>,
) -> Result<client::Handle<SshClientHandler>> {
    connect_with_depth(host, storage, 0, None).await
}

/// Error returned by [`connect_quiet`]: the server host key changed (connection refused).
#[derive(Debug)]
pub struct HostKeyChanged;

impl std::fmt::Display for HostKeyChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", t!("ssh.key.changed_short"))
    }
}

impl std::error::Error for HostKeyChanged {}

/// Opens an authenticated session for background work (CPU/RAM monitoring): nothing is ever
/// printed or asked. A changed host key makes it fail with [`HostKeyChanged`].
pub(crate) async fn connect_quiet(
    host: &SshHost,
    storage: Arc<Storage>,
) -> Result<client::Handle<SshClientHandler>> {
    let flag = Arc::new(AtomicBool::new(false));
    let result = connect_with_depth(host, storage, 0, Some(Arc::clone(&flag))).await;
    match result {
        Err(_) if flag.load(Ordering::SeqCst) => Err(HostKeyChanged.into()),
        other => other,
    }
}

fn connect_with_depth<'a>(
    host: &'a SshHost,
    storage: Arc<Storage>,
    depth: u8,
    quiet: Option<Arc<AtomicBool>>,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<client::Handle<SshClientHandler>>> + Send + 'a>,
> {
    Box::pin(async move {
        if depth > 4 {
            bail!(t!("ssh.err.proxy_loop").into_owned());
        }

        let config = Arc::new(client::Config {
            inactivity_timeout: None,
            keepalive_interval: Some(Duration::from_secs(30)),
            keepalive_max: 3,
            nodelay: true,
            ..Default::default()
        });

        let handler = SshClientHandler {
            host_id: host.host_key_id(),
            storage: Arc::clone(&storage),
            quiet_key_changed: quiet.clone(),
        };

        let mut session = if let Some(ref jump_spec) = host.proxy_jump {
            let jump_host = resolve_jump_host(jump_spec, &storage, &host.username)?;
            if quiet.is_none() {
                eprintln!(
                    "\x1b[2m[ssha] {}\x1b[0m",
                    t!(
                        "ssh.proxy_jump_via",
                        name = jump_host.name,
                        endpoint = jump_host.endpoint_display()
                    )
                );
            }
            let jump_session =
                connect_with_depth(&jump_host, Arc::clone(&storage), depth + 1, quiet.clone())
                    .await?;
            let tunnel = jump_session
                .channel_open_direct_tcpip(host.host.as_str(), host.port as u32, "127.0.0.1", 0)
                .await
                .with_context(|| {
                    t!(
                        "ssh.err.proxy_tunnel",
                        endpoint = format!("{}:{}", host.host, host.port),
                        jump = jump_host.name
                    )
                    .into_owned()
                })?;

            tokio::time::timeout(
                CONNECT_TIMEOUT,
                client::connect_stream(config, tunnel.into_stream(), handler),
            )
            .await
            .map_err(|_| {
                anyhow!(t!(
                    "ssh.err.proxy_timeout",
                    secs = CONNECT_TIMEOUT.as_secs(),
                    endpoint = format!("{}:{}", host.host, host.port)
                )
                .into_owned())
            })?
            .with_context(|| {
                t!(
                    "ssh.err.proxy_session",
                    endpoint = format!("{}:{}", host.host, host.port)
                )
                .into_owned()
            })?
        } else {
            tokio::time::timeout(
                CONNECT_TIMEOUT,
                client::connect(config, (host.host.as_str(), host.port), handler),
            )
            .await
            .map_err(|_| {
                anyhow!(t!(
                    "ssh.err.connect_timeout",
                    secs = CONNECT_TIMEOUT.as_secs(),
                    endpoint = format!("{}:{}", host.host, host.port)
                )
                .into_owned())
            })?
            .with_context(|| {
                t!(
                    "ssh.err.connect",
                    endpoint = format!("{}:{}", host.host, host.port)
                )
                .into_owned()
            })?
        };

        authenticate(&mut session, host).await?;
        Ok(session)
    })
}

fn resolve_jump_host(spec: &str, storage: &Storage, default_user: &str) -> Result<SshHost> {
    let trimmed = spec.trim();
    if let Ok(vault) = storage.load_vault() {
        if let Some(found) = vault.find_by_name(trimmed) {
            return Ok(found.clone());
        }
    }

    // Parse inline `[user@]host[:port]`
    let (user, host_port) = match trimmed.split_once('@') {
        Some((u, hp)) => (u.to_string(), hp),
        None => (default_user.to_string(), trimmed),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (
            h.trim_matches(['[', ']']).to_string(),
            p.parse::<u16>()
                .with_context(|| t!("ssh.err.proxy_port", spec = spec).into_owned())?,
        ),
        None => (host_port.to_string(), 22),
    };

    Ok(SshHost {
        name: trimmed.to_string(),
        host,
        port,
        username: user,
        auth: AuthMethod::Key {
            path: "~/.ssh/id_ed25519".to_string(),
            passphrase: None,
        },
        group: None,
        note: None,
        proxy_jump: None,
        local_forwards: Vec::new(),
        extra_keys: vec!["~/.ssh/id_rsa".to_string()],
        forward_agent: false,
        monitor: false,
        created_at: Utc::now(),
        last_used: None,
    })
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
        .context(t!("ssh.err.exec_channel").into_owned())?;

    channel
        .exec(true, command)
        .await
        .context(t!("ssh.err.exec").into_owned())?;

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

    Ok((
        exit_code,
        String::from_utf8_lossy(&output).trim().to_string(),
    ))
}

/// Establishes an interactive SSH terminal session with automatic authentication,
/// optional ProxyJump bastion, and active LocalForward TCP tunnels.
pub async fn connect_interactive(host: &SshHost, storage: Arc<Storage>) -> Result<u32> {
    eprintln!(
        "\x1b[1;36m[ssha]\x1b[0m {}",
        t!(
            "ssh.connecting",
            name = format!("\x1b[1m{}\x1b[0m", host.name),
            endpoint = host.endpoint_display()
        )
    );

    let session = Arc::new(connect_and_authenticate(host, storage).await?);

    // Start any configured LocalForward TCP tunnels
    let mut forward_tasks = Vec::new();
    for spec in &host.local_forwards {
        let bind_target = format!("{}:{}", spec.bind_addr, spec.local_port);
        match tokio::net::TcpListener::bind(&bind_target).await {
            Ok(listener) => {
                eprintln!(
                    "\x1b[2m[ssha] {}\x1b[0m",
                    t!("ssh.tunnel_active", spec = spec)
                );
                let sess = Arc::clone(&session);
                let remote_host = spec.remote_host.clone();
                let remote_port = spec.remote_port as u32;
                forward_tasks.push(tokio::spawn(async move {
                    while let Ok((mut local_stream, peer)) = listener.accept().await {
                        let sess = Arc::clone(&sess);
                        let rh = remote_host.clone();
                        tokio::spawn(async move {
                            if let Ok(channel) = sess
                                .channel_open_direct_tcpip(
                                    rh.as_str(),
                                    remote_port,
                                    peer.ip().to_string(),
                                    peer.port() as u32,
                                )
                                .await
                            {
                                let mut ssh_stream = channel.into_stream();
                                let _ = tokio::io::copy_bidirectional(
                                    &mut local_stream,
                                    &mut ssh_stream,
                                )
                                .await;
                            }
                        });
                    }
                }));
            }
            Err(e) => {
                eprintln!(
                    "\x1b[1;33m[ssha]\x1b[0m {}",
                    t!("ssh.err.tunnel", spec = spec, error = e)
                );
            }
        }
    }

    let mut channel = session
        .channel_open_session()
        .await
        .context(t!("ssh.err.session").into_owned())?;

    let (cols, rows) = terminal::size().unwrap_or((80, 24));
    let term = env::var("TERM")
        .ok()
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| "xterm-256color".to_string());

    channel
        .request_pty(true, &term, cols as u32, rows as u32, 0, 0, &[])
        .await
        .context(t!("ssh.err.pty").into_owned())?;

    channel
        .request_shell(true)
        .await
        .context(t!("ssh.err.shell").into_owned())?;

    let exit_code = run_interactive_loop(&mut channel).await?;

    for task in forward_tasks {
        task.abort();
    }

    let _ = session
        .disconnect(Disconnect::ByApplication, "", "en")
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
                .context(t!("ssh.err.auth_password").into_owned())?;

            if res.success() {
                return Ok(());
            }

            // Fallback to keyboard-interactive (common with Linux PAM / OpenSSH defaults)
            let mut kbd = session
                .authenticate_keyboard_interactive_start(&host.username, None)
                .await
                .context(t!("ssh.err.auth_kbd").into_owned())?;

            let mut attempts = 0;
            loop {
                match kbd {
                    KeyboardInteractiveAuthResponse::Success => return Ok(()),
                    KeyboardInteractiveAuthResponse::Failure { .. } => {
                        bail!(t!(
                            "ssh.err.auth_refused",
                            target = format!("{}@{}", host.username, host.host)
                        )
                        .into_owned());
                    }
                    KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                        attempts += 1;
                        if attempts > 5 {
                            bail!(t!("ssh.err.auth_too_many").into_owned());
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
                            .context(t!("ssh.err.auth_kbd_reply").into_owned())?;
                    }
                }
            }
        }
        AuthMethod::Key { path, passphrase } => {
            let best_rsa_hash = session
                .best_supported_rsa_hash()
                .await
                .ok()
                .flatten()
                .flatten();

            let mut candidate_keys: Vec<(&str, Option<&str>)> =
                vec![(path.as_str(), passphrase.as_deref())];
            for extra in &host.extra_keys {
                candidate_keys.push((extra.as_str(), None));
            }

            let mut last_err: Option<anyhow::Error> = None;
            for (key_path, key_pass) in candidate_keys {
                let expanded = expand_tilde(key_path);
                let key_pair = match load_secret_key(&expanded, key_pass) {
                    Ok(k) => k,
                    Err(e) => {
                        last_err = Some(anyhow!(t!(
                            "ssh.err.key_load",
                            path = expanded.display(),
                            error = e
                        )
                        .into_owned()));
                        continue;
                    }
                };

                match session
                    .authenticate_publickey(
                        &host.username,
                        PrivateKeyWithHashAlg::new(Arc::new(key_pair), best_rsa_hash),
                    )
                    .await
                {
                    Ok(auth_res) if auth_res.success() => return Ok(()),
                    Ok(_) => {
                        last_err = Some(anyhow!(t!(
                            "ssh.err.key_refused",
                            path = expanded.display(),
                            target = format!("{}@{}", host.username, host.host)
                        )
                        .into_owned()));
                    }
                    Err(e) => {
                        last_err = Some(anyhow!(t!("ssh.err.key_auth", error = e).into_owned()));
                    }
                }
            }

            Err(last_err.unwrap_or_else(|| {
                anyhow!(t!(
                    "ssh.err.key_auth_refused",
                    target = format!("{}@{}", host.username, host.host)
                )
                .into_owned())
            }))
        }
    }
}

async fn run_interactive_loop(channel: &mut russh::Channel<client::Msg>) -> Result<u32> {
    let _raw_guard = RawModeGuard::enter()?;

    let stop = Arc::new(AtomicBool::new(false));
    let (tx, mut rx) = mpsc::channel::<TerminalInput>(128);
    let reader_handle = spawn_input_reader(tx, Arc::clone(&stop));

    #[cfg(unix)]
    let mut sigwinch =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()).ok();

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
                        if tx
                            .blocking_send(TerminalInput::Data(buf[..n].to_vec()))
                            .is_err()
                        {
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
            expected_pass: "my-secret-password".into(),
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
                password: "my-secret-password".into(),
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
        };

        let client_cfg = Arc::new(client::Config::default());
        let handler = SshClientHandler {
            host_id: host.host_key_id(),
            storage: Arc::clone(&storage),
            quiet_key_changed: None,
        };
        let mut session = client::connect(client_cfg, ("127.0.0.1", port), handler)
            .await
            .unwrap();
        authenticate(&mut session, &host).await.unwrap();
        let _ = session
            .disconnect(Disconnect::ByApplication, "", "en")
            .await;

        // Verify TOFU fingerprint was persisted
        let known = storage.load_known_hosts().unwrap();
        assert!(known.contains_key(&host.host_key_id()));

        // 3. Wrong password must fail cleanly
        let bad_host = SshHost {
            auth: AuthMethod::Password {
                password: "wrong-password".into(),
            },
            ..host
        };
        let client_cfg2 = Arc::new(client::Config::default());
        let handler2 = SshClientHandler {
            host_id: bad_host.host_key_id(),
            storage: Arc::clone(&storage),
            quiet_key_changed: None,
        };
        let mut session2 = client::connect(client_cfg2, ("127.0.0.1", port), handler2)
            .await
            .unwrap();
        assert!(authenticate(&mut session2, &bad_host).await.is_err());

        // 4. Background (quiet) connection with the saved password works silently
        let good_host = SshHost {
            auth: AuthMethod::Password {
                password: "my-secret-password".into(),
            },
            ..bad_host
        };
        let quiet = connect_quiet(&good_host, Arc::clone(&storage))
            .await
            .unwrap();
        let _ = quiet.disconnect(Disconnect::ByApplication, "", "en").await;

        // 5. A changed host key is refused without any prompt and reported as HostKeyChanged
        let mut known = storage.load_known_hosts().unwrap();
        if let Some(entry) = known.get_mut(&good_host.host_key_id()) {
            entry.fingerprint = "SHA256:not-the-real-key".into();
        }
        storage.save_known_hosts(&known).unwrap();
        let err = match connect_quiet(&good_host, Arc::clone(&storage)).await {
            Ok(_) => panic!("a changed host key must be refused"),
            Err(e) => e,
        };
        assert!(err.downcast_ref::<HostKeyChanged>().is_some());

        server_task.abort();
    }
}
