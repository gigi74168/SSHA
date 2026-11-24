//! Live CPU/RAM monitoring of the machines that have `monitor` enabled.
//!
//! One background task per monitored machine keeps a quiet SSH session open and reads
//! `/proc/stat` + `/proc/meminfo` every [`POLL_INTERVAL`]. Results are sent to the TUI
//! through a channel, exactly like the UP/DOWN ping.

use crate::models::SshHost;
use crate::ssh::{connect_quiet, exec_remote_command, HostKeyChanged};
use crate::storage::Storage;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

pub const POLL_INTERVAL: Duration = Duration::from_secs(2);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const EXEC_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PARALLEL_CONNECTS: usize = 8;
const RETRY_MIN: Duration = Duration::from_secs(5);
const RETRY_MAX: Duration = Duration::from_secs(30);
const KEY_CHANGED_RETRY: Duration = Duration::from_secs(60);

/// Single remote command, POSIX `sh` compatible, Linux `/proc` based.
const REMOTE_COMMAND: &str = "head -n 1 /proc/stat; grep -E '^(MemTotal|MemAvailable|MemFree|Buffers|Cached):' /proc/meminfo";

#[derive(Clone, Debug, PartialEq)]
pub struct HostMetrics {
    /// `None` until two CPU samples have been taken.
    pub cpu_pct: Option<f32>,
    pub mem_used: u64,
    pub mem_total: u64,
}

impl HostMetrics {
    pub fn mem_pct(&self) -> f32 {
        if self.mem_total == 0 {
            0.0
        } else {
            (self.mem_used as f64 / self.mem_total as f64 * 100.0) as f32
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum MetricsState {
    Connecting,
    Ok(HostMetrics),
    /// The remote system has no Linux `/proc` (macOS, BSD, Windows...).
    Unsupported,
    /// The server host key changed: refused without asking (connect once manually).
    KeyChanged,
    /// Connection or authentication error (message for the status bar).
    Failed(String),
}

/// CPU counters of the `cpu` line of `/proc/stat`: (total, idle + iowait).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuSample {
    pub total: u64,
    pub idle: u64,
}

pub fn parse_proc_stat(text: &str) -> Option<CpuSample> {
    let line = text.lines().find(|l| l.starts_with("cpu "))?;
    let values: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|v| v.parse().ok())
        .collect();
    if values.len() < 4 {
        return None;
    }
    // user nice system idle iowait irq softirq steal (guest values are already in user/nice)
    let total: u64 = values.iter().take(8).sum();
    let idle = values[3] + values.get(4).copied().unwrap_or(0);
    Some(CpuSample { total, idle })
}

/// Returns `(used_bytes, total_bytes)` from `/proc/meminfo` lines.
pub fn parse_meminfo(text: &str) -> Option<(u64, u64)> {
    let mut fields: HashMap<&str, u64> = HashMap::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(key), Some(value)) = (parts.next(), parts.next()) else {
            continue;
        };
        if let Ok(kb) = value.parse::<u64>() {
            fields.insert(key.trim_end_matches(':'), kb);
        }
    }
    let total = *fields.get("MemTotal")?;
    if total == 0 {
        return None;
    }
    let available = fields.get("MemAvailable").copied().unwrap_or_else(|| {
        fields.get("MemFree").copied().unwrap_or(0)
            + fields.get("Buffers").copied().unwrap_or(0)
            + fields.get("Cached").copied().unwrap_or(0)
    });
    let used = total.saturating_sub(available.min(total));
    Some((used * 1024, total * 1024))
}

/// CPU usage in percent between two samples.
pub fn cpu_usage(prev: CpuSample, cur: CpuSample) -> Option<f32> {
    let total = cur.total.checked_sub(prev.total)?;
    let idle = cur.idle.checked_sub(prev.idle)?;
    if total == 0 {
        return None;
    }
    Some(((total.saturating_sub(idle)) as f64 / total as f64 * 100.0).clamp(0.0, 100.0) as f32)
}

/// Formats a byte count as GiB with at most one decimal (`2.8`, `16`), using the
/// decimal separator of the active language.
pub fn format_gib(bytes: u64) -> String {
    format_gib_with(bytes, &t!("monitor.decimal_sep"))
}

fn format_gib_with(bytes: u64, decimal_sep: &str) -> String {
    let gib = bytes as f64 / (1024.0 * 1024.0 * 1024.0);
    let text = if gib >= 10.0 || (gib - gib.round()).abs() < 0.05 {
        format!("{:.0}", gib.round())
    } else {
        format!("{gib:.1}")
    };
    text.replace('.', decimal_sep)
}

/// Monitoring can be disabled globally with `SSHA_NO_MONITOR=1`.
pub fn globally_disabled() -> bool {
    std::env::var("SSHA_NO_MONITOR")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false)
}

struct Running {
    config_hash: u64,
    handle: JoinHandle<()>,
}

/// Owns one background task per monitored machine. Dropping it stops all tasks
/// (and closes their SSH sessions).
pub struct MonitorManager {
    storage: Arc<Storage>,
    tx: mpsc::Sender<(String, MetricsState)>,
    running: HashMap<String, Running>,
    semaphore: Arc<Semaphore>,
}

fn config_hash(host: &SshHost) -> u64 {
    let mut hasher = DefaultHasher::new();
    host.host.hash(&mut hasher);
    host.port.hash(&mut hasher);
    host.username.hash(&mut hasher);
    host.proxy_jump.hash(&mut hasher);
    host.extra_keys.hash(&mut hasher);
    // Hash the auth method without keeping another copy of the secret.
    serde_json::to_string(&host.auth)
        .unwrap_or_default()
        .hash(&mut hasher);
    hasher.finish()
}

impl MonitorManager {
    pub fn new(storage: Arc<Storage>, tx: mpsc::Sender<(String, MetricsState)>) -> Self {
        Self {
            storage,
            tx,
            running: HashMap::new(),
            semaphore: Arc::new(Semaphore::new(MAX_PARALLEL_CONNECTS)),
        }
    }

    /// Starts, restarts or stops tasks so that exactly the machines with `monitor == true` are watched.
    pub fn sync(&mut self, hosts: &[SshHost]) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let wanted: HashMap<&str, &SshHost> = hosts
            .iter()
            .filter(|h| h.monitor)
            .map(|h| (h.name.as_str(), h))
            .collect();

        self.running.retain(|name, run| {
            let keep = wanted
                .get(name.as_str())
                .map(|h| config_hash(h) == run.config_hash)
                .unwrap_or(false);
            if !keep {
                run.handle.abort();
            }
            keep
        });

        for (name, host) in wanted {
            if self.running.contains_key(name) {
                continue;
            }
            let host = host.clone();
            let storage = Arc::clone(&self.storage);
            let tx = self.tx.clone();
            let semaphore = Arc::clone(&self.semaphore);
            let config_hash = config_hash(&host);
            let task = handle.spawn(monitor_host(host, storage, tx, semaphore));
            self.running.insert(
                name.to_string(),
                Running {
                    config_hash,
                    handle: task,
                },
            );
        }
    }

    pub fn is_running(&self, name: &str) -> bool {
        self.running.contains_key(name)
    }
}

impl Drop for MonitorManager {
    fn drop(&mut self) {
        for run in self.running.values() {
            run.handle.abort();
        }
    }
}

fn short_error(err: &anyhow::Error) -> String {
    // Keep the most specific cause, on one line, for the status bar.
    err.chain()
        .last()
        .map(|e| e.to_string())
        .unwrap_or_else(|| err.to_string())
        .lines()
        .next()
        .unwrap_or_default()
        .to_string()
}

async fn monitor_host(
    host: SshHost,
    storage: Arc<Storage>,
    tx: mpsc::Sender<(String, MetricsState)>,
    semaphore: Arc<Semaphore>,
) {
    let name = host.name.clone();
    let send = |state: MetricsState| tx.send((name.clone(), state)).is_ok();
    let mut retry = RETRY_MIN;
    if !send(MetricsState::Connecting) {
        return;
    }

    loop {
        let connection = {
            let _permit = semaphore.acquire().await;
            tokio::time::timeout(CONNECT_TIMEOUT, connect_quiet(&host, Arc::clone(&storage))).await
        };

        let session = match connection {
            Ok(Ok(session)) => session,
            Ok(Err(err)) => {
                let (state, wait) = if err.downcast_ref::<HostKeyChanged>().is_some() {
                    (MetricsState::KeyChanged, KEY_CHANGED_RETRY)
                } else {
                    (MetricsState::Failed(short_error(&err)), retry)
                };
                if !send(state) {
                    return;
                }
                tokio::time::sleep(wait).await;
                retry = (retry * 2).min(RETRY_MAX);
                continue;
            }
            Err(_) => {
                if !send(MetricsState::Failed(t!("monitor.timeout").into_owned())) {
                    return;
                }
                tokio::time::sleep(retry).await;
                retry = (retry * 2).min(RETRY_MAX);
                continue;
            }
        };
        retry = RETRY_MIN;

        let mut previous: Option<CpuSample> = None;
        loop {
            let result = tokio::time::timeout(
                EXEC_TIMEOUT,
                exec_remote_command(&session, REMOTE_COMMAND, None),
            )
            .await;
            let output = match result {
                Ok(Ok((_, output))) => output,
                // Session lost or stuck: reconnect.
                _ => break,
            };
            let (Some(cpu), Some((mem_used, mem_total))) =
                (parse_proc_stat(&output), parse_meminfo(&output))
            else {
                let _ = send(MetricsState::Unsupported);
                return;
            };
            let cpu_pct = previous.and_then(|p| cpu_usage(p, cpu));
            previous = Some(cpu);
            if !send(MetricsState::Ok(HostMetrics {
                cpu_pct,
                mem_used,
                mem_total,
            })) {
                return;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }

        tokio::time::sleep(retry).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "cpu  4705 356 584 3699 23 23 0 0 0 0\nMemTotal:        4044044 kB\nMemFree:          612340 kB\nMemAvailable:    1170012 kB\nBuffers:          102400 kB\nCached:           800000 kB\n";

    #[test]
    fn parses_cpu_line() {
        let s = parse_proc_stat(SAMPLE).unwrap();
        assert_eq!(s.total, 4705 + 356 + 584 + 3699 + 23 + 23);
        assert_eq!(s.idle, 3699 + 23);
        assert!(parse_proc_stat("Darwin").is_none());
    }

    #[test]
    fn computes_cpu_delta() {
        let a = CpuSample {
            total: 1000,
            idle: 800,
        };
        let b = CpuSample {
            total: 1100,
            idle: 825,
        };
        let pct = cpu_usage(a, b).unwrap();
        assert!((pct - 75.0).abs() < 0.01);
        assert!(cpu_usage(b, a).is_none());
        assert!(cpu_usage(a, a).is_none());
    }

    #[test]
    fn parses_meminfo_with_and_without_available() {
        let (used, total) = parse_meminfo(SAMPLE).unwrap();
        assert_eq!(total, 4044044 * 1024);
        assert_eq!(used, (4044044 - 1170012) * 1024);

        let old_kernel = "MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 50 kB\nCached: 250 kB\n";
        let (used, total) = parse_meminfo(old_kernel).unwrap();
        assert_eq!(total, 1000 * 1024);
        assert_eq!(used, 600 * 1024);
        assert!(parse_meminfo("nope").is_none());
    }

    #[test]
    fn formats_gib() {
        assert_eq!(format_gib_with(4 * 1024 * 1024 * 1024, "."), "4");
        assert_eq!(format_gib_with(3006477107, "."), "2.8");
        assert_eq!(format_gib_with(3006477107, ","), "2,8");
        assert_eq!(
            format_gib_with(16 * 1024 * 1024 * 1024 + 300_000_000, "."),
            "16"
        );
    }

    #[test]
    fn metrics_percent() {
        let m = HostMetrics {
            cpu_pct: Some(10.0),
            mem_used: 50,
            mem_total: 200,
        };
        assert!((m.mem_pct() - 25.0).abs() < 0.01);
    }
}
