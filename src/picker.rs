use std::path::PathBuf;

/// Result of invoking a native OS file/folder picker dialog.
pub enum PickerResult {
    /// User selected a path.
    Selected(PathBuf),
    /// User cancelled the dialog.
    Cancelled,
    /// No GUI picker is available on this system (e.g. headless Linux TTY); caller should fall back to CLI input.
    Unavailable,
}

/// Opens a native OS file picker dialog to select an existing file.
pub fn pick_file(title: &str, filter: Option<(&str, &str)>) -> PickerResult {
    #[cfg(windows)]
    {
        windows_pick_file(title, filter)
    }
    #[cfg(target_os = "macos")]
    {
        macos_pick_file(title, filter)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        unix_pick_file(title, filter)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (title, filter);
        PickerResult::Unavailable
    }
}

/// Opens a native OS folder picker dialog to select an existing directory.
pub fn pick_folder(title: &str) -> PickerResult {
    #[cfg(windows)]
    {
        windows_pick_folder(title)
    }
    #[cfg(target_os = "macos")]
    {
        macos_pick_folder(title)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        unix_pick_folder(title)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = title;
        PickerResult::Unavailable
    }
}

/// Opens a native OS "Save File" dialog to choose an export destination.
pub fn pick_save_file(
    title: &str,
    default_name: &str,
    filter: Option<(&str, &str)>,
) -> PickerResult {
    #[cfg(windows)]
    {
        windows_pick_save_file(title, default_name, filter)
    }
    #[cfg(target_os = "macos")]
    {
        macos_pick_save_file(title, default_name, filter)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        unix_pick_save_file(title, default_name, filter)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (title, default_name, filter);
        PickerResult::Unavailable
    }
}

#[cfg(windows)]
fn ps_escape(s: &str) -> String {
    s.replace('\'', "''")
}

#[cfg(windows)]
fn run_powershell_dialog(script: &str) -> PickerResult {
    use std::process::Command;

    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-STA", "-Command", script])
        .output();

    let Ok(out) = output else {
        return PickerResult::Unavailable;
    };
    if !out.status.success() {
        return PickerResult::Unavailable;
    }

    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if stdout.is_empty() {
        PickerResult::Cancelled
    } else {
        PickerResult::Selected(PathBuf::from(stdout))
    }
}

#[cfg(windows)]
fn windows_pick_file(title: &str, filter: Option<(&str, &str)>) -> PickerResult {
    let filter_str = match filter {
        Some((label, pattern)) => format!("{label}|{pattern}|{} (*.*)|*.*", t!("picker.all_files")),
        None => format!("{} (*.*)|*.*", t!("picker.all_files")),
    };
    let script = format!(
        r#"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()
$owner = New-Object System.Windows.Forms.Form
$owner.TopMost = $true
$dlg = New-Object System.Windows.Forms.OpenFileDialog
$dlg.Title = '{}'
$dlg.Filter = '{}'
$dlg.Multiselect = $false
if ($dlg.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) {{
    Write-Output $dlg.FileName
}}
$owner.Dispose()"#,
        ps_escape(title),
        ps_escape(&filter_str)
    );
    run_powershell_dialog(&script)
}

#[cfg(windows)]
fn windows_pick_folder(title: &str) -> PickerResult {
    let script = format!(
        r#"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()
$owner = New-Object System.Windows.Forms.Form
$owner.TopMost = $true
$dlg = New-Object System.Windows.Forms.FolderBrowserDialog
$dlg.Description = '{}'
$dlg.UseDescriptionForTitle = $true
$dlg.ShowNewFolderButton = $true
if ($dlg.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) {{
    Write-Output $dlg.SelectedPath
}}
$owner.Dispose()"#,
        ps_escape(title)
    );
    run_powershell_dialog(&script)
}

#[cfg(windows)]
fn windows_pick_save_file(
    title: &str,
    default_name: &str,
    filter: Option<(&str, &str)>,
) -> PickerResult {
    let filter_str = match filter {
        Some((label, pattern)) => format!("{label}|{pattern}|{} (*.*)|*.*", t!("picker.all_files")),
        None => format!("{} (*.*)|*.*", t!("picker.all_files")),
    };
    let script = format!(
        r#"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()
$owner = New-Object System.Windows.Forms.Form
$owner.TopMost = $true
$dlg = New-Object System.Windows.Forms.SaveFileDialog
$dlg.Title = '{}'
$dlg.FileName = '{}'
$dlg.Filter = '{}'
$dlg.OverwritePrompt = $true
if ($dlg.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) {{
    Write-Output $dlg.FileName
}}
$owner.Dispose()"#,
        ps_escape(title),
        ps_escape(default_name),
        ps_escape(&filter_str)
    );
    run_powershell_dialog(&script)
}

#[cfg(target_os = "macos")]
fn applescript_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(target_os = "macos")]
fn run_osascript(script: &str) -> PickerResult {
    use std::process::Command;

    let out = match Command::new("osascript").args(["-e", script]).output() {
        Ok(o) => o,
        Err(_) => return PickerResult::Unavailable,
    };
    if out.status.success() {
        let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if path.is_empty() {
            PickerResult::Cancelled
        } else {
            PickerResult::Selected(PathBuf::from(path))
        }
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("-128") || stderr.to_lowercase().contains("cancel") {
            PickerResult::Cancelled
        } else {
            PickerResult::Unavailable
        }
    }
}

#[cfg(target_os = "macos")]
fn macos_pick_file(title: &str, _filter: Option<(&str, &str)>) -> PickerResult {
    let script = format!(
        r#"POSIX path of (choose file with prompt "{}")"#,
        applescript_escape(title)
    );
    run_osascript(&script)
}

#[cfg(target_os = "macos")]
fn macos_pick_folder(title: &str) -> PickerResult {
    let script = format!(
        r#"POSIX path of (choose folder with prompt "{}")"#,
        applescript_escape(title)
    );
    run_osascript(&script)
}

#[cfg(target_os = "macos")]
fn macos_pick_save_file(
    title: &str,
    default_name: &str,
    _filter: Option<(&str, &str)>,
) -> PickerResult {
    let script = format!(
        r#"POSIX path of (choose file name with prompt "{}" default name "{}")"#,
        applescript_escape(title),
        applescript_escape(default_name)
    );
    run_osascript(&script)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn has_graphical_session() -> bool {
    std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some()
}

#[cfg(all(unix, not(target_os = "macos")))]
fn run_unix_cmd(bin: &str, args: &[String]) -> Option<PickerResult> {
    use std::process::Command;

    let out = Command::new(bin).args(args).output().ok()?;
    if out.status.success() {
        let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if path.is_empty() {
            Some(PickerResult::Cancelled)
        } else {
            Some(PickerResult::Selected(PathBuf::from(path)))
        }
    } else if out.status.code() == Some(1) {
        Some(PickerResult::Cancelled)
    } else {
        None
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn unix_pick_file(title: &str, filter: Option<(&str, &str)>) -> PickerResult {
    if !has_graphical_session() {
        return PickerResult::Unavailable;
    }

    let mut zenity_args = vec!["--file-selection".to_string(), format!("--title={title}")];
    if let Some((label, pattern)) = filter {
        zenity_args.push(format!("--file-filter={label} | {pattern}"));
        zenity_args.push(format!("--file-filter={} | *", t!("picker.all_files")));
    }
    if let Some(res) = run_unix_cmd("zenity", &zenity_args) {
        return res;
    }

    let kdialog_filter = filter
        .map(|(label, pattern)| format!("{pattern}|{label}"))
        .unwrap_or_else(|| format!("*|{}", t!("picker.all_files")));
    let kdialog_args = vec![
        "--getopenfilename".to_string(),
        ".".to_string(),
        kdialog_filter,
        "--title".to_string(),
        title.to_string(),
    ];
    if let Some(res) = run_unix_cmd("kdialog", &kdialog_args) {
        return res;
    }

    PickerResult::Unavailable
}

#[cfg(all(unix, not(target_os = "macos")))]
fn unix_pick_folder(title: &str) -> PickerResult {
    if !has_graphical_session() {
        return PickerResult::Unavailable;
    }

    let zenity_args = vec![
        "--file-selection".to_string(),
        "--directory".to_string(),
        format!("--title={title}"),
    ];
    if let Some(res) = run_unix_cmd("zenity", &zenity_args) {
        return res;
    }

    let kdialog_args = vec![
        "--getexistingdirectory".to_string(),
        ".".to_string(),
        "--title".to_string(),
        title.to_string(),
    ];
    if let Some(res) = run_unix_cmd("kdialog", &kdialog_args) {
        return res;
    }

    PickerResult::Unavailable
}

#[cfg(all(unix, not(target_os = "macos")))]
fn unix_pick_save_file(
    title: &str,
    default_name: &str,
    filter: Option<(&str, &str)>,
) -> PickerResult {
    if !has_graphical_session() {
        return PickerResult::Unavailable;
    }

    let mut zenity_args = vec![
        "--file-selection".to_string(),
        "--save".to_string(),
        "--confirm-overwrite".to_string(),
        format!("--filename={default_name}"),
        format!("--title={title}"),
    ];
    if let Some((label, pattern)) = filter {
        zenity_args.push(format!("--file-filter={label} | {pattern}"));
    }
    if let Some(res) = run_unix_cmd("zenity", &zenity_args) {
        return res;
    }

    let kdialog_args = vec![
        "--getsavefilename".to_string(),
        default_name.to_string(),
        "--title".to_string(),
        title.to_string(),
    ];
    if let Some(res) = run_unix_cmd("kdialog", &kdialog_args) {
        return res;
    }

    PickerResult::Unavailable
}
