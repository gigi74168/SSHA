//! Interface language handling: supported languages, system language detection,
//! first-start language picker and plural helpers.

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::{Frame, Terminal};
use std::io;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    En,
    Fr,
    Ru,
    Uk,
    Es,
    It,
}

impl Lang {
    pub const ALL: [Lang; 6] = [Lang::En, Lang::Fr, Lang::Ru, Lang::Uk, Lang::Es, Lang::It];

    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Fr => "fr",
            Lang::Ru => "ru",
            Lang::Uk => "uk",
            Lang::Es => "es",
            Lang::It => "it",
        }
    }

    /// Language name written in the language itself.
    pub fn native_name(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::Fr => "Français",
            Lang::Ru => "Русский",
            Lang::Uk => "Українська",
            Lang::Es => "Español",
            Lang::It => "Italiano",
        }
    }

    /// Parses a language code or a full locale (`fr`, `fr_FR.UTF-8`, `uk-UA`, `ES`).
    pub fn from_code(code: &str) -> Option<Lang> {
        let lower = code.trim().to_ascii_lowercase();
        let primary = lower.split(['_', '-', '.', '@']).next().unwrap_or_default();
        match primary {
            "en" => Some(Lang::En),
            "fr" => Some(Lang::Fr),
            "ru" => Some(Lang::Ru),
            "uk" | "ua" => Some(Lang::Uk),
            "es" => Some(Lang::Es),
            "it" => Some(Lang::It),
            _ => None,
        }
    }

    pub fn index(self) -> usize {
        Lang::ALL.iter().position(|l| *l == self).unwrap_or(0)
    }
}

/// Detects the operating system language (Windows, macOS, Linux), falling back to English.
pub fn detect_system_lang() -> Lang {
    for var in ["LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"] {
        if let Ok(v) = std::env::var(var) {
            if v.is_empty() || v == "C" || v == "POSIX" || v.starts_with("C.") {
                continue;
            }
            for part in v.split(':') {
                if let Some(lang) = Lang::from_code(part) {
                    return lang;
                }
            }
        }
    }
    sys_locale::get_locales()
        .find_map(|l| Lang::from_code(&l))
        .unwrap_or(Lang::En)
}

/// Language forced through the `SSHA_LANG` environment variable, if any.
pub fn env_override() -> Option<Lang> {
    std::env::var("SSHA_LANG")
        .ok()
        .and_then(|v| Lang::from_code(&v))
}

pub fn set_lang(lang: Lang) {
    rust_i18n::set_locale(lang.code());
}

pub fn current_lang() -> Lang {
    Lang::from_code(&rust_i18n::locale()).unwrap_or(Lang::En)
}

/// Plural category of `n` for the current language: `one`, `few` or `many`.
/// English, Spanish and Italian use one/many; French treats 0 and 1 as singular;
/// Russian and Ukrainian use the three Slavic forms.
pub fn plural_category(lang: Lang, n: u64) -> &'static str {
    match lang {
        Lang::Ru | Lang::Uk => {
            let n10 = n % 10;
            let n100 = n % 100;
            if n10 == 1 && n100 != 11 {
                "one"
            } else if (2..=4).contains(&n10) && !(12..=14).contains(&n100) {
                "few"
            } else {
                "many"
            }
        }
        Lang::Fr => {
            if n <= 1 {
                "one"
            } else {
                "many"
            }
        }
        _ => {
            if n == 1 {
                "one"
            } else {
                "many"
            }
        }
    }
}

/// Translates a key built at runtime (the `t!` macro is meant for literal keys).
pub fn tr(key: &str) -> String {
    crate::_rust_i18n_translate(&rust_i18n::locale(), key).into_owned()
}

/// Translates a pluralised key: looks up `{key}.one|few|many` and replaces `%{count}`.
/// Extra `%{name}` placeholders can be passed in `args`.
pub fn tn(key: &str, count: u64, args: &[(&str, &str)]) -> String {
    let category = plural_category(current_lang(), count);
    let mut text = tr(&format!("{key}.{category}"));
    text = text.replace("%{count}", &count.to_string());
    for (name, value) in args {
        text = text.replace(&format!("%{{{name}}}"), value);
    }
    text
}

/// Returns `true` if the answer means "yes" in any supported language.
pub fn is_yes(answer: &str) -> bool {
    matches!(
        answer.trim().to_lowercase().as_str(),
        "y" | "yes" | "o" | "oui" | "д" | "да" | "т" | "так" | "s" | "si" | "sí"
    )
}

/// Returns `true` if an empty answer or any "yes" word was typed (default = yes).
pub fn is_yes_default(answer: &str) -> bool {
    answer.trim().is_empty() || is_yes(answer)
}

/// Draws the language selection box (shared by the first-start screen and the `/lang` modal).
pub fn draw_lang_picker(frame: &mut Frame, area: Rect, selected: usize, detected: Lang) {
    let width = 52.min(area.width);
    let height = (Lang::ALL.len() as u16 + 5).min(area.height);
    let rect = Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    };

    let mut lines = vec![Line::raw("")];
    for (i, lang) in Lang::ALL.iter().enumerate() {
        let is_sel = i == selected;
        let marker = if is_sel { " ▸ " } else { "   " };
        let style = if is_sel {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        let mut spans = vec![
            Span::styled(marker, style),
            Span::styled(format!("{:<14}", lang.native_name()), style),
            Span::styled(
                format!("{:<4}", lang.code()),
                Style::default().fg(Color::DarkGray),
            ),
        ];
        if *lang == detected {
            spans.push(Span::styled(
                format!("({})", t!("lang.detected", locale = lang.code())),
                Style::default().fg(Color::Green),
            ));
        }
        lines.push(Line::from(spans));
    }
    lines.push(Line::raw(""));
    lines.push(Line::from(Span::styled(
        "↑/↓ · Enter ✓ · Esc",
        Style::default().fg(Color::DarkGray),
    )));

    let current = Lang::ALL[selected.min(Lang::ALL.len() - 1)];
    let title = format!(" 🌐 {} ", t!("lang.title", locale = current.code()));

    let widget = Paragraph::new(lines).block(
        Block::default()
            .title(Span::styled(
                title,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ))
            .title_alignment(Alignment::Center)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(Clear, rect);
    frame.render_widget(widget, rect);
}

/// Applies a key press to the picker selection. Returns `Some(Some(lang))` when confirmed,
/// `Some(None)` when cancelled, `None` to keep the picker open.
pub fn handle_lang_picker_key(
    selected: &mut usize,
    code: KeyCode,
    modifiers: KeyModifiers,
) -> Option<Option<Lang>> {
    let len = Lang::ALL.len();
    match code {
        KeyCode::Up | KeyCode::Char('k') => {
            *selected = (*selected + len - 1) % len;
            None
        }
        KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
            *selected = (*selected + 1) % len;
            None
        }
        KeyCode::Char(c @ '1'..='6') => {
            *selected = (c as usize) - ('1' as usize);
            None
        }
        KeyCode::Enter => Some(Some(Lang::ALL[*selected])),
        KeyCode::Esc => Some(None),
        KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => Some(None),
        _ => None,
    }
}

/// Full-screen language picker shown on first start. Returns `None` if cancelled
/// (the caller then keeps the detected language for this run without saving it).
pub fn run_first_start_picker(detected: Lang) -> io::Result<Option<Lang>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let result = (|| -> io::Result<Option<Lang>> {
        let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        let mut selected = detected.index();
        loop {
            terminal.draw(|f| {
                let area = f.area();
                draw_lang_picker(f, area, selected, detected);
            })?;
            if !event::poll(Duration::from_millis(200))? {
                continue;
            }
            let Event::Key(key) = event::read()? else {
                continue;
            };
            if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                continue;
            }
            if let Some(choice) = handle_lang_picker_key(&mut selected, key.code, key.modifiers) {
                return Ok(choice);
            }
        }
    })();
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn parses_locale_codes() {
        assert_eq!(Lang::from_code("fr_FR.UTF-8"), Some(Lang::Fr));
        assert_eq!(Lang::from_code("uk-UA"), Some(Lang::Uk));
        assert_eq!(Lang::from_code("ES"), Some(Lang::Es));
        assert_eq!(Lang::from_code("ru"), Some(Lang::Ru));
        assert_eq!(Lang::from_code("de_DE"), None);
    }

    #[test]
    fn slavic_plurals() {
        assert_eq!(plural_category(Lang::Ru, 1), "one");
        assert_eq!(plural_category(Lang::Ru, 3), "few");
        assert_eq!(plural_category(Lang::Ru, 5), "many");
        assert_eq!(plural_category(Lang::Ru, 11), "many");
        assert_eq!(plural_category(Lang::Uk, 22), "few");
        assert_eq!(plural_category(Lang::Uk, 21), "one");
        assert_eq!(plural_category(Lang::Fr, 0), "one");
        assert_eq!(plural_category(Lang::En, 0), "many");
    }

    #[test]
    fn yes_words() {
        assert!(is_yes("oui"));
        assert!(is_yes("Y"));
        assert!(is_yes("да"));
        assert!(is_yes("так"));
        assert!(is_yes("sí"));
        assert!(!is_yes("n"));
        assert!(is_yes_default(""));
    }

    fn placeholders(text: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let mut rest = text;
        while let Some(start) = rest.find("%{") {
            let after = &rest[start + 2..];
            if let Some(end) = after.find('}') {
                out.insert(after[..end].to_string());
                rest = &after[end + 1..];
            } else {
                break;
            }
        }
        out
    }

    /// Every key must exist in all 6 languages with the same placeholders.
    #[test]
    fn all_locales_have_all_keys_and_placeholders() {
        let backend = crate::_rust_i18n_backend();
        let mut per_lang: BTreeMap<&str, BTreeMap<String, String>> = BTreeMap::new();
        for lang in Lang::ALL {
            let msgs = backend
                .messages_for_locale(lang.code())
                .unwrap_or_default()
                .into_iter()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            per_lang.insert(lang.code(), msgs);
        }
        let en = &per_lang["en"];
        assert!(!en.is_empty(), "no English translations loaded");
        let mut problems = Vec::new();
        for lang in Lang::ALL {
            let msgs = &per_lang[lang.code()];
            for (key, en_text) in en {
                // Plural forms `few` are only meaningful for Slavic languages but must exist everywhere.
                match msgs.get(key) {
                    None => problems.push(format!("[{}] missing key {key}", lang.code())),
                    Some(text) => {
                        if placeholders(text) != placeholders(en_text) {
                            problems.push(format!(
                                "[{}] placeholder mismatch for {key}: {:?} vs {:?}",
                                lang.code(),
                                placeholders(text),
                                placeholders(en_text)
                            ));
                        }
                    }
                }
            }
            for key in msgs.keys() {
                if !en.contains_key(key) {
                    problems.push(format!("[{}] extra key {key} not in en", lang.code()));
                }
            }
        }
        assert!(problems.is_empty(), "{}", problems.join("\n"));
    }
}
