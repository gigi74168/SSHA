# Registro delle modifiche

Tutte le modifiche rilevanti di **`ssha`** sono documentate in questo file.

Il formato segue [Keep a Changelog](https://keepachangelog.com/it-IT/1.1.0/) e il [Versionamento Semantico](https://semver.org/lang/it/). I titoli delle sezioni restano in inglese (`Added`, `Fixed`, `Changed`) perché `ssha` li legge per mostrare le novità ✨ e le correzioni 🐛.

## [0.10.0] — 2026-11-24
### Added
- **Monitoraggio CPU/RAM in tempo reale** accanto a ogni macchina nell'elenco (`CPU 34% · RAM 71% (2,8/4 GB)`, aggiornato ogni 2 s, verde / giallo / rosso in base al carico).
  - Attivabile per singola macchina: casella `Monitora CPU/RAM` nel modulo, `Ctrl+P` o `/monitor [nome]` nell'interfaccia, `ssha new --monitor` da riga di comando.
  - Macchine Linux (lettura di `/proc`); gli altri sistemi mostrano `n/d`. `SSHA_NO_MONITOR=1` lo disattiva ovunque.
- **6 lingue dell'interfaccia**: English, Français, Русский, Українська, Español, Italiano.
  - Scelta della lingua al primo avvio, preselezionata sulla lingua di sistema.
  - Modificabile in qualsiasi momento con `/lang`, `ssha lang <codice>` o la variabile d'ambiente `SSHA_LANG`.
  - Anche `ssha --help` è tradotto.
- **Note di rilascio nell'aggiornamento**: la proposta di aggiornamento elenca ora le novità ✨ e le correzioni 🐛 di ogni versione che stai per ricevere, nella tua lingua.
- **Schermata «Novità»** mostrata una volta al primo avvio dopo un aggiornamento, più `ssha changelog` e `/changelog` per rivederla.
### Fixed
- Le connessioni SSH in background non possono più stampare testo né fare domande sopra l'interfaccia (verifica silenziosa dell'impronta; una chiave modificata viene rifiutata e mostrata come `⚠ chiave`).
### Changed
- Il repository, la documentazione e gli installer sono ora in inglese; il registro delle modifiche è disponibile nelle 6 lingue.
- Le release di GitHub usano ora la sezione corrispondente di `CHANGELOG.md` come descrizione.

## [0.9.0] — 2026-11-20
### Added
- **Supporto completo per macOS** (Apple Silicon `aarch64` e Intel `x86_64`): binari precompilati in GitHub Releases, rilevamento automatico in `install.sh`, aggiornamento automatico Mach-O, finestre native del Finder (`osascript`) e CI su `macos-latest`.
- **Importazione OpenSSH da `~/.ssh/config`**: nuovo comando `ssha import-ssh [percorso]` e `/import-ssh` nell'interfaccia (gestisce `Host`, `HostName`, `Port`, `User`, più `IdentityFile`, `ProxyJump`, `LocalForward`, `ForwardAgent`).
- **Opzioni SSH avanzate**:
  - **ProxyJump / Bastion** (`-J` / `--proxy-jump` o importato da `~/.ssh/config`) con salti concatenati.
  - **Inoltro di porta locale** (`-L local_port:remote_host:remote_port`, ripetibile).
  - **Più chiavi di riserva** (più `IdentityFile`).
- **Modalità password principale facoltativa** (`ssha security enable-master-password` / `disable-master-password` / `status`) basata su **Argon2id + AES-256-GCM** per un `vault.enc` portabile al 100% tra macchine, mantenendo di default la modalità chiave automatica senza password.
- **Documentazione e community**: `CHANGELOG.md`, `CONTRIBUTING.md`, badge GitHub/CI/Release/licenza nel `README.md`, descrizione e topic GitHub.

## [0.8.0] — 2026-11-20
### Added
- **Completamento automatico dei nomi delle macchine**: popup di suggerimenti sopra la barra di input fin dalle prime lettere (e dopo `/files `, `/connect `, `/edit `, `/del `, `/test `), completamento con **`Tab`**, navigazione `↑`/`↓` e anteprima in grigio.

## [0.7.0] — 2026-11-20
### Added
- **Importazione / esportazione completa della configurazione** (`ssha export` / `ssha import` e `/export` / `/import`) con IP, porte, utenti, password, chiavi, gruppi e note.
- **Finestre native di selezione di file e cartelle** (Esplora file di Windows, Linux `zenity`/`kdialog`, modalità testo senza interfaccia grafica) per inviare e scaricare file e cartelle in modo ricorsivo in entrambe le direzioni.

## [0.6.0] — 2026-11-20
### Added
- **Rilevamento e installazione automatica di SFTP** sulle macchine Linux remote alla prima connessione SFTP (`apt`, `pacman`, `dnf`, `yum`, `apk`, `zypper`, `opkg` + attivazione di `Subsystem sftp internal-sftp` e ricarica di `sshd`).

## [0.5.0] — 2026-11-20
### Added
- **Stato `UP` / `DOWN` in tempo reale** accanto a ogni IP + indicatore **`●`** verde / rosso all'estrema destra (verifica TCP parallela non bloccante all'avvio, aggiornata ogni 15 s o con `Ctrl+R` / `F5` / `/refresh`), disponibile anche in `ssha list`.

## [0.4.0] — 2026-11-20
### Added
- **Rilevamento automatico degli aggiornamenti su GitHub** all'avvio con proposta direttamente nel terminale (`[S/n]`) e sostituzione atomica dell'eseguibile tramite `self-replace` (Windows e Linux), più il comando `ssha update`.

## [0.3.1] — 2026-11-19
### Fixed
- Supporto dei tasti **AltGr** (`\`, `~`, `@`, `[`, `]`) sulle tastiere AZERTY di Windows nelle finestre SFTP.
- Pulizia automatica delle virgolette copiate da Esplora file di Windows (`"C:\..."`) e del prefisso PowerShell `& '...'`.
- Espansione di `~` nei percorsi SFTP remoti e visualizzazione completa delle cause di errore.

## [0.3.0] — 2026-11-19
### Added
- **File manager SFTP remoto integrato** (`Ctrl+F`, `/files`, `ssha files`): navigazione, anteprima di testo scorrevole, download ricorsivo (`Ctrl+D` / `ssha get`), invio ricorsivo (`Ctrl+U` / `ssha put`), creazione di cartelle, rinomina ed eliminazione ricorsiva.

## [0.2.0] — 2026-11-19
### Changed
- Comando e pacchetto rinominati da `ssh-a` a **`ssha`**.

## [0.1.0] — 2026-11-19
### Added
- Prima versione pubblica: interfaccia 100% CLI/TUI in Rust (`ratatui`), client SSH nativo (`russh`), cassaforte cifrata automatica AES-256-GCM (DPAPI su Windows / `0600` su Linux), installer per Windows e Linux, CI/CD con GitHub Actions.
