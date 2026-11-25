# Journal des modifications

Toutes les évolutions notables de **`ssha`** sont documentées dans ce fichier.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le [Versionnage Sémantique](https://semver.org/lang/fr/). Les titres de section restent en anglais (`Added`, `Fixed`, `Changed`) car `ssha` les lit pour afficher les nouveautés ✨ et correctifs 🐛.

## [0.10.0] — 2026-11-24
### Added
- **Monitoring CPU/RAM en direct** à côté de chaque machine dans la liste (`CPU 34% · RAM 71% (2,8/4 Go)`, actualisé toutes les 2 s, vert / jaune / rouge selon la charge).
  - Activable par machine : case `Surveiller CPU/RAM` dans le formulaire, `Ctrl+P` ou `/monitor [nom]` dans l'interface, `ssha new --monitor` en ligne de commande.
  - Machines Linux (lecture de `/proc`) ; les autres systèmes affichent `n/d`. `SSHA_NO_MONITOR=1` le désactive partout.
- **6 langues d'interface** : English, Français, Русский, Українська, Español, Italiano.
  - Choix de la langue au premier démarrage, pré-sélectionnée sur la langue du système.
  - Modifiable à tout moment avec `/lang`, `ssha lang <code>` ou la variable d'environnement `SSHA_LANG`.
  - `ssha --help` est traduit lui aussi.
- **Notes de version dans la mise à jour** : la proposition de mise à jour liste les nouveautés ✨ et correctifs 🐛 de chaque version que tu vas recevoir, dans ta langue.
- **Écran « Quoi de neuf »** affiché une fois au premier lancement après une mise à jour, plus `ssha changelog` et `/changelog` pour le revoir.
### Fixed
- Les connexions SSH en arrière-plan ne peuvent plus afficher de texte ni poser de question par-dessus l'interface (vérification silencieuse de l'empreinte ; une clé modifiée est refusée et affichée `⚠ clé`).
### Changed
- Le dépôt, la documentation et les installateurs sont désormais en anglais ; le journal des modifications est disponible dans les 6 langues.
- Les releases GitHub utilisent maintenant la section correspondante de `CHANGELOG.md` comme description.

## [0.9.0] — 2026-11-20
### Added
- **Support complet macOS** (Apple Silicon `aarch64` & Intel `x86_64`) : binaires précompilés dans GitHub Releases, détection automatique dans `install.sh`, auto-updater Mach-O, boîtes de dialogue Finder natives (`osascript`), et CI sur `macos-latest`.
- **Import OpenSSH depuis `~/.ssh/config`** : nouvelle commande `ssha import-ssh [chemin]` et `/import-ssh` dans la TUI (gère `Host`, `HostName`, `Port`, `User`, multiples `IdentityFile`, `ProxyJump`, `LocalForward`, `ForwardAgent`).
- **Options SSH avancées** :
  - **ProxyJump / Bastion** (`-J` / `--proxy-jump` ou importé depuis `~/.ssh/config`) avec support de rebonds chaînés.
  - **Port Forwarding local** (`-L local_port:remote_host:remote_port`, répétable).
  - **Fallback multi-clés** (`IdentityFile` multiples).
- **Mode mot de passe maître optionnel** (`ssha security enable-master-password` / `disable-master-password` / `status`) basé sur **Argon2id + AES-256-GCM** pour un `vault.enc` 100 % portable entre machines, tout en conservant le mode clé automatique sans mot de passe par défaut.
- **Documentation & communauté** : `CHANGELOG.md`, `CONTRIBUTING.md`, badges GitHub/CI/Release/Licence dans le `README.md`, description et topics GitHub.

## [0.8.0] — 2026-11-20
### Added
- **Autocomplétion des noms de machines** : popup de suggestions au-dessus de la barre de saisie dès les premières lettres tapées (et après `/files `, `/connect `, `/edit `, `/del `, `/test `), complétion par **`Tab`**, navigation `↑`/`↓` et aperçu grisé en ligne.

## [0.7.0] — 2026-11-20
### Added
- **Import / Export complet de la configuration** (`ssha export` / `ssha import` et `/export` / `/import`) incluant IP, ports, utilisateurs, mots de passe, clés, groupes et notes.
- **Fenêtres natives de sélection de fichier et de dossier** (Windows Explorateur, Linux `zenity`/`kdialog`, repli CLI en mode headless) pour envoyer et télécharger fichiers et dossiers récursivement dans les deux sens.

## [0.6.0] — 2026-11-20
### Added
- **Détection et installation automatique de SFTP** sur les machines Linux distantes lors de la première connexion SFTP (`apt`, `pacman`, `dnf`, `yum`, `apk`, `zypper`, `opkg` + activation `Subsystem sftp internal-sftp` et rechargement `sshd`).

## [0.5.0] — 2026-11-20
### Added
- **Statut `UP` / `DOWN` en temps réel** à côté de chaque IP + voyant **`●` vert / rouge** tout à droite (vérification TCP parallèle non bloquante au lancement, actualisée toutes les 15 s ou via `Ctrl+R` / `F5` / `/refresh`), également disponible dans `ssha list`.

## [0.4.0] — 2026-11-20
### Added
- **Détection automatique des mises à jour GitHub** au lancement avec proposition directe dans le terminal (`[O/n]`) et remplacement atomique de l'exécutable via `self-replace` (Windows & Linux), plus commande `ssha update`.

## [0.3.1] — 2026-11-19
### Fixed
- Support des touches **AltGr** (`\`, `~`, `@`, `[`, `]`) sur claviers AZERTY Windows dans les modales SFTP.
- Nettoyage automatique des guillemets copiés depuis l'Explorateur Windows (`"C:\..."`) et du préfixe PowerShell `& '...'`.
- Expansion de `~` sur les chemins distants SFTP et affichage complet des causes d'erreur.

## [0.3.0] — 2026-11-19
### Added
- **Gestionnaire de fichiers distant SFTP intégré** (`Ctrl+F`, `/files`, `ssha files`) : navigation, aperçu texte scrollable, téléchargement récursif (`Ctrl+D` / `ssha get`), envoi récursif (`Ctrl+U` / `ssha put`), création de dossier, renommage et suppression récursive.

## [0.2.0] — 2026-11-19
### Changed
- Renommage de la commande et du package `ssh-a` en **`ssha`**.

## [0.1.0] — 2026-11-19
### Added
- Première version publique : interface 100 % CLI/TUI en Rust (`ratatui`), client SSH natif (`russh`), coffre-fort chiffré automatique AES-256-GCM (DPAPI Windows / `0600` Linux), installateurs Windows & Linux, CI/CD GitHub Actions.
