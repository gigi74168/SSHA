# Changelog

Toutes les évolutions notables de **`ssha`** sont documentées dans ce fichier.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le [Versionnage Sémantique](https://semver.org/lang/fr/).

## [0.9.0] — 2026-11-20
### Ajouté
- **Support complet macOS** (Apple Silicon `aarch64` & Intel `x86_64`) : binaires précompilés dans GitHub Releases, détection automatique dans `install.sh`, auto-updater Mach-O, boîtes de dialogue Finder natives (`osascript`), et CI sur `macos-latest`.
- **Import OpenSSH depuis `~/.ssh/config`** : nouvelle commande `ssha import-ssh [chemin]` et `/import-ssh` dans la TUI (gère `Host`, `HostName`, `Port`, `User`, multiples `IdentityFile`, `ProxyJump`, `LocalForward`, `ForwardAgent`).
- **Options SSH avancées** :
  - **ProxyJump / Bastion** (`-J` / `--proxy-jump` ou importé depuis `~/.ssh/config`) avec support de rebonds chaînés.
  - **Port Forwarding local** (`-L local_port:remote_host:remote_port`, répétable).
  - **Fallback multi-clés** (`IdentityFile` multiples).
- **Mode mot de passe maître optionnel** (`ssha security enable-master-password` / `disable-master-password` / `status`) basé sur **Argon2id + AES-256-GCM** pour un `vault.enc` 100 % portable entre machines, tout en conservant le mode clé automatique sans mot de passe par défaut.
- **Documentation & communauté** : `CHANGELOG.md`, `CONTRIBUTING.md`, badges GitHub/CI/Release/Licence dans le `README.md`, description et topics GitHub.

## [0.8.0] — 2026-11-20
### Ajouté
- **Autocomplétion des noms de machines** : popup de suggestions au-dessus de la barre de saisie dès les premières lettres tapées (et après `/files `, `/connect `, `/edit `, `/del `, `/test `), complétion par **`Tab`**, navigation `↑`/`↓` et aperçu grisé en ligne.

## [0.7.0] — 2026-11-20
### Ajouté
- **Import / Export complet de la configuration** (`ssha export` / `ssha import` et `/export` / `/import`) incluant IP, ports, utilisateurs, mots de passe, clés, groupes et notes.
- **Fenêtres natives de sélection de fichier et de dossier** (Windows Explorateur, Linux `zenity`/`kdialog`, repli CLI en mode headless) pour envoyer et télécharger fichiers et dossiers récursivement dans les deux sens.

## [0.6.0] — 2026-11-20
### Ajouté
- **Détection et installation automatique de SFTP** sur les machines Linux distantes lors de la première connexion SFTP (`apt`, `pacman`, `dnf`, `yum`, `apk`, `zypper`, `opkg` + activation `Subsystem sftp internal-sftp` et rechargement `sshd`).

## [0.5.0] — 2026-11-20
### Ajouté
- **Statut `UP` / `DOWN` en temps réel** à côté de chaque IP + voyant **`●` vert / rouge** tout à droite (vérification TCP parallèle non bloquante au lancement, actualisée toutes les 15 s ou via `Ctrl+R` / `F5` / `/refresh`), également disponible dans `ssha list`.

## [0.4.0] — 2026-11-20
### Ajouté
- **Détection automatique des mises à jour GitHub** au lancement avec proposition directe dans le terminal (`[O/n]`) et remplacement atomique de l'exécutable via `self-replace` (Windows & Linux), plus commande `ssha update`.

## [0.3.1] — 2026-11-19
### Corrigé
- Support des touches **AltGr** (`\`, `~`, `@`, `[`, `]`) sur claviers AZERTY Windows dans les modales SFTP.
- Nettoyage automatique des guillemets copiés depuis l'Explorateur Windows (`"C:\..."`) et du préfixe PowerShell `& '...'`.
- Expansion de `~` sur les chemins distants SFTP et affichage complet des causes d'erreur.

## [0.3.0] — 2026-11-19
### Ajouté
- **Gestionnaire de fichiers distant SFTP intégré** (`Ctrl+F`, `/files`, `ssha files`) : navigation, aperçu texte scrollable, téléchargement récursif (`Ctrl+D` / `ssha get`), envoi récursif (`Ctrl+U` / `ssha put`), création de dossier, renommage et suppression récursive.

## [0.2.0] — 2026-11-19
### Modifié
- Renommage de la commande et du package `ssh-a` en **`ssha`**.

## [0.1.0] — 2026-11-19
### Ajouté
- Première version publique : interface 100 % CLI/TUI en Rust (`ratatui`), client SSH natif (`russh`), coffre-fort chiffré automatique AES-256-GCM (DPAPI Windows / `0600` Linux), installateurs Windows & Linux, CI/CD GitHub Actions.
