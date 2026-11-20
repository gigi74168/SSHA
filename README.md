# ssha

**`ssha`** est un gestionnaire de connexions SSH **100 % CLI** écrit en Rust, compatible **Windows 10 / 11** et **Linux** (Debian, Ubuntu, Arch, Fedora, etc.).

Enregistre tes machines une seule fois (ex. `192.168.1.192` + mot de passe ou clé SSH), puis reconnecte-toi instantanément sans retaper ton mot de passe — sans aucune dépendance externe (`sshpass` n'est pas nécessaire, le client SSH est 100 % natif en Rust).

---

## Captures d'écran

### Liste des connexions enregistrées (`ssha`)
![Liste des connexions SSH dans ssha](assets/screenshots/home.png)

### Commandes rapides avec autocomplétion (`/new`, `/edit`, `/del`, `/test`...)
![Menu des commandes slash dans ssha](assets/screenshots/slash-commands.png)

### Ajout d'une nouvelle machine (`/new`)
![Formulaire d'ajout d'une connexion SSH dans ssha](assets/screenshots/new-modal.png)

---

## Fonctionnalités

- **Interface 100 % CLI interactive (`ssha`)** :
  - Statut en direct **`UP` / `DOWN`** à côté de chaque IP + voyant **● vert / rouge** tout à droite (vérification non bloquante en parallèle, actualisée automatiquement toutes les 15 s ou via `Ctrl+R` / `F5` / `/refresh`)
  - Liste filtrable en temps réel (tape un nom, une IP ou un groupe)
  - Commandes slash intégrées avec autocomplétion (`Tab`) : `/new`, `/files`, `/edit`, `/del`, `/connect`, `/test`, `/refresh`, `/help`, `/quit`
  - Raccourcis clavier rapides (`↑`/`↓`, `Entrée`, `Ctrl+F`, `Ctrl+N`, `Ctrl+E`, `Ctrl+D`, `Ctrl+T`, `Ctrl+R`, `Esc`)
- **Gestionnaire de fichiers à distance (SFTP intégré)** :
  - **Installation automatique de SFTP** sur la machine Linux distante si le sous-système SFTP n'est pas encore installé ou activé (`apt`, `pacman`, `dnf`, `yum`, `apk`, `zypper`, `opkg` + activation `internal-sftp` & rechargement `sshd`)
  - Parcours des dossiers distants, filtrage live, fichiers cachés (`Ctrl+H`) et aperçu rapide des fichiers texte (`Entrée`)
  - **Téléchargement** de fichiers ou dossiers complets (récursif) vers n'importe où sur ton PC (`Ctrl+D` / `/download` avec bouton `Ctrl+P` / `F3` ouvrant la fenêtre de choix de dossier Windows/Linux, ou `ssha get`)
  - **Envoi** de fichiers ou dossiers complets (récursif) vers la machine distante avec **fenêtre native Windows / Linux de sélection de fichier ou dossier** (`Ctrl+U` / `/upload` / `/upload-dir` ou `ssha put`)
  - **Création de dossier** (`Ctrl+N` / `/mkdir`), **renommage** (`Ctrl+E` / `/rename`), **suppression** récursive sécurisée (`Ctrl+X` / `/del`)
- **Import / Export complet de la configuration** :
  - Exporte toutes tes connexions (IP, ports, utilisateurs, mots de passe, clés, groupes, notes) dans un fichier portable (`ssha export` ou `/export`) et réimporte-les sur un autre PC (`ssha import` ou `/import`) avec sélecteur de fichier natif Windows/Linux
- **Connexion directe** : `ssha mon-pc` te connecte sans même ouvrir le menu
- **Client SSH & SFTP natif multiplateforme** (`russh` + `russh-sftp`) :
  - Authentification par **mot de passe** (incluant `keyboard-interactive` / PAM) ou **clé privée SSH** (Ed25519, RSA, ECDSA + passphrase optionnelle)
  - PTY interactif complet (couleurs, `vim`, `nano`, `htop`, `tmux`, redimensionnement automatique de la fenêtre, AltGr sur claviers AZERTY Windows)
  - Vérification des empreintes serveurs (TOFU) avec alerte en cas de changement suspect
- **Mises à jour automatiques intégrées** :
  - Détecte automatiquement les nouvelles releases GitHub au lancement de `ssha` et propose de mettre à jour directement dans le terminal (`[O/n]`) — sans rien retaper (désactivable via `SSHA_NO_UPDATE_CHECK=1`)
  - Commande manuelle `ssha update` disponible à tout moment
- **Chiffrement automatique transparent** :
  - Tes connexions et mots de passe sont chiffrés dans `vault.enc` en **AES-256-GCM**
  - Clé générée et gérée automatiquement par le logiciel (**aucun mot de passe maître à gérer**) :
    - **Windows 10/11** : clé protégée par **Windows DPAPI** (liée à ta session utilisateur Windows)
    - **Linux** : clé locale protégée en permissions strictes `0600` dans `~/.config/ssha/`

---

## Installation (une seule fois, accessible partout)

### Windows 10 & 11 (PowerShell)

**Depuis GitHub Releases (sans avoir besoin de Rust) :**
```powershell
irm https://raw.githubusercontent.com/gigi74168/SSHA/main/installers/install.ps1 | iex
```

**Ou depuis ce dépôt cloné :**
Double-clique sur `installers\install.bat` ou lance dans PowerShell :
```powershell
.\installers\install.ps1
```
L'installateur copie `ssha.exe` dans `%LOCALAPPDATA%\Programs\ssha` et l'ajoute automatiquement à ton `PATH` utilisateur (aucun droit administrateur requis).

### Linux (Debian, Ubuntu, Arch, Fedora, etc.)

**Depuis GitHub Releases :**
```bash
curl -fsSL https://raw.githubusercontent.com/gigi74168/SSHA/main/installers/install.sh | bash
```

**Ou depuis ce dépôt cloné :**
```bash
chmod +x installers/install.sh
./installers/install.sh
```

**Ou directement avec Cargo (Linux & Windows) :**
```bash
cargo install --path .
```

---

## Utilisation

### 1. Lancer l'interface interactive
```bash
ssha
```

Dans l'interface :
- Tape **`/new`** (ou appuie sur `Ctrl+N`) pour ajouter une nouvelle machine (ex: nom `mon-pc`, IP `192.168.1.192`, utilisateur, mot de passe SSH).
- Utilise **`↑` / `↓`** (ou tape quelques lettres pour filtrer) puis appuie sur **`Entrée`** pour ouvrir le terminal SSH, ou **`Ctrl+F`** (ou `/files`) pour ouvrir le **gestionnaire de fichiers distant**.
- Dans le gestionnaire de fichiers :
  - `Ctrl+U` (`/upload`) ouvre le choix **Fichier (`F`) / Dossier (`D`)** avec la fenêtre native Windows/Linux et envoie directement
  - `Ctrl+D` (`/download`) télécharge le fichier ou dossier sélectionné (`Ctrl+P` / `F3` pour choisir le dossier de destination dans la fenêtre Windows/Linux)
  - `Entrée` ouvre un dossier ou affiche un aperçu texte, `Ctrl+N` (`/mkdir`) crée un dossier, `Ctrl+E` (`/rename`) renomme, `Ctrl+X` (`/del`) supprime.
- Tape **`/export`** ou **`/import`** pour sauvegarder ou transférer toutes tes connexions vers un autre PC.

### 2. Commandes directes depuis le terminal
```bash
ssha mon-pc                                    # Connexion SSH directe à "mon-pc"
ssha files mon-pc                              # Ouvrir l'explorateur de fichiers distant (SFTP)
ssha get mon-pc /home/gigi/rapport.pdf         # Télécharger un fichier/dossier dans Téléchargements
ssha get mon-pc /home/gigi/mon-dossier ./dest  # Télécharger un dossier récursivement où tu veux
ssha put mon-pc                                # Ouvrir la fenêtre Windows/Linux pour choisir un fichier à envoyer
ssha put mon-pc --dir                          # Ouvrir la fenêtre Windows/Linux pour choisir un dossier à envoyer
ssha put mon-pc ./mon-dossier /home/gigi/      # Envoyer un fichier/dossier local directement
ssha export                                    # Exporter toutes les connexions (IP, users, mdp) en JSON
ssha import                                    # Importer une config exportée depuis un autre ssha
ssha new                                       # Assistant d'ajout en ligne de commande
ssha list                                      # Lister les connexions avec statut UP/DOWN
ssha test mon-pc                               # Tester la joignabilité TCP + latence
ssha rm mon-pc                                 # Supprimer une connexion
ssha update                                    # Vérifier et installer la dernière version
ssha info                                      # Afficher l'emplacement du coffre-fort chiffré
```

---

## Emplacement des fichiers

| Système | Coffre-fort chiffré (`vault.enc`) |
|---|---|
| **Windows 10/11** | `%APPDATA%\ssha\config\` |
| **Linux** | `~/.config/ssha/` |

*(Tu peux aussi personnaliser le dossier via la variable d'environnement `SSHA_CONFIG_DIR`.)*

---

## Désinstallation

- **Windows** : `.\installers\uninstall.ps1` (ajouter `-Purge` pour supprimer aussi le coffre-fort)
- **Linux** : `./installers/uninstall.sh` (ajouter `--purge` pour supprimer aussi le coffre-fort)
