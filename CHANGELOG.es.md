# Registro de cambios

Todos los cambios destacados de **`ssha`** se documentan en este archivo.

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y el [Versionado Semántico](https://semver.org/lang/es/). Los títulos de sección se mantienen en inglés (`Added`, `Fixed`, `Changed`) porque `ssha` los lee para mostrar las novedades ✨ y correcciones 🐛.

## [0.10.0] — 2026-11-24
### Added
- **Monitorización de CPU/RAM en directo** junto a cada máquina de la lista (`CPU 34% · RAM 71% (2,8/4 GB)`, actualizada cada 2 s, verde / amarillo / rojo según la carga).
  - Se activa por máquina: casilla `Monitorizar CPU/RAM` en el formulario, `Ctrl+P` o `/monitor [nombre]` en la interfaz, `ssha new --monitor` en la línea de comandos.
  - Máquinas Linux (lectura de `/proc`); los demás sistemas muestran `n/d`. `SSHA_NO_MONITOR=1` la desactiva por completo.
- **6 idiomas de interfaz**: English, Français, Русский, Українська, Español, Italiano.
  - Selector de idioma en el primer arranque, preseleccionado en el idioma del sistema.
  - Se puede cambiar en cualquier momento con `/lang`, `ssha lang <código>` o la variable de entorno `SSHA_LANG`.
  - `ssha --help` también está traducido.
- **Notas de versión en el actualizador**: la propuesta de actualización muestra ahora las novedades ✨ y correcciones 🐛 de cada versión que vas a recibir, en tu idioma.
- **Pantalla «Novedades»** mostrada una vez en el primer arranque tras una actualización, además de `ssha changelog` y `/changelog` para volver a verla.
### Fixed
- Las conexiones SSH en segundo plano ya no pueden mostrar texto ni hacer preguntas encima de la interfaz (comprobación silenciosa de la huella; una clave modificada se rechaza y se muestra como `⚠ clave`).
### Changed
- El repositorio, la documentación y los instaladores están ahora en inglés; el registro de cambios está disponible en los 6 idiomas.
- Las releases de GitHub usan ahora la sección correspondiente de `CHANGELOG.md` como descripción.

## [0.9.0] — 2026-11-20
### Added
- **Soporte completo de macOS** (Apple Silicon `aarch64` e Intel `x86_64`): binarios precompilados en GitHub Releases, detección automática en `install.sh`, actualizador Mach-O, diálogos nativos de Finder (`osascript`) y CI en `macos-latest`.
- **Importación de OpenSSH desde `~/.ssh/config`**: nuevo comando `ssha import-ssh [ruta]` y `/import-ssh` en la interfaz (admite `Host`, `HostName`, `Port`, `User`, varios `IdentityFile`, `ProxyJump`, `LocalForward`, `ForwardAgent`).
- **Opciones SSH avanzadas**:
  - **ProxyJump / bastión** (`-J` / `--proxy-jump` o importado desde `~/.ssh/config`) con saltos encadenados.
  - **Redirección de puertos local** (`-L local_port:remote_host:remote_port`, repetible).
  - **Varias claves de respaldo** (varios `IdentityFile`).
- **Modo opcional de contraseña maestra** (`ssha security enable-master-password` / `disable-master-password` / `status`) basado en **Argon2id + AES-256-GCM** para un `vault.enc` 100 % portable entre máquinas, manteniendo por defecto el modo de clave automática sin contraseña.
- **Documentación y comunidad**: `CHANGELOG.md`, `CONTRIBUTING.md`, insignias de GitHub/CI/Release/licencia en `README.md`, descripción y temas de GitHub.

## [0.8.0] — 2026-11-20
### Added
- **Autocompletado de nombres de máquinas**: ventana de sugerencias encima de la barra de entrada desde las primeras letras (y tras `/files `, `/connect `, `/edit `, `/del `, `/test `), completado con **`Tab`**, navegación `↑`/`↓` y vista previa en gris.

## [0.7.0] — 2026-11-20
### Added
- **Importación / exportación completa de la configuración** (`ssha export` / `ssha import` y `/export` / `/import`) con IP, puertos, usuarios, contraseñas, claves, grupos y notas.
- **Ventanas nativas de selección de archivos y carpetas** (Explorador de Windows, Linux `zenity`/`kdialog`, modo texto sin interfaz gráfica) para enviar y descargar archivos y carpetas de forma recursiva en ambos sentidos.

## [0.6.0] — 2026-11-20
### Added
- **Detección e instalación automática de SFTP** en máquinas Linux remotas en la primera conexión SFTP (`apt`, `pacman`, `dnf`, `yum`, `apk`, `zypper`, `opkg` + activación de `Subsystem sftp internal-sftp` y recarga de `sshd`).

## [0.5.0] — 2026-11-20
### Added
- **Estado `UP` / `DOWN` en tiempo real** junto a cada IP + indicador **`●`** verde / rojo a la derecha (comprobación TCP paralela no bloqueante al arrancar, actualizada cada 15 s o con `Ctrl+R` / `F5` / `/refresh`), también en `ssha list`.

## [0.4.0] — 2026-11-20
### Added
- **Detección automática de actualizaciones en GitHub** al arrancar, con propuesta directa en el terminal (`[S/n]`) y sustitución atómica del ejecutable mediante `self-replace` (Windows y Linux), además del comando `ssha update`.

## [0.3.1] — 2026-11-19
### Fixed
- Soporte de las teclas **AltGr** (`\`, `~`, `@`, `[`, `]`) en teclados AZERTY de Windows en las ventanas SFTP.
- Limpieza automática de las comillas copiadas desde el Explorador de Windows (`"C:\..."`) y del prefijo de PowerShell `& '...'`.
- Expansión de `~` en las rutas SFTP remotas y visualización completa de las causas de error.

## [0.3.0] — 2026-11-19
### Added
- **Gestor de archivos SFTP remoto integrado** (`Ctrl+F`, `/files`, `ssha files`): navegación, vista previa de texto desplazable, descarga recursiva (`Ctrl+D` / `ssha get`), envío recursivo (`Ctrl+U` / `ssha put`), creación de carpetas, cambio de nombre y borrado recursivo.

## [0.2.0] — 2026-11-19
### Changed
- El comando y el paquete pasan de `ssh-a` a **`ssha`**.

## [0.1.0] — 2026-11-19
### Added
- Primera versión pública: interfaz 100 % CLI/TUI en Rust (`ratatui`), cliente SSH nativo (`russh`), bóveda cifrada automática AES-256-GCM (DPAPI en Windows / `0600` en Linux), instaladores para Windows y Linux, CI/CD con GitHub Actions.
