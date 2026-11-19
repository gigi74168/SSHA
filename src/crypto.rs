use aes_gcm::{
    aead::{Aead, Generate, Key, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

const VAULT_MAGIC: &[u8; 4] = b"SSHA";
const VAULT_FORMAT_VERSION: u8 = 1;
const VAULT_AAD: &[u8] = b"SSHA-VAULT-V1";
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

#[cfg(windows)]
const DPAPI_PREFIX: &[u8; 6] = b"DPAPI1";

/// Encrypts plaintext using AES-256-GCM with an automatically managed 256-bit key.
pub fn encrypt_vault(plaintext: &[u8], key: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow!("Impossible d'initialiser le chiffrement AES-256-GCM: {e}"))?;

    let nonce = Nonce::generate();
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: VAULT_AAD,
            },
        )
        .map_err(|e| anyhow!("Erreur lors du chiffrement du coffre-fort: {e}"))?;

    let mut output = Vec::with_capacity(4 + 1 + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(VAULT_MAGIC);
    output.push(VAULT_FORMAT_VERSION);
    output.extend_from_slice(nonce.as_slice());
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypts an encrypted `vault.enc` payload using the automatically managed 256-bit key.
pub fn decrypt_vault(data: &[u8], key: &[u8; KEY_LEN]) -> Result<Zeroizing<Vec<u8>>> {
    let header_len = 4 + 1 + NONCE_LEN;
    if data.len() < header_len + 16 {
        bail!("Fichier coffre-fort invalide ou tronqué.");
    }
    if &data[0..4] != VAULT_MAGIC {
        bail!("Signature de coffre-fort invalide (fichier corrompu ou non reconnu).");
    }
    if data[4] != VAULT_FORMAT_VERSION {
        bail!(
            "Version de coffre-fort non supportée: {} (attendu {}).",
            data[4],
            VAULT_FORMAT_VERSION
        );
    }

    let nonce_bytes: [u8; NONCE_LEN] = data[5..header_len]
        .try_into()
        .map_err(|_| anyhow!("Nonce invalide"))?;
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = &data[header_len..];

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow!("Impossible d'initialiser le déchiffrement AES-256-GCM: {e}"))?;

    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: VAULT_AAD,
            },
        )
        .map_err(|_| {
            anyhow!("Échec du déchiffrement du coffre-fort (clé incorrecte ou fichier altéré).")
        })?;

    Ok(Zeroizing::new(plaintext))
}

/// Loads the automatic encryption key from disk, or generates and persists a new one if absent.
///
/// - On Windows: protected transparently with DPAPI (`CryptProtectData`), bound to the current user.
/// - On Linux/Unix: stored with strict `0600` file permissions in the user's config directory.
pub fn load_or_create_key(key_path: &Path) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if key_path.exists() {
        let raw = fs::read(key_path)
            .with_context(|| format!("Impossible de lire la clé: {}", key_path.display()))?;
        return unwrap_key(&raw);
    }

    let generated = Key::<Aes256Gcm>::generate();
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(generated.as_slice());

    let protected = wrap_key(&key)?;
    write_secret_file(key_path, &protected)?;
    Ok(key)
}

#[cfg(unix)]
fn wrap_key(key: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    Ok(key.to_vec())
}

#[cfg(unix)]
fn unwrap_key(raw: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if raw.len() != KEY_LEN {
        bail!(
            "Fichier clé invalide ({} octets au lieu de {}).",
            raw.len(),
            KEY_LEN
        );
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(raw);
    Ok(key)
}

#[cfg(windows)]
fn wrap_key(key: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: key.len() as u32,
        pbData: key.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    let ok = unsafe {
        CryptProtectData(
            &input,
            ptr::null(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };

    if ok == 0 || output.pbData.is_null() {
        bail!("Échec de la protection de clé via Windows DPAPI.");
    }

    let protected_slice =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) };
    let mut result = Vec::with_capacity(DPAPI_PREFIX.len() + protected_slice.len());
    result.extend_from_slice(DPAPI_PREFIX);
    result.extend_from_slice(protected_slice);

    unsafe {
        LocalFree(output.pbData as *mut _);
    }

    Ok(result)
}

#[cfg(windows)]
fn unwrap_key(raw: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    if !raw.starts_with(DPAPI_PREFIX) {
        if raw.len() == KEY_LEN {
            let mut key = Zeroizing::new([0u8; KEY_LEN]);
            key.copy_from_slice(raw);
            return Ok(key);
        }
        bail!("Format de fichier clé Windows non reconnu.");
    }

    let blob = &raw[DPAPI_PREFIX.len()..];
    let input = CRYPT_INTEGER_BLOB {
        cbData: blob.len() as u32,
        pbData: blob.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    let ok = unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };

    if ok == 0 || output.pbData.is_null() {
        bail!("Échec du déchiffrement de clé via Windows DPAPI.");
    }

    let unprotected = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) };
    if unprotected.len() != KEY_LEN {
        unsafe {
            LocalFree(output.pbData as *mut _);
        }
        bail!("Taille de clé déchiffrée invalide.");
    }

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(unprotected);

    unsafe {
        LocalFree(output.pbData as *mut _);
    }

    Ok(key)
}

pub fn write_secret_file(path: &Path, content: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("Impossible d'écrire {}", path.display()))?;
        file.write_all(content)?;
        file.sync_all()?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        fs::write(path, content)
            .with_context(|| format!("Impossible d'écrire {}", path.display()))?;
        Ok(())
    }
}

pub fn protection_summary() -> &'static str {
    #[cfg(windows)]
    {
        "AES-256-GCM + clé automatique protégée par Windows DPAPI"
    }
    #[cfg(unix)]
    {
        "AES-256-GCM + clé automatique locale (permissions 0600)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join(".vault.key");
        let key = load_or_create_key(&key_path).unwrap();

        let plaintext = b"{\"hosts\":[{\"name\":\"pc\",\"password\":\"s3cr3t\"}]}";
        let encrypted = encrypt_vault(plaintext, &key).unwrap();
        assert_ne!(encrypted.as_slice(), plaintext);
        assert!(encrypted.starts_with(VAULT_MAGIC));

        let loaded_key = load_or_create_key(&key_path).unwrap();
        assert_eq!(&*key, &*loaded_key);

        let decrypted = decrypt_vault(&encrypted, &loaded_key).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn detects_tampered_ciphertext() {
        let key = [42u8; KEY_LEN];
        let mut encrypted = encrypt_vault(b"secret", &key).unwrap();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        assert!(decrypt_vault(&encrypted, &key).is_err());
    }
}
