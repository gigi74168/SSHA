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
const VAULT_FORMAT_MASTER_V2: u8 = 2;
const VAULT_AAD: &[u8] = b"SSHA-VAULT-V1";
const VAULT_AAD_V2: &[u8] = b"SSHA-VAULT-V2";
const NONCE_LEN: usize = 12;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;

#[cfg(windows)]
const DPAPI_PREFIX: &[u8; 6] = b"DPAPI1";

/// Returns true if the encrypted vault blob uses optional Master Password mode (format v2).
pub fn is_master_password_vault(data: &[u8]) -> bool {
    data.len() >= 5 && &data[0..4] == VAULT_MAGIC && data[4] == VAULT_FORMAT_MASTER_V2
}

fn derive_master_key(password: &str, salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2::Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|e| anyhow!(t!("crypto.err.argon2", error = e).into_owned()))?;
    Ok(key)
}

/// Encrypts plaintext using AES-256-GCM with an Argon2id key derived from the user's master password.
pub fn encrypt_vault_with_password(plaintext: &[u8], password: &str) -> Result<Vec<u8>> {
    let generated_salt = Key::<Aes256Gcm>::generate();
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&generated_salt.as_slice()[..SALT_LEN]);

    let key = derive_master_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&*key)
        .map_err(|e| anyhow!(t!("crypto.err.cipher_init", error = e).into_owned()))?;

    let nonce = Nonce::generate();
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: VAULT_AAD_V2,
            },
        )
        .map_err(|e| anyhow!(t!("crypto.err.encrypt", error = e).into_owned()))?;

    let mut output = Vec::with_capacity(4 + 1 + SALT_LEN + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(VAULT_MAGIC);
    output.push(VAULT_FORMAT_MASTER_V2);
    output.extend_from_slice(&salt);
    output.extend_from_slice(nonce.as_slice());
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypts a v2 master-password-protected `vault.enc` payload.
pub fn decrypt_vault_with_password(data: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>> {
    let header_len = 4 + 1 + SALT_LEN + NONCE_LEN;
    if data.len() < header_len + 16 {
        bail!(t!("crypto.err.truncated").into_owned());
    }
    if &data[0..4] != VAULT_MAGIC || data[4] != VAULT_FORMAT_MASTER_V2 {
        bail!(t!("crypto.err.master_format").into_owned());
    }

    let salt: [u8; SALT_LEN] = data[5..5 + SALT_LEN]
        .try_into()
        .map_err(|_| anyhow!("Sel Argon2 invalide"))?;
    let nonce_bytes: [u8; NONCE_LEN] = data[5 + SALT_LEN..header_len]
        .try_into()
        .map_err(|_| anyhow!("Nonce invalide"))?;
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = &data[header_len..];

    let key = derive_master_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&*key)
        .map_err(|e| anyhow!(t!("crypto.err.cipher_init", error = e).into_owned()))?;

    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: VAULT_AAD_V2,
            },
        )
        .map_err(|_| anyhow!(t!("crypto.err.wrong_master").into_owned()))?;

    Ok(Zeroizing::new(plaintext))
}

/// Encrypts plaintext using AES-256-GCM with an automatically managed 256-bit key.
pub fn encrypt_vault(plaintext: &[u8], key: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow!(t!("crypto.err.cipher_init", error = e).into_owned()))?;

    let nonce = Nonce::generate();
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: VAULT_AAD,
            },
        )
        .map_err(|e| anyhow!(t!("crypto.err.encrypt", error = e).into_owned()))?;

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
        bail!(t!("crypto.err.truncated").into_owned());
    }
    if &data[0..4] != VAULT_MAGIC {
        bail!(t!("crypto.err.signature").into_owned());
    }
    if data[4] != VAULT_FORMAT_VERSION {
        bail!(t!(
            "crypto.err.version",
            found = data[4],
            expected = VAULT_FORMAT_VERSION
        )
        .into_owned());
    }

    let nonce_bytes: [u8; NONCE_LEN] = data[5..header_len]
        .try_into()
        .map_err(|_| anyhow!("Nonce invalide"))?;
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = &data[header_len..];

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow!(t!("crypto.err.cipher_init", error = e).into_owned()))?;

    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: VAULT_AAD,
            },
        )
        .map_err(|_| anyhow!(t!("crypto.err.decrypt").into_owned()))?;

    Ok(Zeroizing::new(plaintext))
}

/// Loads the automatic encryption key from disk, or generates and persists a new one if absent.
///
/// - On Windows: protected transparently with DPAPI (`CryptProtectData`), bound to the current user.
/// - On Linux/Unix: stored with strict `0600` file permissions in the user's config directory.
pub fn load_or_create_key(key_path: &Path) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if key_path.exists() {
        let raw = fs::read(key_path)
            .with_context(|| t!("crypto.err.read_key", path = key_path.display()).into_owned())?;
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
        bail!(t!("crypto.err.key_size", found = raw.len(), expected = KEY_LEN).into_owned());
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
        bail!(t!("crypto.err.dpapi_protect").into_owned());
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
        bail!(t!("crypto.err.dpapi_format").into_owned());
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
        bail!(t!("crypto.err.dpapi_unprotect").into_owned());
    }

    let unprotected = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) };
    if unprotected.len() != KEY_LEN {
        unsafe {
            LocalFree(output.pbData as *mut _);
        }
        bail!(t!("crypto.err.decrypted_key_size").into_owned());
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
            .with_context(|| t!("common.err.write", path = path.display()).into_owned())?;
        file.write_all(content)?;
        file.sync_all()?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        fs::write(path, content)
            .with_context(|| t!("common.err.write", path = path.display()).into_owned())?;
        Ok(())
    }
}

pub fn protection_summary() -> String {
    #[cfg(windows)]
    {
        t!("crypto.summary_windows").into_owned()
    }
    #[cfg(unix)]
    {
        t!("crypto.summary_unix").into_owned()
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

    #[test]
    fn master_password_roundtrip_and_wrong_password_rejected() {
        let plaintext = b"{\"hosts\":[{\"name\":\"srv\"}]}";
        let enc = encrypt_vault_with_password(plaintext, "my-master-pass").unwrap();
        assert!(is_master_password_vault(&enc));

        let dec = decrypt_vault_with_password(&enc, "my-master-pass").unwrap();
        assert_eq!(dec.as_slice(), plaintext);

        assert!(decrypt_vault_with_password(&enc, "mauvais-mdp").is_err());
    }
}
