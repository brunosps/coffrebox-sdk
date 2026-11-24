use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use coffrebox_core::trust::TrustStore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

const KEYRING_SERVICE: &str = "coffrebox";
const KEYRING_USER: &str = "active-session";

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct StoredCliSession {
    pub server_url: String,
    pub email: String,
    #[zeroize(skip)]
    pub user_id: Uuid,
    pub access_token: String,
    pub enc_sk_b64: String,
    pub sign_seed_b64: String,
    pub fingerprint: String,
}

fn fallback_session_path() -> PathBuf {
    if let Ok(explicit) = std::env::var("COFFREBOX_SESSION_FILE")
        && !explicit.trim().is_empty()
    {
        return PathBuf::from(explicit);
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME")
        && !xdg.trim().is_empty()
    {
        return PathBuf::from(xdg).join("coffrebox").join("session.json");
    }
    if let Ok(home) = std::env::var("HOME")
        && !home.trim().is_empty()
    {
        return PathBuf::from(home)
            .join(".config")
            .join("coffrebox")
            .join("session.json");
    }
    std::env::temp_dir().join("coffrebox-session.json")
}

fn keyring_disabled() -> bool {
    std::env::var("COFFREBOX_NO_KEYRING").as_deref() == Ok("1")
        || std::env::var("COFFREBOX_SESSION_FILE").is_ok()
}

pub fn save_session(session: &StoredCliSession) -> Result<()> {
    let raw = serde_json::to_string(session).context("falha ao serializar sessão")?;

    if !keyring_disabled()
        && let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        && entry.set_password(&raw).is_ok()
    {
        return Ok(());
    }

    let path = fallback_session_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&path)?;
        f.write_all(raw.as_bytes())?;
        f.sync_all()?;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, raw.as_bytes())?;
    }

    eprintln!(
        "Aviso: chaveiro do sistema indisponível; sessão salva em {} com permissão 0600.",
        path.display()
    );
    Ok(())
}

pub fn load_session() -> Result<StoredCliSession> {
    if !keyring_disabled()
        && let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        && let Ok(raw) = entry.get_password()
    {
        return serde_json::from_str(&raw).context("sessão inválida no chaveiro do sistema");
    }

    let path = fallback_session_path();
    let raw = std::fs::read_to_string(&path).with_context(
        || "Nenhuma sessão ativa encontrada. Execute `coffre login` ou `coffre signup`.",
    )?;
    serde_json::from_str(&raw).context("arquivo de sessão corrompido")
}

pub fn clear_session() {
    if !keyring_disabled()
        && let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
    {
        let _ = entry.delete_credential();
    }
    let path = fallback_session_path();
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
}

/// Arquivo com as âncoras de confiança (chave do dono fixada, revisões já vistas) desta conta.
///
/// Fica ao lado do arquivo de sessão e sobrevive ao `coffre logout`: é ele que permite recusar a
/// troca silenciosa da chave do dono de um vault compartilhado e a volta no tempo.
pub fn trust_store_path(user_id: Uuid) -> PathBuf {
    if let Ok(explicit) = std::env::var("COFFREBOX_TRUST_FILE")
        && !explicit.trim().is_empty()
    {
        return PathBuf::from(explicit);
    }
    let session = fallback_session_path();
    let dir = session
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(std::env::temp_dir);
    dir.join(format!("confianca-{user_id}.json"))
}

pub fn load_trust_store(user_id: Uuid) -> Result<TrustStore> {
    let path = trust_store_path(user_id);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(TrustStore::new(user_id)),
        Err(e) => {
            return Err(e).with_context(|| format!("falha ao ler {}", path.display()));
        }
    };
    let store: TrustStore = serde_json::from_str(&raw)
        .with_context(|| format!("estado de confiança corrompido em {}", path.display()))?;
    store
        .validate_for(user_id)
        .with_context(|| format!("estado de confiança inválido em {}", path.display()))?;
    Ok(store)
}

pub fn save_trust_store(store: &TrustStore) -> Result<()> {
    let path = trust_store_path(store.user_id);
    let raw =
        serde_json::to_vec_pretty(store).context("falha ao serializar estado de confiança")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&raw)?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp, &raw)?;
    }
    std::fs::rename(&tmp, &path).with_context(|| format!("falha ao gravar {}", path.display()))?;
    Ok(())
}
