mod webauthn;

use anyhow::{Result, anyhow};
use bitcoin::{Network, PrivateKey};
use hkdf::Hkdf;
use log::{Level, debug, error};
use sha2::Sha256;
use web_sys::js_sys::futures::spawn_local;

fn main() -> Result<()> {
    let _ = console_log::init_with_level(Level::Debug);

    spawn_local(async {
        if let Err(err) = get_creds().await {
            error!("error get credentials: {}", err);
        }
    });

    Ok(())
}

async fn get_creds() -> Result<()> {
    let window = web_sys::window().ok_or(anyhow!("missing window")).unwrap();
    let cred_container = window.navigator().credentials();
    let storage_container = window
        .local_storage()
        .unwrap()
        .expect("Storage not available");

    let prf_data = webauthn::get_prf_data(&storage_container, &cred_container).await?;
    debug!("prf_data: {}", hex::encode(&prf_data));

    let app_root_key = derive_key::<32>(&prf_data, "app-root-key")?;
    let wallet_root_key = derive_key::<32>(&app_root_key, "wallet-root-key")?;

    let master_key = PrivateKey::from_slice(&wallet_root_key, Network::Bitcoin)?;
    debug!("master key: {}", master_key);

    Ok(())
}

fn derive_key<const L: usize>(ikm: &[u8], name: &str) -> Result<[u8; L]> {
    let key = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0_u8; L];
    key.expand(name.as_bytes(), &mut okm)?;
    Ok(okm)
}
