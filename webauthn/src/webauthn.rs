use anyhow::{Result, anyhow, bail};
use base64::prelude::*;
use log::debug;
use web_sys::js_sys::{Array, Uint8Array};
use web_sys::*;

#[repr(i32)]
enum AlgoIdentifier {
    EdDSA = -8,
    ES256 = -7,
    RS256 = -257,
}

const CREDENTIAL_ID_FIELD: &str = "credential_id";
const ROOT_KEY_V1_NAMESPACE: &str = "credential.v1";

fn log_credential(cred: &PublicKeyCredential) {
    debug!("credential {} {}", cred.type_(), cred.id());
}

pub async fn get_prf_data(
    storage_container: &Storage,
    cred_container: &CredentialsContainer,
) -> Result<Vec<u8>> {
    let cred_id = storage_container
        .get_item(CREDENTIAL_ID_FIELD)
        .map_err(|err| anyhow!("error getting public key credentials: {:?}", err))?;
    let cred_id = match cred_id {
        Some(cred_id) => cred_id,
        None => {
            let cred = create_credential(cred_container).await?;
            log_credential(&cred);

            let Some(prf) = cred.get_client_extension_results().get_prf() else {
                bail!("prf is not supported by this device")
            };

            // The create() call will return "enabled: true" if PRF is supported when creds created.
            // If it's not, we need to run a get() as well.
            let enabled = prf.get_enabled().unwrap_or_default();

            if enabled && let Some(results) = prf.get_results() {
                return Ok(Uint8Array::new(&results.get_first()).to_vec());
            } else {
                cred.id()
            }
        }
    };

    // Either we already created a credential or the device doesn't support PRF at creation time.
    let cred = get_credential(&cred_container, &cred_id).await?;
    log_credential(&cred);

    let Some(prf) = cred.get_client_extension_results().get_prf() else {
        bail!("prf is not supported by this device")
    };

    let Some(results) = prf.get_results() else {
        bail!("no prf results were returned")
    };

    Ok(Uint8Array::new(&results.get_first()).to_vec())
}

async fn create_credential(cred_container: &CredentialsContainer) -> Result<PublicKeyCredential> {
    let mut challenge = [0_u8; 32];
    rand::fill(&mut challenge);
    debug!("create challenge: {}", hex::encode(challenge));

    let pub_key_cred_params = Array::<PublicKeyCredentialParameters>::new_typed();
    pub_key_cred_params.push(&PublicKeyCredentialParameters::new(
        AlgoIdentifier::EdDSA as i32,
        web_sys::PublicKeyCredentialType::PublicKey,
    ));
    pub_key_cred_params.push(&PublicKeyCredentialParameters::new(
        AlgoIdentifier::ES256 as i32,
        web_sys::PublicKeyCredentialType::PublicKey,
    ));
    pub_key_cred_params.push(&PublicKeyCredentialParameters::new(
        AlgoIdentifier::RS256 as i32,
        web_sys::PublicKeyCredentialType::PublicKey,
    ));

    let rp = PublicKeyCredentialRpEntity::new("Alex Test Signer");

    let user_id = uuid::Uuid::new_v4();
    let user_id = Uint8Array::new_from_slice(&user_id.as_bytes()[..]);
    let user = PublicKeyCredentialUserEntity::new("w3irdrobot", "Alex as w3irdrobot", &user_id);

    let pubkey_options = PublicKeyCredentialCreationOptions::new_with_u8_slice(
        &mut challenge,
        &pub_key_cred_params,
        &rp,
        &user,
    );
    pubkey_options.set_extensions(&get_extensions());

    let options = CredentialCreationOptions::new();
    options.set_public_key(&pubkey_options);

    cred_container
        .create_with_options(&options)
        .map_err(|_val| anyhow!("error creating signing challenge"))?
        .await
        .map(PublicKeyCredential::from)
        .map_err(|_val| anyhow!("error signing challenge"))
}

async fn get_credential(
    cred_container: &CredentialsContainer,
    cred_id: &str,
) -> Result<PublicKeyCredential> {
    let mut challenge = [0_u8; 32];
    rand::fill(&mut challenge);
    debug!(
        "get challenge for id {}: {}",
        cred_id,
        hex::encode(challenge)
    );

    // The ID the base64-encoded form of the rawId
    let mut cred_id = BASE64_URL_SAFE_NO_PAD.decode(cred_id)?;
    let allowed_cred = PublicKeyCredentialDescriptor::new_with_u8_slice(
        &mut cred_id,
        PublicKeyCredentialType::PublicKey,
    );
    let allowed_creds = Array::of1(&allowed_cred);

    let pubkey_options = PublicKeyCredentialRequestOptions::new_with_u8_slice(&mut challenge);
    pubkey_options.set_allow_credentials(&allowed_creds);
    pubkey_options.set_extensions(&get_extensions());

    let options = CredentialRequestOptions::new();
    options.set_public_key(&pubkey_options);

    cred_container
        .get_with_options(&options)
        .map_err(|_val| anyhow!("error creating signing challenge"))?
        .await
        .map(PublicKeyCredential::from)
        .map_err(|val| {
            let err = js_sys::Error::from(val);
            anyhow!("error signing challenge: {}", err.message())
        })
}

fn get_extensions() -> AuthenticationExtensionsClientInputs {
    let mut cred_namespace = Uint8Array::new_from_slice(ROOT_KEY_V1_NAMESPACE.as_bytes());
    let prf_values = AuthenticationExtensionsPrfValues::new_with_u8_array(&mut cred_namespace);
    let prf_inputs = AuthenticationExtensionsPrfInputs::new();
    prf_inputs.set_eval(&prf_values);

    let extensions = AuthenticationExtensionsClientInputs::new();
    extensions.set_prf(&prf_inputs);

    extensions
}
