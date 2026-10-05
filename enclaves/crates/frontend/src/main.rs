use anyhow::{Result, anyhow};
use log::{debug, info};
use nsm_nitro_enclave_utils::api::Time;
use nsm_nitro_enclave_utils::api::nsm::AttestationDoc;
use nsm_nitro_enclave_utils::verify::AttestationDocVerifierExt;
use rand::Rng;
use sha2::{Digest, Sha256};
use shared::*;
use uuid::Uuid;
use web_sys::js_sys::{Date, futures as wasm_bindgen_futures};
use web_sys::wasm_bindgen;
use web_sys::wasm_bindgen::prelude::*;
use x25519_dalek::{EphemeralSecret, PublicKey};

#[wasm_bindgen(main)]
async fn main() -> Result<()> {
    let _ = console_log::init_with_level(log::Level::Debug);

    let session = create_session().await?;
    info!("session {} created", session.id());

    match get_entropy(&session).await {
        Ok(entropy) => info!("received entropy: {:?}", entropy),
        Err(error) => return Err(anyhow!("error getting entropy: {}", error)),
    }

    Ok(())
}

async fn create_session() -> Result<Session> {
    let ephemeral_secret = EphemeralSecret::random();
    let client_pub_key = PublicKey::from(&ephemeral_secret);

    let mut nonce = [0_u8; 32];
    rand::rng().fill_bytes(&mut nonce);

    let req = CreateSessionRequest {
        nonce,
        pub_key: client_pub_key,
    };
    let client = reqwest::Client::new();
    let res = client
        .post("https://localhost:3001/api/sessions")
        .json(&req)
        .send()
        .await?;

    let status = res.status();
    if !status.is_success() {
        return Err(anyhow!("error making entropy request: {}", status));
    }

    let body = res.json::<CreateSessionResponse>().await?;

    debug!("received attestation doc bytes: {:?}", body.attestation_doc);
    let doc = parse_attestation_doc(body.attestation_doc, nonce, client_pub_key, body.id)?;

    let server_pub_key = doc
        .public_key
        .map(|b| {
            let mut key = [0_u8; 32];
            key.copy_from_slice(&b);
            PublicKey::from(key)
        })
        .ok_or(anyhow!("the server did not send a public key"))?;

    Ok(Session::for_client(
        ephemeral_secret,
        server_pub_key,
        nonce,
        body.id,
    )?)
}

fn parse_attestation_doc(
    doc: Vec<u8>,
    nonce: [u8; 32],
    client_pub_key: PublicKey,
    session_id: Uuid,
) -> Result<AttestationDoc> {
    #[cfg(feature = "dev")]
    let root_cert = include_bytes!("../../../certs/root-certificate.der");
    #[cfg(not(feature = "dev"))]
    let root_cert = include_bytes!("../../../certs/aws-root-cert.der");
    let time = Time::new(Box::new(|| Date::now() as u64));
    // This checks the root cert and the cert chain in the doc
    let doc = AttestationDoc::from_cose(&doc, root_cert, time)
        .map_err(|err| anyhow!("error validating attestation doc: {:?}", err))?;

    // Check the nonce matches the once we sent
    let doc_nonce = doc
        .nonce
        .as_deref()
        .ok_or(anyhow!("nonce missing from attestation doc"))?;
    if doc_nonce[..] != nonce {
        return Err(anyhow!(
            "the document nonce {:?} doesn't match the nonce sent {:?}",
            doc_nonce,
            nonce
        ));
    }

    // Check the user data matches what is expected
    let doc_user_data = doc
        .user_data
        .as_deref()
        .ok_or(anyhow!("user data missing from attestation doc"))?;

    let mut user_data = Vec::new();
    user_data.extend_from_slice(client_pub_key.as_bytes());
    user_data.extend_from_slice(&session_id.to_bytes_le());
    let user_data_hash = Sha256::digest(user_data);

    if doc_user_data != user_data_hash.as_slice() {
        return Err(anyhow!(
            "the document user data hash {:?} doesn't match the user data hash we calculated {:?}",
            doc_user_data,
            user_data_hash
        ));
    }

    let pcr0 = doc
        .pcrs
        .get(&0)
        .ok_or(anyhow!("PCR0 missing from attestation doc"))
        .map(|b| b.to_vec())?;

    let mut expected_pcr = [0_u8; 48];
    expected_pcr[47] = 1;

    if pcr0 != expected_pcr {
        return Err(anyhow!("PCR0 {:?} is invalid", pcr0));
    }

    Ok(doc)
}

async fn get_entropy(session: &Session) -> Result<[u8; 32]> {
    let client = reqwest::Client::new();
    let res = client
        .post("https://localhost:3001/api/entropy")
        .headers(session_request_headers(&session))
        .send()
        .await?;

    let status = res.status();
    if status.is_success() {
        let body = res.bytes().await?;
        let payload = EncryptedPayload::<GetEntropyResponse>::try_from(body.to_vec())?;
        let res = payload.decrypt(&session)?;
        Ok(res.entropy)
    } else {
        Err(anyhow!("error making entropy request: {}", status))
    }
}

pub fn session_request_headers(session: &Session) -> reqwest::header::HeaderMap {
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

    let id_header = HeaderName::from_static("x-session-id");

    let mut headers = HeaderMap::default();

    let id = HeaderValue::from_str(&session.id().to_string()).unwrap();
    headers.insert(id_header, id);

    headers
}
