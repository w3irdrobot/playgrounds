use anyhow::{Result, anyhow};
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::Generate;
use log::{debug, info};
use nsm_nitro_enclave_utils::api::Time;
use nsm_nitro_enclave_utils::api::nsm::AttestationDoc;
use nsm_nitro_enclave_utils::verify::AttestationDocVerifierExt;
use rand::Rng;
use shared::*;
use web_sys::js_sys::Date;
use web_sys::js_sys::futures as wasm_bindgen_futures;
use web_sys::wasm_bindgen;
use web_sys::wasm_bindgen::prelude::*;

#[wasm_bindgen(main)]
async fn main() -> Result<()> {
    let _ = console_log::init_with_level(log::Level::Debug);

    let attestation_doc = get_attestation_doc().await?;
    info!("attestation_doc: {:?}", attestation_doc);

    match get_entropy().await {
        Ok(entropy) => info!("received entropy: {}", entropy),
        Err(error) => return Err(anyhow!("error getting entropy: {}", error)),
    }

    Ok(())
}

async fn get_attestation_doc() -> Result<AttestationDoc> {
    let signing_key = SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let mut nonce = [0_u8; 32];
    rand::rng().fill_bytes(&mut nonce);

    let req = GetAttestationDocRequest {
        nonce: hex::encode(nonce),
        pub_key: *verifying_key,
    };
    let client = reqwest::Client::new();
    let res = client
        .post("https://localhost:3001/api/attest")
        .json(&req)
        .send()
        .await?;

    let status = res.status();
    if status.is_success() {
        let body = res.json::<GetAttestationDocResponse>().await?;

        debug!("received attestation doc bytes: {}", body.attestation_doc);
        let doc = hex::decode(body.attestation_doc)?;
        parse_attestation_doc(&doc)
    } else {
        Err(anyhow!("error making entropy request: {}", status))
    }
}

fn parse_attestation_doc(doc: &[u8]) -> Result<AttestationDoc> {
    #[cfg(feature = "dev")]
    let root_cert = include_str!("../../../root-certificate.pem").as_bytes();
    #[cfg(not(feature = "dev"))]
    let root_cert = r#"-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----"#
        .as_bytes();
    let time = Time::new(Box::new(|| Date::now() as u64));
    let attestation_doc = AttestationDoc::from_cose(doc, root_cert, time)
        .map_err(|err| anyhow!("error validating attestation doc: {:?}", err))?;

    todo!()
}

async fn get_entropy() -> Result<String> {
    let client = reqwest::Client::new();
    let res = client
        .post("https://localhost:3001/api/entropy")
        .send()
        .await?;

    let status = res.status();
    if status.is_success() {
        let body = res.json::<GetEntropyResponse>().await?;

        Ok(body.entropy)
    } else {
        Err(anyhow!("error making entropy request: {}", status))
    }
}
