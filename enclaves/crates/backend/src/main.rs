use std::sync::Arc;

use anyhow::Result;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::Generate;
use nsm_nitro_enclave_utils::api::ByteBuf;
use nsm_nitro_enclave_utils::api::nsm::{Request as NsmRequest, Response};
use nsm_nitro_enclave_utils::driver::Driver;
use rand::Rng;
use sha2::{Digest, Sha256};
use shared::*;
use tokio::net::TcpListener;

#[derive(Clone)]
struct AppState {
    nitro: Arc<dyn Driver + Send + Sync>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let nitro = get_nitro()?;
    let app_state = AppState {
        nitro: Arc::new(nitro),
    };
    let api = Router::new()
        .route("/entropy", post(get_entropy))
        .route("/attest", post(create_session))
        .with_state(app_state);
    let app = Router::new().nest("/api", api);
    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn get_nitro() -> Result<impl Driver> {
    #[cfg(feature = "dev")]
    {
        use nsm_nitro_enclave_utils::api::ByteBuf;
        use nsm_nitro_enclave_utils::pcr::Pcrs;
        let end_cert = {
            let der = std::fs::read("end-certificate.pem")?;
            ByteBuf::from(der)
        };
        let signing_key = {
            use nsm_nitro_enclave_utils::api::{DecodePrivateKey, SecretKey};
            let der = std::fs::read("end-signing-key.pem")?;
            SecretKey::from_pkcs8_der(&der)?
        };
        let int_cert = {
            let der = std::fs::read("int-certificate.pem")?;
            ByteBuf::from(der)
        };

        let nitro = nsm_nitro_enclave_utils::driver::dev::DevNitro::builder(signing_key, end_cert)
            .pcrs(Pcrs::zeros())
            .ca_bundle(vec![int_cert])
            .build();

        Ok(nitro)
    }

    #[cfg(not(feature = "dev"))]
    Ok(nsm_nitro_enclave_utils::driver::nitro::Nitro::init())
}

#[axum::debug_handler]
async fn create_session(
    State(state): State<AppState>,
    req: Json<GetAttestationDocRequest>,
) -> AppResult<(StatusCode, Json<GetAttestationDocResponse>)> {
    let client_key_hash = ByteBuf::from(Sha256::digest(req.pub_key.to_sec1_bytes()));
    let nonce = ByteBuf::from(&req.nonce[..]);

    let server_key = SigningKey::generate();
    let verifying_key = ByteBuf::from(server_key.verifying_key().to_sec1_bytes());
    let nsm_req = NsmRequest::Attestation {
        user_data: Some(client_key_hash),
        nonce: Some(nonce),
        public_key: Some(verifying_key),
    };

    let nitro = state.nitro.clone();
    let Response::Attestation { document } =
        tokio::spawn(async move { nitro.process_request(nsm_req) })
            .await
            .unwrap()
    else {
        return Err(AppError::InvalidResponse("AttestationDoc".to_string()));
    };

    let res = GetAttestationDocResponse {
        attestation_doc: hex::encode(document),
    };
    Ok((StatusCode::OK, Json(res)))
}

#[axum::debug_handler]
async fn get_entropy() -> (StatusCode, Json<GetEntropyResponse>) {
    let mut data = [0_u8; 32];
    rand::rng().fill_bytes(&mut data);

    let res = GetEntropyResponse {
        entropy: hex::encode(data),
    };

    (StatusCode::CREATED, Json(res))
}
