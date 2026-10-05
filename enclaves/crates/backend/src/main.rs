use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, RwLock};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use log::debug;
use nsm_nitro_enclave_utils::api::ByteBuf;
use nsm_nitro_enclave_utils::api::nsm::{Request as NsmRequest, Response};
use nsm_nitro_enclave_utils::driver::Driver;
use rand::Rng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use shared::*;
use tokio::net::TcpListener;
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey};

trait SessionGetter {
    fn get_session(&self, id: Uuid) -> AppResult<Arc<Session>>;
}

#[derive(Clone)]
struct AppState {
    nitro: Arc<dyn Driver + Send + Sync>,
    sessions: Arc<Sessions>,
}

impl SessionGetter for AppState {
    fn get_session(&self, id: Uuid) -> AppResult<Arc<Session>> {
        self.sessions.get(id)
    }
}

#[tokio::main]
async fn main() -> AppResult<()> {
    let _ = dotenvy::dotenv();
    env_logger::init();

    let nitro = get_nitro()?;
    let app_state = AppState {
        nitro: Arc::new(nitro),
        sessions: Arc::new(Sessions::default()),
    };
    let api = Router::new()
        .route("/entropy", post(get_entropy))
        .route("/sessions", post(create_session))
        .with_state(app_state);
    let app = Router::new().nest("/api", api);
    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn get_nitro() -> AppResult<impl Driver> {
    #[cfg(feature = "dev")]
    {
        use nsm_nitro_enclave_utils::api::ByteBuf;
        use nsm_nitro_enclave_utils::pcr::{Pcr, PcrIndex, Pcrs};
        let end_cert = {
            let der = std::fs::read("certs/end-certificate.der")?;
            ByteBuf::from(der)
        };
        let signing_key = {
            use nsm_nitro_enclave_utils::api::SecretKey;
            let der = std::fs::read("certs/end-signing-key.der")?;
            SecretKey::from_sec1_der(&der).map_err(|e| AppError::Sec1Encoding(e.to_string()))?
        };
        let int_cert = {
            let der = std::fs::read("certs/int-certificate.der")?;
            ByteBuf::from(der)
        };

        let mut pcr = [0_u8; 48];
        pcr[47] = 1;
        let mut pcrs = Pcrs::zeros();
        pcrs.set(PcrIndex::Zero, Pcr::from(pcr));

        let nitro = nsm_nitro_enclave_utils::driver::dev::DevNitro::builder(signing_key, end_cert)
            .pcrs(pcrs)
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
    req: Json<CreateSessionRequest>,
) -> AppResult<(StatusCode, Json<CreateSessionResponse>)> {
    let server_key = EphemeralSecret::random();
    let server_pub_key = PublicKey::from(&server_key);

    let session = Session::for_server(server_key, req.pub_key, req.nonce)
        .map_err(AppError::SessionDerivation)?;

    let mut user_data = Vec::new();
    user_data.extend_from_slice(req.pub_key.as_bytes());
    user_data.extend_from_slice(&session.id().to_bytes_le());

    let user_data_hash = Sha256::digest(user_data);
    let client_key_hash = ByteBuf::from(user_data_hash.as_slice());

    let nonce = ByteBuf::from(req.nonce);

    let nsm_req = NsmRequest::Attestation {
        user_data: Some(client_key_hash),
        nonce: Some(nonce),
        public_key: Some(ByteBuf::from(server_pub_key.as_bytes())),
    };

    let nitro = state.nitro.clone();
    let Response::Attestation { document } =
        tokio::spawn(async move { nitro.process_request(nsm_req) })
            .await
            .unwrap()
    else {
        return Err(AppError::InvalidResponse("AttestationDoc".to_string()));
    };

    let res = CreateSessionResponse {
        id: session.id(),
        attestation_doc: document,
    };
    state.sessions.add(session);

    Ok((StatusCode::OK, Json(res)))
}

#[axum::debug_handler(state = AppState)]
async fn get_entropy(
    session: AppSession,
) -> AppResult<(StatusCode, AppEncryptedPayload<GetEntropyResponse>)> {
    let mut data = [0_u8; 32];
    rand::rng().fill_bytes(&mut data);
    debug!("generated entropy: {:?}", data);

    let res = GetEntropyResponse { entropy: data };
    let ciphertext = session
        .encrypt_payload(res)
        .map_err(AppError::PayloadEncryption)?;

    Ok((StatusCode::CREATED, ciphertext))
}

struct Sessions {
    db: RwLock<HashMap<Uuid, Arc<Session>>>,
}

impl Sessions {
    pub fn get(&self, id: Uuid) -> AppResult<Arc<Session>> {
        // TODO: Handle this better
        let db = self.db.read().unwrap();
        db.get(&id).cloned().ok_or(AppError::SessionNotFound(id))
    }

    pub fn add(&self, session: Session) {
        let mut db = self.db.write().unwrap();
        db.insert(session.id(), Arc::new(session));
    }
}

impl Default for Sessions {
    fn default() -> Self {
        Self {
            db: RwLock::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorResponse {
    error: String,
}

type AppResult<T> = std::result::Result<T, AppError>;

#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("incorrect operation response for operation: {0}")]
    InvalidResponse(String),
    #[error("session {0} not found")]
    SessionNotFound(Uuid),
    #[error("x-session-id header missing")]
    SessionHeaderMissing,
    #[error("invalid session header {0:?}")]
    InvalidSessionHeader(axum::http::HeaderValue),
    #[error("file not found: {0}")]
    MissingFile(#[from] std::io::Error),
    #[error("unable to encrypt payload: {0}")]
    PayloadEncryption(shared::Error),
    #[error("unable to decode the cert: {0}")]
    Sec1Encoding(String),
    #[error("unable to derive the session: {0}")]
    SessionDerivation(shared::Error),
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;

        let (status, error) = match self {
            Self::SessionHeaderMissing => (
                StatusCode::UNAUTHORIZED,
                "x-session-id header is required".to_string(),
            ),
            Self::InvalidSessionHeader(_) => (
                StatusCode::UNAUTHORIZED,
                "x-session-id header must be a valid guid".to_string(),
            ),
            Self::SessionNotFound(id) => {
                (StatusCode::BAD_REQUEST, format!("session {} not found", id))
            }
            // TODO: log this error or something
            Self::InvalidResponse(_err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "something happened, and we don't know what".to_string(),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "something happened, and we don't know what".to_string(),
            ),
        };

        (status, axum::Json(ErrorResponse { error })).into_response()
    }
}

struct AppSession(Arc<Session>);

impl AppSession {
    fn encrypt_payload<T: Serialize>(&self, payload: T) -> Result<AppEncryptedPayload<T>> {
        let payload = self.0.encrypt_payload(payload)?;
        Ok(AppEncryptedPayload(payload))
    }
}

impl<S: SessionGetter + Send + Sync> axum::extract::FromRequestParts<S> for AppSession {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> AppResult<Self> {
        use axum::http::HeaderName;

        let id_header = HeaderName::from_static("x-session-id");
        let session_id = parts
            .headers
            .get(id_header)
            .ok_or(AppError::SessionHeaderMissing)?;
        let id = session_id
            .to_str()
            .map_err(|_| AppError::InvalidSessionHeader(session_id.clone()))?;
        let id =
            Uuid::parse_str(id).map_err(|_| AppError::InvalidSessionHeader(session_id.clone()))?;

        state.get_session(id).map(AppSession)
    }
}

struct AppEncryptedPayload<T>(EncryptedPayload<T>);

impl<T> Deref for AppEncryptedPayload<T> {
    type Target = EncryptedPayload<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> axum::response::IntoResponse for AppEncryptedPayload<T> {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;

        (StatusCode::OK, Vec::from(self.0)).into_response()
    }
}
