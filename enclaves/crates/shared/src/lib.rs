use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAttestationDocRequest {
    pub nonce: String,
    pub pub_key: VerifyingKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAttestationDocResponse {
    /// A hex-encoded array of bytes representing the COSE-signed attestation document
    pub attestation_doc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetEntropyResponse {
    pub entropy: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorResponse {
    error: String,
}

pub type AppResult<T> = std::result::Result<T, AppError>;

#[derive(Debug, Clone, thiserror::Error)]
pub enum AppError {
    #[error("incorrect operation response for operation: {0}")]
    InvalidResponse(String),
}

#[cfg(feature = "server")]
impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        use log::error;

        let (status, error) = match self {
            err => {
                error!("{}", err);
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "something happened, and we don't know what".to_string(),
                )
            }
        };

        (status, axum::Json(ErrorResponse { error })).into_response()
    }
}
