use std::marker::PhantomData;
use std::sync::atomic::{AtomicU32, Ordering};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::Error::InvalidVersion;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionRequest {
    pub nonce: [u8; 32],
    pub pub_key: PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionResponse {
    pub id: Uuid,
    /// A hex-encoded array of bytes representing the COSE-signed attestation document
    pub attestation_doc: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetEntropyResponse {
    pub entropy: [u8; 32],
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unable to encode the payload into messagepack: {0}")]
    MessagePackEncoding(String),
    #[error("unable to encrypt the payload: {0}")]
    PayloadEncrypt(chacha20poly1305::Error),
    #[error("unable to decrypt the payload: {0}")]
    PayloadDecryption(chacha20poly1305::Error),
    #[error("unable to decode the payload: {0}")]
    PayloadDecode(#[from] rmp_serde::decode::Error),
    #[error("the shared secret cannot be the identity")]
    SharedSecretIdentity,
    #[error("invalid version {0}")]
    InvalidVersion(u8),
    #[error("invalid direction {0}")]
    InvalidDirection(u8),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Version {
    One = 1,
}

impl TryFrom<u8> for Version {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Version::One),
            _ => Err(InvalidVersion(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Direction {
    ClientToServer = 1,
    ServerToClient = 2,
}

impl TryFrom<u8> for Direction {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Direction::ClientToServer),
            2 => Ok(Direction::ServerToClient),
            _ => Err(Error::InvalidDirection(value)),
        }
    }
}

#[derive(Debug)]
pub struct Session {
    id: Uuid,
    direction: Direction,
    send_key: Key,
    send_nonce_prefix: [u8; 20],
    send_count: AtomicU32,
    receive_key: Key,
    receive_nonce_prefix: [u8; 20],
}

impl Session {
    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn for_server(
        server_key: EphemeralSecret,
        client_key: PublicKey,
        nonce: [u8; 32],
    ) -> Result<Self> {
        let session_id = Uuid::new_v4();
        let server_pub_key = PublicKey::from(&server_key);
        let transcript =
            Self::handshake_transcript(Version::One, server_pub_key, client_key, nonce, session_id);
        let (send_key, send_nonce_prefix, receive_key, receive_nonce_prefix) =
            Self::derive_keys(server_key, client_key, transcript)?;

        Ok(Self {
            id: session_id,
            direction: Direction::ServerToClient,
            send_key,
            send_nonce_prefix,
            send_count: AtomicU32::default(),
            receive_key,
            receive_nonce_prefix,
        })
    }

    pub fn for_client(
        client_key: EphemeralSecret,
        server_key: PublicKey,
        nonce: [u8; 32],
        session_id: Uuid,
    ) -> Result<Self> {
        let client_pub_key = PublicKey::from(&client_key);
        let transcript =
            Self::handshake_transcript(Version::One, server_key, client_pub_key, nonce, session_id);
        let (receive_key, receive_nonce_prefix, send_key, send_nonce_prefix) =
            Self::derive_keys(client_key, server_key, transcript)?;

        Ok(Self {
            id: session_id,
            direction: Direction::ClientToServer,
            send_key,
            send_nonce_prefix,
            send_count: AtomicU32::default(),
            receive_key,
            receive_nonce_prefix,
        })
    }

    fn handshake_transcript(
        version: Version,
        server_key: PublicKey,
        client_key: PublicKey,
        nonce: [u8; 32],
        session_id: Uuid,
    ) -> [u8; 113] {
        let mut transcript = [0_u8; 1 + 32 + 32 + 32 + 16];
        transcript[0] = version as u8;
        transcript[1..33].copy_from_slice(server_key.as_bytes());
        transcript[33..65].copy_from_slice(client_key.as_bytes());
        transcript[65..97].copy_from_slice(&nonce);
        transcript[97..].copy_from_slice(session_id.as_bytes());

        transcript
    }

    fn derive_keys(
        our_key: EphemeralSecret,
        their_key: PublicKey,
        transcript: [u8; 113],
    ) -> Result<(Key, [u8; 20], Key, [u8; 20])> {
        let shared_secret = our_key.diffie_hellman(&their_key);
        if !shared_secret.was_contributory() {
            return Err(Error::SharedSecretIdentity);
        }

        // Get root key
        let extracted = Hkdf::<Sha256>::new(Some(&transcript), shared_secret.as_bytes());
        let mut root_key = [0_u8; 32];
        // TODO: Handle this potential error
        let _ = extracted.expand("app-session/v1".as_bytes(), &mut root_key);

        let extracted = Hkdf::<Sha256>::new(None, &root_key);

        let mut key_1 = [0_u8; 32];
        // TODO: Handle this potential error
        let _ = extracted.expand("app-session/v1/key-1".as_bytes(), &mut key_1);
        let key_1 = Key::from(key_1);

        let mut key_2 = [0_u8; 32];
        // TODO: Handle this potential error
        let _ = extracted.expand("app-session/v1/key-2".as_bytes(), &mut key_2);
        let key_2 = Key::from(key_2);

        let mut key1_nonce_prefix = [0_u8; 20];
        // TODO: Handle this potential error
        let _ = extracted.expand(
            "app-session/v1/key-1-nonce-prefix".as_bytes(),
            &mut key1_nonce_prefix,
        );

        let mut key2_nonce_prefix = [0_u8; 20];
        // TODO: Handle this potential error
        let _ = extracted.expand(
            "app-session/v1/key-2-nonce-prefix".as_bytes(),
            &mut key2_nonce_prefix,
        );

        Ok((key_1, key1_nonce_prefix, key_2, key2_nonce_prefix))
    }

    pub fn encrypt_payload<T: Serialize>(&self, payload: T) -> Result<EncryptedPayload<T>> {
        let cipher = XChaCha20Poly1305::new(&self.send_key);

        let msg =
            rmp_serde::to_vec(&payload).map_err(|e| Error::MessagePackEncoding(e.to_string()))?;
        let msg_num = self.send_count.fetch_add(1, Ordering::Relaxed);

        let header = PayloadHeader {
            session_id: self.id,
            version: Version::One,
            direction: self.direction,
            msg_num,
        };

        let payload = Payload {
            msg: &msg,
            aad: &header.as_bytes(),
        };

        let mut nonce = [0_u8; 24];
        nonce[..20].copy_from_slice(&self.send_nonce_prefix);
        nonce[20..].copy_from_slice(&msg_num.to_be_bytes());
        let nonce = XNonce::from(nonce);

        let ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|e| Error::PayloadEncrypt(e))?;

        Ok(EncryptedPayload {
            header,
            contents: ciphertext,
            _marker: PhantomData,
        })
    }
}

pub struct PayloadHeader {
    session_id: Uuid,
    version: Version,
    direction: Direction,
    msg_num: u32,
}

impl PayloadHeader {
    fn as_bytes(&self) -> [u8; 22] {
        let mut aad = [0_u8; 16 + 1 + 1 + 4];
        aad[..16].copy_from_slice(self.session_id.as_bytes());
        aad[16] = self.version as u8;
        aad[17] = self.direction as u8;
        aad[18..].copy_from_slice(&self.msg_num.to_be_bytes());

        aad
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let session_id = Uuid::from_slice(&bytes[..16]).unwrap();
        let version = Version::try_from(bytes[16])?;
        let direction = Direction::try_from(bytes[17])?;

        let mut msg_num = [0_u8; 4];
        msg_num.copy_from_slice(&bytes[18..22]);
        let msg_num = u32::from_be_bytes(msg_num);

        Ok(Self {
            session_id,
            version,
            direction,
            msg_num,
        })
    }
}

pub struct EncryptedPayload<T> {
    header: PayloadHeader,
    contents: Vec<u8>,
    _marker: PhantomData<fn() -> T>,
}

impl<T: DeserializeOwned> EncryptedPayload<T> {
    pub fn decrypt(self, session: &Session) -> Result<T> {
        let cipher = XChaCha20Poly1305::new(&session.receive_key);

        let mut nonce = [0_u8; 24];
        nonce[..20].copy_from_slice(&session.receive_nonce_prefix);
        nonce[20..].copy_from_slice(&self.header.msg_num.to_be_bytes());
        let nonce = XNonce::from(nonce);

        let payload = Payload {
            msg: &self.contents,
            aad: &self.header.as_bytes(),
        };

        let plaintext = cipher
            .decrypt(&nonce, payload)
            .map_err(Error::PayloadDecryption)?;
        let res: T = rmp_serde::from_slice(&plaintext)?;

        Ok(res)
    }
}

impl<T> TryFrom<Vec<u8>> for EncryptedPayload<T> {
    type Error = Error;

    fn try_from(mut value: Vec<u8>) -> Result<Self> {
        // The header is the first 22 bytes. So we split here to get everything after the header
        let contents = value.split_off(22);
        let header = PayloadHeader::from_bytes(&value[..22])?;

        Ok(Self {
            header,
            contents,
            _marker: PhantomData,
        })
    }
}

impl<T> From<EncryptedPayload<T>> for Vec<u8> {
    fn from(value: EncryptedPayload<T>) -> Self {
        let mut output = Vec::with_capacity(22 + value.contents.len());
        output.extend(value.header.as_bytes());
        output.extend(value.contents);
        output
    }
}
