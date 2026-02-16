use crate::exec::SignProvider;
use ed25519_dalek::{Signer, SigningKey};
use std::sync::Arc;

/// Assinador baseado em chave Ed25519 carregada de bytes (ENV/arquivo).
/// MVP: assina payload cru; integração JWS virá depois.
pub struct EnvSigner {
    kid: String,
    key: Arc<SigningKey>,
}

impl EnvSigner {
    pub fn from_seed_bytes(kid: impl Into<String>, seed32: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed32);
        Self {
            kid: kid.into(),
            key: Arc::new(key),
        }
    }
    pub fn kid(&self) -> &str {
        &self.kid
    }
}

impl SignProvider for EnvSigner {
    fn sign_jws(&self, payload_nrf_bytes: &[u8]) -> Vec<u8> {
        // MVP: retorna assinatura nua; substituir por JWS compact/Detached na próxima iteração.
        let sig = self.key.sign(payload_nrf_bytes);
        sig.to_bytes().to_vec()
    }
    fn kid(&self) -> String {
        self.kid.clone()
    }
}
