use cryptimitives::{aead, kdf::sha256, key::x25519_ristretto};
use cryptraits::convert::FromBytes;
use cryptraits::key::PublicKey;
use cryptraits::{convert::ToVec, key::KeyPair, signature::Sign};
use rand_core::OsRng;
use wasm_bindgen::prelude::*;
use xxxdh::{inmem, Protocol};

pub mod errors;

#[wasm_bindgen]
pub struct X25519RistrettoKeyPair {
    keypair: x25519_ristretto::KeyPair,
}

#[wasm_bindgen]
impl X25519RistrettoKeyPair {
    #[wasm_bindgen(constructor)]
    pub fn generate() -> Self {
        Self {
            keypair: x25519_ristretto::KeyPair::generate_with(OsRng),
        }
    }

    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.keypair.sign(data).to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn public(&self) -> Vec<u8> {
        self.keypair.to_public().to_vec()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.keypair.to_vec()
    }
}

#[wasm_bindgen]
pub struct ProtocolX25519RistrettoInMemSha256Aes256Gm {
    protocol: Protocol<
        x25519_ristretto::SecretKey,
        x25519_ristretto::EphemeralSecretKey,
        x25519_ristretto::Signature,
        inmem::Storage<x25519_ristretto::SecretKey, x25519_ristretto::Signature>,
        sha256::Kdf,
        aead::aes_gcm::Aes256Gcm,
    >,
}

#[wasm_bindgen]
impl ProtocolX25519RistrettoInMemSha256Aes256Gm {
    #[wasm_bindgen(constructor)]
    pub fn new(
        identity_keypair: js_sys::Uint8Array,
        prekey_keypair: js_sys::Uint8Array,
        prekey_signature: js_sys::Uint8Array,
        onetime_keypairs: Option<Vec<js_sys::Uint8Array>>,
    ) -> Result<ProtocolX25519RistrettoInMemSha256Aes256Gm, JsValue> {
        let identity_keypair = x25519_ristretto::KeyPair::from_bytes(&identity_keypair.to_vec())
            .or(Err(JsValue::from(
                self::errors::XxxDhError::InvalidKeyBytes,
            )))?;

        let prekey_keypair = x25519_ristretto::KeyPair::from_bytes(&prekey_keypair.to_vec()).or(
            Err(JsValue::from(self::errors::XxxDhError::InvalidKeyBytes)),
        )?;

        let prekey_signature = x25519_ristretto::Signature::from_bytes(&prekey_signature.to_vec())
            .or(Err(JsValue::from(
                self::errors::XxxDhError::InvalidKeyBytes,
            )))?;

        let onetime_keypairs: Option<Vec<x25519_ristretto::KeyPair>> = match onetime_keypairs {
            Some(keypairs) => {
                let mut onetime_keypairs = Vec::new();

                for k in keypairs {
                    let keypair = x25519_ristretto::KeyPair::from_bytes(&k.to_vec()).or(Err(
                        JsValue::from(self::errors::XxxDhError::InvalidKeyBytes),
                    ))?;

                    onetime_keypairs.push(keypair);
                }

                Some(onetime_keypairs)
            }
            None => None,
        };

        Ok(Self {
            protocol: Protocol::new(
                identity_keypair,
                prekey_keypair,
                prekey_signature,
                onetime_keypairs,
            ),
        })
    }

    pub fn prepare_init_msg(
        &mut self,
        receiver_identity: js_sys::Uint8Array,
        receiver_prekey: js_sys::Uint8Array,
        receiver_prekey_signature: js_sys::Uint8Array,
        receiver_onetime_key: js_sys::Uint8Array,
    ) -> Result<InitMsgBundle, JsValue> {
        let receiver_identity =
            x25519_ristretto::PublicKey::from_bytes(&receiver_identity.to_vec()).or(Err(
                JsValue::from(self::errors::XxxDhError::InvalidKeyBytes),
            ))?;

        let receiver_prekey = x25519_ristretto::PublicKey::from_bytes(&receiver_prekey.to_vec())
            .or(Err(JsValue::from(
                self::errors::XxxDhError::InvalidKeyBytes,
            )))?;

        let receiver_prekey_signature =
            x25519_ristretto::Signature::from_bytes(&receiver_prekey_signature.to_vec()).or(
                Err(JsValue::from(self::errors::XxxDhError::InvalidKeyBytes)),
            )?;

        let receiver_onetime_key =
            x25519_ristretto::PublicKey::from_bytes(&receiver_onetime_key.to_vec()).or(Err(
                JsValue::from(self::errors::XxxDhError::InvalidKeyBytes),
            ))?;

        Ok(InitMsgBundle::from(
            self.protocol
                .prepare_init_msg(
                    &receiver_identity,
                    &receiver_prekey,
                    &receiver_prekey_signature,
                    &receiver_onetime_key,
                )
                .or_else(|e| {
                    Err(JsValue::from(self::errors::XxxDhError::ProtocolError(
                        format!("{:?}", e),
                    )))
                })?,
        ))
    }

    pub fn derive_shared_secret(
        &mut self,
        sender_identity: js_sys::Uint8Array,
        sender_ephemeral_key: js_sys::Uint8Array,
        receiver_onetime_key: js_sys::Uint8Array,
        nonce: js_sys::Uint8Array,
        cyphertext: js_sys::Uint8Array,
    ) -> Result<js_sys::Uint8Array, JsValue> {
        let sender_identity = x25519_ristretto::PublicKey::from_bytes(&sender_identity.to_vec())
            .or(Err(JsValue::from(
                self::errors::XxxDhError::InvalidKeyBytes,
            )))?;

        let sender_ephemeral_key =
            x25519_ristretto::PublicKey::from_bytes(&sender_ephemeral_key.to_vec()).or(Err(
                JsValue::from(self::errors::XxxDhError::InvalidKeyBytes),
            ))?;

        let receiver_onetime_key =
            x25519_ristretto::PublicKey::from_bytes(&receiver_onetime_key.to_vec()).or(Err(
                JsValue::from(self::errors::XxxDhError::InvalidKeyBytes),
            ))?;

        let sk = self
            .protocol
            .derive_shared_secret(
                &sender_identity,
                &sender_ephemeral_key,
                &receiver_onetime_key,
                &nonce.to_vec(),
                &cyphertext.to_vec(),
            )
            .or_else(|e| {
                Err(JsValue::from(self::errors::XxxDhError::ProtocolError(
                    format!("{:?}", e),
                )))
            })?;

        Ok(js_sys::Uint8Array::from(&sk[..]))
    }
}

#[wasm_bindgen]
pub struct InitMsgBundle {
    init_msg: InitMsg,
    shared_secret: Vec<u8>,
}

impl<PK> From<(PK, PK, PK, Vec<u8>, Vec<u8>, Vec<u8>)> for InitMsgBundle
where
    PK: PublicKey + ToVec,
{
    fn from(msg: (PK, PK, PK, Vec<u8>, Vec<u8>, Vec<u8>)) -> Self {
        Self {
            init_msg: InitMsg {
                sender_identity: msg.0.to_vec(),
                sender_ephemerial_key: msg.1.to_vec(),
                receiver_onetime_key: msg.2.to_vec(),
                nonce: msg.4,
                cyphertext: msg.5,
            },
            shared_secret: msg.3,
        }
    }
}

#[wasm_bindgen]
impl InitMsgBundle {
    #[wasm_bindgen(getter)]
    pub fn init_msg(&self) -> InitMsg {
        self.init_msg.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn shared_secret(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(&self.shared_secret[..])
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct InitMsg {
    sender_identity: Vec<u8>,
    sender_ephemerial_key: Vec<u8>,
    receiver_onetime_key: Vec<u8>,
    nonce: Vec<u8>,
    cyphertext: Vec<u8>,
}

#[wasm_bindgen]
impl InitMsg {
    #[wasm_bindgen(getter)]
    pub fn sender_identity(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(&self.sender_identity[..])
    }

    #[wasm_bindgen(getter)]
    pub fn sender_ephemerial_key(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(&self.sender_ephemerial_key[..])
    }

    #[wasm_bindgen(getter)]
    pub fn receiver_onetime_key(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(&self.receiver_onetime_key[..])
    }

    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(&self.nonce[..])
    }

    #[wasm_bindgen(getter)]
    pub fn cyphertext(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(&self.cyphertext[..])
    }
}
