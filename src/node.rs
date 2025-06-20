use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, KeyInit},
};
use base64::{Engine as _, engine::general_purpose};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1v15::{Signature, SigningKey, VerifyingKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    rand_core::OsRng,
    sha2::Sha256,
    signature::{SignatureEncoding, Signer, Verifier},
    traits::PublicKeyParts,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Node {
    pub name: String,
    pub nodetype: String,
    pub pubkey: String,
    #[serde(default)]
    pub privkey: String,
    pub address: String,
    pub listen_port: u16,
    pub public_port: u16,
    pub secure: bool,
    pub strict: Option<bool>,
    pub min_hashcash: Option<usize>,
    pub suggested_hashcash: Option<usize>,
    pub version: Option<String>,
    pub peers: Option<Vec<PublicNode>>,
    pub ping_interval: usize,
}

impl Node {
    pub fn load(path: &str) -> Result<Node, serde_json::Error> {
        let data = fs::read_to_string(path).expect("Unable to read file");
        let version = env!("CARGO_PKG_VERSION").to_string();
        let mut node: Node = serde_json::from_str(&data)?;
        node.version = Some(version);

        let private_key_path = "config/privateKey.pem";

        if !Path::new(private_key_path).exists() {
            if let Some(parent) = Path::new(private_key_path).parent() {
                fs::create_dir_all(parent).expect("Failed to create config directory");
            }
            if node.privkey.is_empty() {
                let mut rng = OsRng;
                let private_key =
                    RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key");
                let pem_key = private_key
                    .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                    .expect("Failed to encode private key to PEM");

                node.privkey = pem_key.to_string();
                fs::write(private_key_path, &pem_key).expect("Failed to write private key file");
            } else {
                fs::write(private_key_path, &node.privkey)
                    .expect("Failed to write private key file");
            }
        } else {
            let file_private_key =
                fs::read_to_string(private_key_path).expect("Failed to read private key file");

            let private_key = RsaPrivateKey::from_pkcs8_pem(&file_private_key)
                .expect("Failed to parse private key from file");
            let public_key = RsaPublicKey::from(&private_key);
            let public_key_der = public_key
                .to_public_key_der()
                .expect("Failed to encode public key");
            let derived_pubkey = general_purpose::STANDARD.encode(public_key_der.as_bytes());

            if node.pubkey != derived_pubkey {
                println!("Config pubkey: {}", node.pubkey);
                println!("Derived pubkey: {}", derived_pubkey);
                panic!(
                    "Public key mismatch! Config pubkey doesn't match the one derived from private key file!"
                );
            }

            if !node.privkey.is_empty() {
                if node.privkey != file_private_key {
                    panic!("Private key mismatch between config and privateKey.pem file!");
                }
            } else {
                node.privkey = file_private_key;
            }
        }

        if !node.privkey.is_empty() {
            let private_key =
                RsaPrivateKey::from_pkcs8_pem(&node.privkey).expect("Failed to parse private key");
            let public_key = RsaPublicKey::from(&private_key);
            let public_key_der = public_key
                .to_public_key_der()
                .expect("Failed to encode public key");
            let derived_pubkey = general_purpose::STANDARD.encode(public_key_der.as_bytes());

            if node.pubkey != derived_pubkey {
                println!("Config pubkey: {}", node.pubkey);
                println!("Derived pubkey: {}", derived_pubkey);
                panic!("Generated public key doesn't match config pubkey!");
            }
        }

        Ok(node)
    }
    pub fn sign(&self, data: &[u8]) -> String {
        if self.privkey.is_empty() {
            panic!("Private key not found for signing");
        }
        let private_key =
            RsaPrivateKey::from_pkcs8_pem(&self.privkey).expect("Failed to parse private key");
        let signing_key = SigningKey::<Sha256>::new(private_key);
        let signature = signing_key.sign(data);
        general_purpose::STANDARD.encode(signature.to_vec())
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if self.privkey.is_empty() {
            return Err("Private key not found for decryption".into());
        }
        let private_key =
            RsaPrivateKey::from_pkcs8_pem(&self.privkey).expect("Failed to parse private key");

        let rsa_key_size = private_key.size();
        if data.len() < rsa_key_size + 12 {
            return Err("Invalid encrypted data: too short".into());
        }

        let (encrypted_key, rest) = data.split_at(rsa_key_size);
        let (nonce_bytes, ciphertext) = rest.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let padding = rsa::Pkcs1v15Encrypt;
        let symmetric_key = private_key.decrypt(padding, encrypted_key)?;

        let cipher = Aes256Gcm::new_from_slice(&symmetric_key).map_err(|e| {
            Box::<dyn std::error::Error>::from(format!("Failed to create AES cipher: {}", e))
        })?;
        let decrypted_data = cipher.decrypt(nonce, ciphertext).map_err(|e| {
            Box::<dyn std::error::Error>::from(format!("AES decryption failed: {}", e))
        })?;

        Ok(decrypted_data)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicNode {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nodetype: Option<String>,
    pub pubkey: String,
    pub address: String,
    pub public_port: u16,
    pub secure: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strict: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_hashcash: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_hashcash: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_connected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peers: Option<Vec<PublicNode>>,
}

impl From<&Node> for PublicNode {
    fn from(node: &Node) -> Self {
        PublicNode {
            name: Some(node.name.clone()),
            nodetype: Some(node.nodetype.clone()),
            pubkey: node.pubkey.clone(),
            address: node.address.clone(),
            public_port: node.public_port,
            secure: node.secure,
            strict: node.strict,
            is_connected: None,
            last_seen: None,
            min_hashcash: node.min_hashcash,
            suggested_hashcash: node.suggested_hashcash,
            version: node.version.clone(),
            peers: node.peers.clone(),
        }
    }
}
pub fn verify_signature(
    pubkey_b64: &str,
    signature_b64: &str,
    data: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let pubkey_der = general_purpose::STANDARD.decode(pubkey_b64)?;
    let public_key = RsaPublicKey::from_public_key_der(&pubkey_der)?;

    let signature_bytes = general_purpose::STANDARD.decode(signature_b64)?;
    let signature = Signature::try_from(signature_bytes.as_slice())?;

    let verifying_key = VerifyingKey::<Sha256>::new(public_key);

    verifying_key.verify(data, &signature)?;

    Ok(())
}

pub fn encrypt_with_pubkey(
    pubkey_b64: &str,
    data: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|e| Box::<dyn std::error::Error>::from(format!("AES encryption failed: {}", e)))?;

    let pubkey_der = general_purpose::STANDARD.decode(pubkey_b64)?;
    let public_key = RsaPublicKey::from_public_key_der(&pubkey_der)?;
    let padding = rsa::Pkcs1v15Encrypt;
    let encrypted_key = public_key.encrypt(&mut OsRng, padding, key.as_slice())?;

    let mut combined = Vec::with_capacity(encrypted_key.len() + nonce.len() + ciphertext.len());
    combined.extend_from_slice(&encrypted_key);
    combined.extend_from_slice(nonce.as_slice());
    combined.extend_from_slice(&ciphertext);

    Ok(combined)
}
