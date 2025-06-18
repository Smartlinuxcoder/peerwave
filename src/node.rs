use base64::{Engine as _, engine::general_purpose};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
    rand_core::OsRng,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Node {
    pub name: String,
    pub nodetype: String,
    pub pubkey: String,
    privkey: Option<String>,
    pub address: String,
    pub listen_port: Option<u16>,
    pub public_port: u16,
    pub secure: bool,
    pub strict: Option<bool>,
    pub min_hashcash: Option<usize>,
    pub suggested_hashcash: Option<usize>,
    pub last_seen: Option<usize>,
    pub version: Option<String>,
    pub peers: Option<Vec<PublicNode>>,
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
            if node.privkey.is_none() {
                let mut rng = OsRng;
                let private_key =
                    RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key");
                let pem_key = private_key
                    .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                    .expect("Failed to encode private key to PEM");

                node.privkey = Some(pem_key.to_string());
                fs::write(private_key_path, &pem_key).expect("Failed to write private key file");
            } else {
                // Save existing private key from config to file
                fs::write(private_key_path, node.privkey.as_ref().unwrap())
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

            if let Some(config_private_key) = &node.privkey {
                if config_private_key != &file_private_key {
                    panic!("Private key mismatch between config and privateKey.pem file!");
                }
            } else {
                node.privkey = Some(file_private_key);
            }
        }

        // Always verify pubkey matches privkey when both are available
        if let Some(privkey_pem) = &node.privkey {
            let private_key = RsaPrivateKey::from_pkcs8_pem(privkey_pem)
                .expect("Failed to parse private key");
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
            min_hashcash: node.min_hashcash,
            suggested_hashcash: node.suggested_hashcash,
            last_seen: node.last_seen,
            version: node.version.clone(),
            peers: node.peers.clone(),
        }
    }
}