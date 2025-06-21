use bincode::{Decode, Encode, config};

use super::node::{self, Node};

#[derive(Encode, Decode, PartialEq, Debug)]
pub struct Blob {
    pubkey: String,
    payload: Vec<u8>,
    hashcash: String,
}

#[derive(Encode, Decode, PartialEq, Debug)]
pub struct Message {
    from: String,
    text: String,
    signature: String,
}

#[derive(Encode, Decode, PartialEq, Debug)]
pub enum Payload {
    Blob(Blob),
    Message(Message),
}

impl Payload {
    pub fn new_blob(pubkey: String, payload: Vec<u8>, hashcash: String) -> Self {
        Payload::Blob(Blob {
            pubkey,
            payload,
            hashcash,
        })
    }
    pub fn new_message(from: String, text: String, signature: String) -> Self {
        Payload::Message(Message {
            from,
            text,
            signature,
        })
    }
    pub fn new_payload(pubkeys: Vec<String>, text: String, node: &Node) -> Vec<u8> {
        let config = config::standard();
        let signature = node.sign(text.as_bytes());
        let mut message_blob = bincode::encode_to_vec(
            &Self::new_message(node.pubkey.clone(), text, signature),
            config,
        )
        .expect("Failed to encode message");
        for pubkey in pubkeys.iter().rev() {
            let encrypted_payload = node::encrypt_with_pubkey(pubkey, &message_blob)
                .expect("Failed to encrypt payload");
            message_blob = bincode::encode_to_vec(
                &Self::new_blob(pubkey.clone(), encrypted_payload, "hashcash".to_string()),
                config,
            )
            .expect("Failed to encode blob");
        }
        println!("{}", message_blob.len());
        return message_blob;
    }

    pub fn unwrap_payload(&self, node: &Node) -> Result<Payload, Box<dyn std::error::Error>> {
        let config = config::standard();
        match self {
            Payload::Blob(blob) => {
                if blob.pubkey == node.pubkey {
                    let decrypted_payload = node.decrypt(&blob.payload)?;
                    let (unwrapped_payload, _): (Payload, _) =
                        bincode::decode_from_slice(&decrypted_payload, config)?;
                    Ok(unwrapped_payload)
                } else {
                    Err("Public key does not match node's public key".into())
                }
            }
            Payload::Message(_) => {
                Err("Payload is already a message, cannot unwrap further".into())
            }
        }
    }
}
/* 
pub fn test() {
    let mut rng = rsa::rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key");
    let public_key = RsaPublicKey::from(&private_key);
    let public_key_der = public_key.to_public_key_der().unwrap();
    let pubkey_b64 = general_purpose::STANDARD.encode(public_key_der.as_bytes());
    let privkey_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("Failed to encode private key to PEM");

    let test_node = Node {
        name: "Test Node".to_string(),
        nodetype: "Test".to_string(),
        pubkey: pubkey_b64.clone(),
        privkey: privkey_pem.to_string(),
        address: "localhost".to_string(),
        listen_port: 1234,
        public_port: 1234,
        secure: false,
        strict: Some(false),
        min_hashcash: Some(0),
        suggested_hashcash: Some(0),
        version: Some("0.1.0".to_string()),
        peers: None,
        ping_interval: 60,
    };

    let serialized = Payload::new_payload(
        vec![test_node.pubkey.clone()],
        "Hello, Bob!".to_string(),
        &test_node,
    );
    //println!("Serialized Blob: {:?}", serialized);
    let config = config::standard();
    let (deserialized, _): (Payload, _) =
        bincode::decode_from_slice(&serialized, config).expect("Failed to deserialize");
    //println!("Deserialized Blob: {:#?}", deserialized);

    match deserialized.unwrap_payload(&test_node) {
        Ok(unwrapped) => {
            //println!("Unwrapped payload: {:#?}", unwrapped);
            if let Payload::Message(msg) = unwrapped {
                //println!("Message from: {}", msg.from);
                //println!("Message text: {}", msg.text);
                //println!("Message signature: {}", msg.signature);
                assert_eq!(msg.text, "Hello, Bob!");
            } else {
                panic!("Expected a message after unwrapping");
            }
        }
        Err(e) => {
            panic!("Failed to unwrap payload: {}", e);
        }
    }
}
 */