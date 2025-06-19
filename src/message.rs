use std::vec;

use bincode::{config, Decode, Encode};
use rsa::signature;

use crate::message;

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
    pub fn new_payload(pubkeys:Vec<String>, text: String, signature: String) -> Vec<u8> {
        let config = config::standard();
        let mut message_blob =
            bincode::encode_to_vec(&Self::new_message("Arson".to_string(), text, signature), config).expect("Failed to encode message");
        for pubkey in pubkeys {
            message_blob = bincode::encode_to_vec(&Self::new_blob(pubkey, message_blob, "hashcash".to_string()), config)
                .expect("Failed to encode blob");
        }
        return message_blob;
    }
}


pub fn test() {
    let serialized = Payload::new_payload(vec!["Johnathan's key".to_string()], "Hello, Bob!".to_string(), "uihwefwuihesdfse".to_string());
    println!("Serialized Blob: {:?}", serialized);
    let (deserialized, _): (Payload, _) =
        bincode::decode_from_slice(&serialized, config).expect("Failed to deserialize");
    println!("Deserialized Blob: {:#?}", deserialized);
    assert_eq!(serialized, serialized0);
    match deserialized {
        Payload::Message(msg) => {
            println!("Message from: {}", msg.from);
            println!("Message text: {}", msg.text);
            println!("Message signature: {}", msg.signature);
        },
        Payload::Blob(blob) => {
            println!("Blob pubkey: {}", blob.pubkey);
            println!("Blob hashcash: {}", blob.hashcash);
            let (inner_message, _): (Payload, _) = bincode::decode_from_slice(&blob.payload, config)
                .expect("Failed to decode inner message");
            if let Payload::Message(inner_msg) = inner_message {
                println!("Inner Message from: {}", inner_msg.from);
                println!("Inner Message text: {}", inner_msg.text);
                println!("Inner Message signature: {}", inner_msg.signature);
            } else {
                println!("Expected inner message to be of type Message, but got something else.");
            }
        }
    }
}