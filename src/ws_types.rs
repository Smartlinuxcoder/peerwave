use crate::node::{self, PublicNode};
use base64::{engine::general_purpose, Engine};
use rsa::rand_core::{OsRng, RngCore};
use bincode::{config, Decode, Encode};
use crate::node::{Node, verify_signature};
use std::time::{SystemTime, UNIX_EPOCH};
use axum::body::Bytes;

#[derive(Encode, Decode, PartialEq, Debug)]
pub struct AuthRequest {
    pub to: String, // receiving guy
    pub salt: String, // random tomfoolery 
    pub pubkey: String, // the pubkey of sender
}
#[derive(Encode, Decode, PartialEq, Debug)]
pub struct AuthResponse {
    pub pubkey: String, // pubkey of receiving guy
    pub signature: String, // signature from req
}

pub struct ConnectionState {
    pub peer_pubkey: Option<String>,
    pub authenticated: bool,
    pub auth_salt: String,
}
#[derive(Encode, Decode, PartialEq, Debug)]
enum AuthPayload {
    Request(AuthRequest),
    Response(AuthResponse),
}


impl ConnectionState {
    pub fn new() -> Self {
        let mut salt_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut salt_bytes);
        Self {
            peer_pubkey: None,
            authenticated: false,
            auth_salt: general_purpose::STANDARD.encode(salt_bytes),
        }
    }
    pub fn send_auth_request(&self, to: String, node: &Node) -> AuthPayload {
        AuthPayload::Request(AuthRequest {
            to: to,
            salt: self.auth_salt.clone(),
            pubkey: node.pubkey.clone(),
        })
    }
    pub fn handle_auth_response(
        &mut self,
        response: AuthResponse,
        node: &Node,
    ) -> Result<(), String> {
        if verify_signature(
            &response.pubkey,
            &response.signature,
            self.auth_salt.as_bytes(),
        )
        .is_err()
        {
            return Err("Invalid signature in auth response".to_string());
        }

        if node
            .peers
            .as_ref()
            .map_or(false, |p| p.iter().any(|p| p.pubkey == response.pubkey))
        {
            self.peer_pubkey = Some(response.pubkey);
            self.authenticated = true;
            Ok(())
        } else {
            Err(format!(
                "Peer with pubkey {} not found in local peer list.",
                response.pubkey
            ))
        }
    }
}

pub fn handle_bin_message(bytes: Bytes, conn_state: &mut ConnectionState, node: &mut Node) {
    if conn_state.authenticated {
        if let Some(pubkey) = &conn_state.peer_pubkey {
            if let Some(peer) = node
                .peers
                .as_mut()
                .and_then(|peers| peers.iter_mut().find(|p| p.pubkey == *pubkey))
            {
                peer.last_seen = Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as usize,
                );
            }
        }
    }
}