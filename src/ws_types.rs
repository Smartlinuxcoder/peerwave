use base64::{engine::general_purpose, Engine};
use rsa::rand_core::{OsRng, RngCore};
use bincode::{config, Decode, Encode};
use crate::node::{Node, PublicNode, verify_signature};
use std::time::{SystemTime, UNIX_EPOCH};
use axum::body::Bytes;

#[derive(Encode, Decode, PartialEq, Debug, Clone)]
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
pub enum AuthPayload {
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
    pub fn send_auth_request(&self, to: String, self_pubkey: &str) -> AuthPayload {
        AuthPayload::Request(AuthRequest {
            to,
            salt: self.auth_salt.clone(),
            pubkey: self_pubkey.to_string(),
        })
    }

    pub fn handle_auth_request(
        &mut self,
        request: AuthRequest,
        node: &Node,
    ) -> Result<AuthPayload, String> {
        let signature = node.sign(request.salt.as_bytes());
        let response = AuthResponse {
            pubkey: node.pubkey.clone(),
            signature,
        };

        self.authenticated = true;
        self.peer_pubkey = Some(request.pubkey);

        Ok(AuthPayload::Response(response))
    }

    pub fn handle_auth_response(
        &mut self,
        response: AuthResponse,
        peers: Option<&Vec<PublicNode>>,
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

        if peers.map_or(false, |p| p.iter().any(|p| p.pubkey == response.pubkey)) {
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

pub fn update_peer_last_seen(conn_state: &ConnectionState, node: &mut Node) {
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