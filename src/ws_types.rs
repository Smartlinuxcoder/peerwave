use base64::{engine::general_purpose, Engine};
use tokio::sync::mpsc;
use rsa::rand_core::{OsRng, RngCore};
use bincode::{config, Decode, Encode};
use crate::node::{Node, PublicNode, verify_signature};
use std::time::{SystemTime, UNIX_EPOCH};
use axum::body::Bytes;
use serde::{Serialize, Deserialize};

#[derive(Encode, Decode, PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct AuthRequest {
    pub to: String, // receiving guy
    pub salt: String, // random tomfoolery 
    pub pubkey: String, // the pubkey of sender
}
#[derive(Encode, Decode, PartialEq, Debug, Clone)]
pub struct AuthResponse {
    pub pubkey: String, // pubkey of receiving guy
    pub signature: String, // signature from req
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ConnectionState {
    pub authenticated: bool,
    pub auth_salt: String,
    #[serde(skip)]
    pub tx: Option<mpsc::UnboundedSender<Message>>,
}

impl std::fmt::Debug for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionState")
            .field("authenticated", &self.authenticated)
            .field("auth_salt", &self.auth_salt)
            .finish()
    }
}
#[derive(Encode, Decode, PartialEq, Debug)]
pub enum AuthPayload {
    Request(AuthRequest),
    Response(AuthResponse),
}


impl ConnectionState {
    pub fn new(tx: mpsc::UnboundedSender<Message>) -> Self {
        let mut salt_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut salt_bytes);
        Self {
            authenticated: false,
            auth_salt: general_purpose::STANDARD.encode(salt_bytes),
            tx: Some(tx),
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

pub fn update_peer_last_seen(node: &mut Node, pubkey: &str) {
    if let Some(peer) = node
        .peers
        .as_mut()
        .and_then(|peers| peers.iter_mut().find(|p| p.pubkey == pubkey))
    {
        if let Some(conn_state) = &peer.connection_state {
            if conn_state.authenticated {
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

#[derive(Debug)]
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
}