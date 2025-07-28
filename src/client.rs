use super::node::{Node, PublicNode, SignedPublicNode};
use super::ws_types::{self, ConnectionState, Message as WsMessage};
use futures_util::{future, SinkExt, StreamExt};
use gloo_net::websocket::{futures::WebSocket, Message, WebSocketError};
use std::ops::ControlFlow;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use wasm_bindgen_futures::spawn_local;

pub async fn connect(destination: PublicNode, node: Arc<Mutex<Node>>) {
    println!(
        "Connecting to {}:{}",
        destination.address, destination.public_port
    );
    let server = format!(
        "{}://{}:{}/ws",
        if destination.secure { "wss" } else { "ws" },
        destination.address,
        destination.public_port
    );

    let ws = match WebSocket::open(&server) {
        Ok(ws) => ws,
        Err(e) => {
            println!("WebSocket connection failed: {e:?}");
            let mut node_guard = node.lock().unwrap();
            if let Some(peer) = node_guard
                .peers
                .as_mut()
                .and_then(|peers| peers.iter_mut().find(|p| p.pubkey == destination.pubkey))
            {
                peer.is_connected = Some(false);
            }
            return;
        }
    };
    println!("WebSocket handshake has been completed");

    let (mut sender, mut receiver) = ws.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<WsMessage>();

    let node_clone = Arc::clone(&node);
    spawn_local(async move {
        let send_task = async {
            while let Some(msg) = rx.recv().await {
                let msg = match msg {
                    WsMessage::Text(t) => Message::Text(t),
                    WsMessage::Binary(b) => Message::Bytes(b),
                };
                if sender.send(msg).await.is_err() {
                    println!("Server disconnected.");
                    break;
                }
            }
        };

        let recv_task = async {
            let mut conn_state = ConnectionState::new(tx.clone());
            let auth_payload = {
                let node_guard = node_clone.lock().unwrap();
                conn_state.send_auth_request(destination.pubkey.clone(), &node_guard.pubkey)
            };
            let config = bincode::config::standard();
            let encoded_payload = bincode::encode_to_vec(auth_payload, config).unwrap();

            if tx.send(WsMessage::Binary(encoded_payload.into()))
                .is_err()
            {
                println!("Failed to send auth request.");
                return;
            }
            println!("Sent auth request.");

            while let Some(msg_result) = receiver.next().await {
                let msg = match msg_result {
                    Ok(msg) => msg,
                    Err(e) => {
                        let mut node_guard = node_clone.lock().unwrap();
                        if let Some(peer) = node_guard
                            .peers
                            .as_mut()
                            .and_then(|peers| peers.iter_mut().find(|p| p.pubkey == destination.pubkey))
                        {
                            peer.is_connected = Some(false);
                        }
                        match e {
                            WebSocketError::ConnectionClose(close_event) => {
                                println!("[WebSocket] ConnectionClose: {close_event:#?}");
                            }
                            err => {
                                println!("[WebSocketError]: {err:#?}");
                            }
                        }
                        break;
                    }
                };

                let our_msg = match msg {
                    Message::Text(t) => WsMessage::Text(t),
                    Message::Bytes(b) => WsMessage::Binary(b),
                };

                if process_message(our_msg, &mut conn_state, &node_clone).is_break() {
                    break;
                }
            }
            println!("Receiver task finished.");
        };

        future::join(send_task, recv_task).await;
        println!("Connection to {} finished.", destination.pubkey);
    });
}

fn process_message(
    msg: WsMessage,
    conn_state: &mut ConnectionState,
    node: &Arc<Mutex<Node>>,
) -> ControlFlow<(), ()> {
    let mut node_guard = node.lock().unwrap();
    let peer_pubkey = node_guard
        .peers
        .as_ref()
        .and_then(|p| p.iter().find(|p| p.connection_state.is_some()))
        .map(|p| p.pubkey.clone());

    if let Some(pubkey) = peer_pubkey {
        ws_types::update_peer_last_seen(&mut node_guard, &pubkey);
    }
    let config = bincode::config::standard();
    match msg {
        WsMessage::Text(t) => {
            println!(">>> got str: {t:?}");
            if t == "gimme info" {
                println!("Received info request");
                let public_node = PublicNode::from(&node_guard.clone());
                let node_info_json = match serde_json::to_string(&public_node) {
                    Ok(json) => json,
                    Err(e) => {
                        eprintln!("Failed to serialize public node: {}", e);
                        return ControlFlow::Continue(());
                    }
                };
                let signed_node = SignedPublicNode {
                    node: public_node,
                    signature: node_guard.sign(node_info_json.as_bytes()),
                };
                let response_json = match serde_json::to_string(&signed_node) {
                    Ok(json) => json,
                    Err(e) => {
                        eprintln!("Failed to serialize public node: {}", e);
                        return ControlFlow::Continue(());
                    }
                };
                if conn_state
                    .tx
                    .as_ref()
                    .expect("Kaboom")
                    .send(WsMessage::Text(response_json.into()))
                    .is_err()
                {
                    return ControlFlow::Break(());
                }
            }
        }
        WsMessage::Binary(d) => {
            if !conn_state.authenticated {
                if let Ok((payload, _)) =
                    bincode::decode_from_slice::<ws_types::AuthPayload, _>(&d, config)
                {
                    if let ws_types::AuthPayload::Response(resp) = payload {
                        println!("Received auth response from {}", resp.pubkey);
                        let peers = node_guard.peers.clone();
                        match conn_state.handle_auth_response(resp.clone(), peers.as_ref()) {
                            Ok(_) => {
                                println!("Successfully authenticated with peer.");
                                if let Some(peer) = node_guard.peers.as_mut().and_then(|p| {
                                    p.iter_mut().find(|p| p.pubkey == resp.pubkey)
                                }) {
                                    peer.is_connected = Some(true);
                                    peer.connection_state = Some(conn_state.clone());
                                }
                            }
                            Err(e) => {
                                eprintln!("Auth response failed: {}", e);
                                return ControlFlow::Break(());
                            }
                        }
                    }
                }
            } else {
                println!(">>> got {} bytes: {d:?}", d.len());
            }
        }
    }
    ControlFlow::Continue(())
}
