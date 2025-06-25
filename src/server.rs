use crate::message::{self, Payload};
use crate::node::{Node, PublicNode, SignedPublicNode};
use crate::ws_types::{self, AuthPayload, ConnectionState};
use axum::{
    body::Bytes,
    extract::State,
    extract::{
        connect_info::ConnectInfo,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
};
use futures_util::{sink::SinkExt, stream::StreamExt};
use std::{
    net::SocketAddr,
    ops::ControlFlow,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;
use ws_types::Message as WsMessage;

pub async fn ws_handler(
    State(node): State<Arc<Mutex<Node>>>,
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    println!("{addr} connected.");
    ws.on_upgrade(move |socket| handle_socket(node, socket, addr))
}

async fn handle_socket(node: Arc<Mutex<Node>>, mut socket: WebSocket, who: SocketAddr) {
    if socket
        .send(Message::Ping(Bytes::from_static(&[1, 2, 3])))
        .await
        .is_ok()
    {
        println!("Pinged {who}...");
    } else {
        println!("Could not send ping {who}!");
        return;
    }

    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<WsMessage>();
    let mut conn_state = ConnectionState::new(tx.clone());

    let mut send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let msg = match msg {
                WsMessage::Text(t) => Message::Text(t.into()),
                WsMessage::Binary(b) => Message::Binary(b.into()),
            };
            if sender.send(msg).await.is_err() {
                println!("Client disconnected.");
                break;
            }
        }
    });

    let node_clone = Arc::clone(&node);
    let mut recv_task = tokio::spawn(async move {
        let mut cnt = 0;
        while let Some(Ok(msg)) = receiver.next().await {
            cnt += 1;
            let our_msg = match msg {
                Message::Text(t) => WsMessage::Text(t.to_string()),
                Message::Binary(d) => WsMessage::Binary(d.to_vec()),
                Message::Ping(v) => {
                    println!(">>> {who} sent ping with {v:?}");
                    continue;
                }
                Message::Pong(v) => {
                    println!(">>> {who} sent pong with {v:?}");
                    continue;
                }
                Message::Close(c) => {
                    if let Some(cf) = c {
                        println!(
                            ">>> {who} sent close with code {} and reason `{}`",
                            cf.code, cf.reason
                        );
                    } else {
                        println!(">>> {who} somehow sent close message without CloseFrame");
                    }
                    break;
                }
            };
            let mut node_guard = node_clone.lock().unwrap();
            if process_message(our_msg, who, &mut conn_state, &mut node_guard).is_break() {
                break;
            }
        }
        cnt
    });

    tokio::select! {
        _ = (&mut send_task) => {
            recv_task.abort();
        },
        rv_b = (&mut recv_task) => {
            match rv_b {
                Ok(cnt) => println!("Received {cnt} messages from {who}, closing connection."),
                Err(e) => println!("Error receiving messages from {who}: {e:?}"),
            }
            send_task.abort();
        }
    };

    println!("Websocket context {who} destroyed");
    let mut node_guard = node.lock().unwrap();
    if let Some(peer) = node_guard
        .peers
        .as_mut()
        .and_then(|peers| peers.iter_mut().find(|p| p.connection_state.is_some()))
    {
        peer.is_connected = Some(false);
    }
}

fn process_message(
    msg: WsMessage,
    who: SocketAddr,
    conn_state: &mut ConnectionState,
    node: &mut Node,
) -> ControlFlow<(), ()> {
    if let Some(peer) = node
        .peers
        .as_mut()
        .and_then(|peers| peers.iter_mut().find(|p| p.connection_state.is_some()))
    {
        let pubkey = peer.pubkey.clone();
        ws_types::update_peer_last_seen(node, &pubkey);
    }
    let config = bincode::config::standard();
    match msg {
        WsMessage::Binary(d) => {
            if !conn_state.authenticated {
                if let Ok((payload, _)) =
                    bincode::decode_from_slice::<ws_types::AuthPayload, _>(&d, config)
                {
                    if let ws_types::AuthPayload::Request(req) = payload {
                        println!("Received auth request from {}", req.pubkey);
                        match conn_state.handle_auth_request(req.clone(), node) {
                            Ok(auth_payload) => {
                                let encoded_response =
                                    bincode::encode_to_vec(auth_payload, config).unwrap();
                                if conn_state.tx.as_ref().expect("Kaboom")
                                    .send(WsMessage::Binary(encoded_response.into()))
                                    .is_err()
                                {
                                    return ControlFlow::Break(());
                                }
                                println!("Authenticated peer.");

                                let peer_exists = node.peers.as_ref().map_or(false, |p| p.iter().any(|p| p.pubkey == req.pubkey));
                                if peer_exists {
                                    if let Some(peer) = node.peers.as_mut().and_then(|p| p.iter_mut().find(|p| p.pubkey == req.pubkey)) {
                                        peer.connection_state = Some(conn_state.clone());
                                    }
                                } else {
                                    println!("Peer {} not found, requesting info.", req.pubkey);
                                    if conn_state.tx.as_ref().expect("Kaboom").send(WsMessage::Text("gimme info".to_string())).is_err() {
                                        eprintln!("Failed to send 'gimme info' request to {}", req.pubkey);
                                        return ControlFlow::Break(());
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Auth request failed: {}", e);
                                return ControlFlow::Break(());
                            }
                        }
                    }
                }
            } else {
                match Payload::unwrap_payload(d, node) {
                    Ok(unwrapped) => {
                        match unwrapped {
                            Payload::Blob(blob) => {
                                if let Some(peer) = node
                                    .peers
                                    .as_mut()
                                    .and_then(|peers| peers.iter_mut().find(|p| p.pubkey == blob.pubkey))
                                {
                                    peer.connection_state.clone().unwrap().tx
                                        .expect("Kaboom")
                                        .send(WsMessage::Binary(blob.payload.into()))
                                        .expect("Failed to forward blob");
                                } else {
                                    println!("No peer found : {}", blob.pubkey);
                                }
                            }
                            Payload::Message(message) => {
                                println!(
                                    "Received message from {}: {}",
                                    message.from, message.text
                                );
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to unwrap payload: {}", e);
                        return ControlFlow::Break(());
                    }
                }
            }
        }
        WsMessage::Text(t) => {
            println!(">>> {who} sent str: {t:?}");
            if conn_state.authenticated {
                if let Ok(signed_node) = serde_json::from_str::<SignedPublicNode>(&t) {
                    println!("Received peer info from {}", signed_node.node.address);
                    let node_info_json = match serde_json::to_string(&signed_node.node) {
                        Ok(json) => json,
                        Err(e) => {
                            eprintln!("Failed to serialize received public node: {}", e);
                            return ControlFlow::Continue(());
                        }
                    };

                    if crate::node::verify_signature(
                        &signed_node.node.pubkey,
                        &signed_node.signature,
                        node_info_json.as_bytes(),
                    )
                    .is_ok()
                    {
                        println!("Signature for received peer info is valid.");
                        let mut new_peer = signed_node.node;
                        if new_peer.pubkey == node.pubkey {
                            return ControlFlow::Continue(());
                        }

                        let self_pubkey = node.pubkey.clone();
                        let local_peers = node.peers.get_or_insert_with(Vec::new);

                        if let Some(remote_peers) = new_peer.peers.clone() {
                            for remote_peer in remote_peers {
                                if remote_peer.pubkey == self_pubkey {
                                    continue;
                                }
                                if !local_peers.iter().any(|p| p.pubkey == remote_peer.pubkey) {
                                    println!("Adding new peer from peer list: {}", remote_peer.address);
                                    local_peers.push(remote_peer);
                                }
                            }
                        }

                        if let Some(peers) = new_peer.peers.as_mut() {
                            peers.retain(|p| p.pubkey != self_pubkey);
                        }

                        if !local_peers.iter().any(|p| p.pubkey == new_peer.pubkey) {
                            println!("Adding new peer: {}", new_peer.address);
                            new_peer.connection_state = Some(conn_state.clone());
                            local_peers.push(new_peer);
                        }
                    } else {
                        eprintln!("This shouldn't happen");
                    }
                }
            }
        }
    }
    ControlFlow::Continue(())
}
