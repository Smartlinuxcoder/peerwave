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

pub async fn ws_handler(
    State(node): State<Arc<Mutex<Node>>>,
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    println!("{addr} connected.");
    ws.on_upgrade(move |socket| handle_socket(node, socket, addr))
}

async fn handle_socket(node: Arc<Mutex<Node>>, mut socket: WebSocket, who: SocketAddr) {
    let mut conn_state = ConnectionState::new();
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
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    let mut send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
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
            let mut node_guard = node_clone.lock().unwrap();
            if process_message(msg, who, &mut conn_state, &mut node_guard, &tx).is_break() {
                break;
            }
        }
        (cnt, conn_state)
    });

    let conn_state = tokio::select! {
        rv_a = (&mut send_task) => {
            match rv_a {
                Ok(_) => println!("Send task for {who} finished."),
                Err(a) => println!("Error in send task for {who}: {a:?}")
            }
            recv_task.abort();
            None
        },
        rv_b = (&mut recv_task) => {
            let res = match rv_b {
                Ok((b, conn_state)) => {
                    println!("Received {b} messages from {who}, closing connection.");
                    Some(conn_state)
                }
                Err(b) => {
                    println!("Error receiving messages from {who}: {b:?}");
                    None
                }
            };
            send_task.abort();
            res
        }
    };

    println!("Websocket context {who} destroyed");
    if let Some(conn_state) = conn_state {
        if let Some(pubkey) = conn_state.peer_pubkey {
            let mut node_guard = node.lock().unwrap();
            if let Some(peer) = node_guard
                .peers
                .as_mut()
                .and_then(|peers| peers.iter_mut().find(|p| p.pubkey == pubkey))
            {
                peer.is_connected = Some(false);
            }
        }
    }
}

fn process_message(
    msg: Message,
    who: SocketAddr,
    conn_state: &mut ConnectionState,
    node: &mut Node,
    tx: &mpsc::UnboundedSender<Message>,
) -> ControlFlow<(), ()> {
    ws_types::update_peer_last_seen(conn_state, node);
    let config = bincode::config::standard();
    match msg {
        Message::Text(t) => {
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
                        let new_peer = signed_node.node;
                        if new_peer.pubkey == node.pubkey {
                            return ControlFlow::Continue(());
                        }
                        let peers = node.peers.get_or_insert_with(Vec::new);
                        println!("{:?}", new_peer);
                        if !peers.iter().any(|p| p.pubkey == new_peer.pubkey) {
                            println!("Adding new peer: {}", new_peer.address);
                            peers.push(new_peer);
                        }
                    } else {
                        eprintln!("This shouldn't happen");
                    }
                }
            }
        }
        Message::Binary(d) => {
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
                                if tx.send(Message::Binary(encoded_response.into())).is_err() {
                                    return ControlFlow::Break(());
                                }
                                println!(
                                    "Authenticated peer {}",
                                    conn_state.peer_pubkey.as_ref().unwrap()
                                );

                                if let Some(pubkey) = conn_state.peer_pubkey.as_ref() {
                                    if let Some(peer) = node.peers.as_mut().and_then(|peers| {
                                        peers.iter_mut().find(|p| p.pubkey == *pubkey)
                                    }) {
                                        peer.is_connected = Some(true);
                                        peer.last_seen = Some(
                                            SystemTime::now()
                                                .duration_since(UNIX_EPOCH)
                                                .unwrap()
                                                .as_secs()
                                                as usize,
                                        );
                                    }
                                }

                                if !node.peers.as_ref().map_or(false, |p| {
                                    p.iter().any(|peer| peer.pubkey == req.pubkey)
                                }) {
                                    println!(
                                        "Peer {} not in peer list. Requesting info.",
                                        req.pubkey
                                    );
                                    let info_req = "gimme info";
                                    if tx.send(Message::Text(info_req.to_string().into())).is_err()
                                    {
                                        return ControlFlow::Break(());
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Auth request failed: {}", e);
                                return ControlFlow::Break(());
                            }
                        }
                    } else {
                        println!("Received unexpected auth payload from unauthenticated peer.");
                        return ControlFlow::Break(());
                    }
                } else {
                    println!("Failed to decode binary message from unauthenticated peer.");
                    return ControlFlow::Break(());
                }
            } else {
                println!("Received binary message from authenticated peer.");
            }
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
            return ControlFlow::Break(());
        }

        Message::Pong(v) => {
            println!(">>> {who} sent pong with {v:?}");
        }

        Message::Ping(v) => {
            println!(">>> {who} sent ping with {v:?}");
        }
    }
    ControlFlow::Continue(())
}
