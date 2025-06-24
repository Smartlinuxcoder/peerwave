use super::node::{Node, PublicNode, SignedPublicNode};
use super::ws_types::{self, ConnectionState};
use futures_util::{SinkExt, StreamExt};
use std::ops::ControlFlow;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio_tungstenite::{
    connect_async,
    tungstenite::protocol::Message,
};
use ws_types::Message as WsMessage;

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
    let ws_stream = match connect_async(server).await {
        Ok((stream, response)) => {
            println!("Handshake has been completed");
            println!("Server response was {response:?}");
            stream
        }
        Err(e) => {
            println!("WebSocket handshake for client failed with {e}!");
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

    let (mut sender, mut receiver) = ws_stream.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<WsMessage>();
    let mut send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let msg = match msg {
                WsMessage::Text(t) => Message::Text(t.into()),
                WsMessage::Binary(b) => Message::Binary(b.into()),
            };
            if sender.send(msg).await.is_err() {
                println!("Server disconnected.");
                break;
            }
        }
    });

    let mut conn_state = ConnectionState::new(tx.clone());
    let auth_payload = {
        let node_guard = node.lock().unwrap();
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

    let node_clone = Arc::clone(&node);
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            let our_msg = match msg {
                Message::Text(t) => WsMessage::Text(t.to_string()),
                Message::Binary(b) => WsMessage::Binary(b.to_vec()),
                Message::Ping(v) => {
                    println!(">>> got ping with {v:?}");
                    continue;
                }
                Message::Pong(v) => {
                    println!(">>> got pong with {v:?}");
                    continue;
                }
                Message::Close(c) => {
                    if let Some(cf) = c {
                        println!(
                            ">>>  got close with code {} and reason `{}`",
                            cf.code, cf.reason
                        );
                    } else {
                        println!(">>> somehow got close message without CloseFrame");
                    }
                    break;
                }
                Message::Frame(_) => {
                    unreachable!("This is never supposed to happen")
                }
            };
            let mut node_guard = node_clone.lock().unwrap();
            let peers = node_guard.peers.clone();
            if process_message(
                our_msg,
                &mut conn_state,
                &mut node_guard,
                peers.as_ref(),
            )
            .is_break()
            {
                break;
            }
        }
    });

    tokio::select! {
        _ = (&mut send_task) => {
            recv_task.abort();
        },
        _ = (&mut recv_task) => {
            send_task.abort();
        }
    };

    println!(
        "Connection with {}:{} closed.",
        destination.address, destination.public_port
    );
    let mut node_guard = node.lock().unwrap();
    if let Some(peer) = node_guard
        .peers
        .as_mut()
        .and_then(|peers| peers.iter_mut().find(|p| p.pubkey == destination.pubkey))
    {
        peer.is_connected = Some(false);
    }
}

fn process_message(
    msg: WsMessage,
    conn_state: &mut ConnectionState,
    node: &mut Node,
    peers: Option<&Vec<PublicNode>>,
) -> ControlFlow<(), ()> {
    if let Some(peer) = peers.and_then(|p| p.iter().find(|p| p.connection_state.is_some())) {
        ws_types::update_peer_last_seen(node, &peer.pubkey);
    }
    let config = bincode::config::standard();
    match msg {
        WsMessage::Text(t) => {
            println!(">>> got str: {t:?}");
            if t == "gimme info" {
                println!("Received info request");
                let public_node = PublicNode::from(&node.clone());
                let node_info_json = match serde_json::to_string(&public_node) {
                    Ok(json) => json,
                    Err(e) => {
                        eprintln!("Failed to serialize public node: {}", e);
                        return ControlFlow::Continue(());
                    }
                };
                let signed_node = SignedPublicNode {
                    node: public_node,
                    signature: node.sign(node_info_json.as_bytes()),
                };
                let response_json = match serde_json::to_string(&signed_node) {
                    Ok(json) => json,
                    Err(e) => {
                        eprintln!("Failed to serialize public node: {}", e);
                        return ControlFlow::Continue(());
                    }
                };
                if conn_state.tx.as_ref().expect("Kaboom").send(WsMessage::Text(response_json.into())).is_err() {
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
                        match conn_state.handle_auth_response(resp, peers) {
                            Ok(_) => {
                                println!("Successfully authenticated with peer.");
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
