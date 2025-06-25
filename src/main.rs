mod node;
mod message;
mod client;
mod server;
mod ws_types;

use node::Node;
use node::{PublicNode, SignedPublicNode};

use axum::{
    extract::State,
    http::StatusCode,
    routing::{any, get, post},
    Json, Router,
};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tower_http::{
    services::ServeDir,
    trace::{DefaultMakeSpan, TraceLayer},
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use serde::{Deserialize, Serialize};


#[tokio::main]
async fn main() {
    message::test();
    let node = Arc::new(Mutex::new(
        Node::load("config/config.json").expect("Failed to load node configuration"),
    ));

    let node_clone = Arc::clone(&node);
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        loop {
            let (peers, ping_interval) = {
                let n = node_clone.lock().unwrap();
                (n.peers.clone(), n.ping_interval)
            };

            let peer_info_futures = peers.iter().flatten().map(|peer| {
                let client = client.clone();
                let peer = peer.clone();
                async move {
                    if peer.is_connected == Some(true) {
                        return Ok(None);
                    }
                    let protocol = if peer.secure { "https" } else { "http" };
                    let url =
                        format!("{}://{}:{}/info", protocol, peer.address, peer.public_port);
                    match client.get(&url).send().await {
                        Ok(response) => match response.json::<SignedPublicNode>().await {
                            Ok(signed_node) => Ok(Some(signed_node)),
                            Err(_) => Err(peer),
                        },
                        Err(_) => Err(peer),
                    }
                }
            });

            let results = futures::future::join_all(peer_info_futures).await;
            for result in results {
                match result {
                    Ok(Some(signed_node)) => {
                        println!(
                            "Successfully fetched info for peer: {:?}",
                            signed_node.node.address
                        );
                        let node_info_json = match serde_json::to_string(&signed_node.node) {
                            Ok(json) => json,
                            Err(e) => {
                                eprintln!("Failed to serialize received public node: {}", e);
                                continue;
                            }
                        };

                        let mut node_guard = node_clone.lock().unwrap();
                        if signed_node.node.pubkey == node_guard.pubkey {
                            println!("Discovered self. Removing from peer list as it is redundant.");
                            if let Some(peers) = node_guard.peers.as_mut() {
                                peers.retain(|p| p.pubkey != signed_node.node.pubkey);
                            }
                            continue;
                        }
                        let self_pubkey = node_guard.pubkey.clone();
                        let peer_index = node_guard
                            .peers
                            .as_ref()
                            .and_then(|p| p.iter().position(|p| p.pubkey == signed_node.node.pubkey));

                        if let Some(index) = peer_index {
                            let (peer_pubkey, peer_address) = {
                                let peer = &node_guard.peers.as_ref().unwrap()[index];
                                (peer.pubkey.clone(), peer.address.clone())
                            };

                            match node::verify_signature(
                                &peer_pubkey,
                                &signed_node.signature,
                                node_info_json.as_bytes(),
                            ) {
                                Ok(_) => {
                                    println!(
                                        "Signature from peer {} is valid.",
                                        peer_address
                                    );

                                    if let Some(remote_peers) = signed_node.node.peers.clone() {
                                        if let Some(local_peers) = node_guard.peers.as_mut() {
                                            for remote_peer in remote_peers {
                                                if remote_peer.pubkey == self_pubkey {
                                                    continue;
                                                }
                                                if !local_peers.iter().any(|p| p.pubkey == remote_peer.pubkey) {
                                                    local_peers.push(remote_peer);
                                                }
                                            }
                                        }
                                    }

                                    let peer_config = &mut node_guard.peers.as_mut().unwrap()[index];
                                    let mut new_peer_node = signed_node.node.clone();
                                    if let Some(peers) = new_peer_node.peers.as_mut() {
                                        peers.retain(|p| p.pubkey != self_pubkey);
                                    }
                                    *peer_config = new_peer_node;
                                    let now = SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .expect("You time traveler!")
                                        .as_secs()
                                        as usize;
                                    peer_config.last_seen = Some(now);
                                    peer_config.is_connected = Some(true);
                                    let destination = peer_config.clone();
                                    let client_node_clone = Arc::clone(&node_clone);
                                    tokio::spawn(async move {
                                        client::connect(destination, client_node_clone).await;
                                    });
                                }
                                Err(e) => {
                                    eprintln!(
                                        "Signature verification failed for peer {}: {}",
                                        peer_address, e
                                    );
                                }
                            }
                        } else {
                            eprintln!(
                                "Received info from an unknown peer with public key: {}",
                                signed_node.node.pubkey
                            );
                        }
                    }
                    Ok(None) => {
                        // za bluethoot device is connected
                    }
                    Err(failed_peer) => {
                        println!("this peer is offline: {}:{}", failed_peer.address, failed_peer.public_port);
                        let mut node_guard = node_clone.lock().unwrap();
                        if let Some(peer_config) = node_guard.peers.as_mut().and_then(|p| {
                            p.iter_mut().find(|p| p.pubkey == failed_peer.pubkey)
                        }) {
                            peer_config.is_connected = Some(false);
                        }
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(ping_interval as u64)).await;
        }
    });

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("{}=debug,tower_http=debug", env!("CARGO_CRATE_NAME")).into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let assets_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets");

    let listen_port = node.lock().unwrap().listen_port;
    let app = Router::new()
        .fallback_service(ServeDir::new(assets_dir).append_index_html_on_directories(true))
        .route("/health", get(|| async { "OK" }))
        .route("/info", get(info_handler))
        .route("/send", post(send_handler))
        .route("/ws", any(server::ws_handler))
        .with_state(Arc::clone(&node))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::default().include_headers(true)),
        );

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", listen_port))
        .await
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();

}


async fn info_handler(State(node): State<Arc<Mutex<Node>>>) -> Json<SignedPublicNode> {
    let node_guard = node.lock().unwrap();
    let public_node = PublicNode::from(&*node_guard);
    let node_info_json =
        serde_json::to_string(&public_node).expect("Failed to serialize public node");

    let signature = node_guard.sign(node_info_json.as_bytes());

    let response = SignedPublicNode {
        node: public_node,
        signature,
    };

    Json(response)
}

#[derive(Deserialize)]
struct UserMessage {
    to: String,
    text: String,
}

async fn send_handler(
    State(node): State<Arc<Mutex<Node>>>,
    Json(payload): Json<UserMessage>,
) -> Result<String, (StatusCode, String)> {
    let mut node_guard = node.lock().unwrap();

    let route = match node_guard.route_payload(payload.to) {
        Ok(route) => route,
        Err(e) => return Err((StatusCode::BAD_REQUEST, e)),
    };
    let message_blob = message::Payload::new_payload(route, payload.text, &node_guard);

    let config = bincode::config::standard();
    let routable: message::Blob = match bincode::decode_from_slice(&message_blob, config) {
        Ok((message::Payload::Blob(blob), _)) => blob,
        _ => return Err((StatusCode::INTERNAL_SERVER_ERROR, "Silly unwrapping error".to_string())),
    };

    if let Some(peer) = node_guard
        .peers
        .as_mut()
        .and_then(|peers| peers.iter_mut().find(|p| p.pubkey == routable.pubkey))
    {
        if let Some(conn_state) = &peer.connection_state {
            if let Some(tx) = &conn_state.tx {
                if tx.send(ws_types::Message::Binary(message_blob)).is_err() {
                    peer.is_connected = Some(false);
                    peer.connection_state = None;
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to send message to peer, connection closed.".to_string(),
                    ));
                }
            } else {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Peer has no sender channel".to_string(),
                ));
            }
        } else {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Peer not connected".to_string(),
            ));
        }
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Peer with pubkey {} not found.", routable.pubkey),
        ));
    }

    Ok("all good sir".to_string())
}