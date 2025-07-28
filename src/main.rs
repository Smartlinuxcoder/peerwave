#[cfg(feature = "server")]
mod client_on_the_server;
#[cfg(feature = "server")]
mod server;
#[cfg(feature = "server")]
use node::{Node, PublicNode, SignedPublicNode};

#[cfg(feature = "web")]
mod client;

mod message;
mod node;
mod ws_types;
mod routes;
use routes::home::Home;
use dioxus::{document, prelude::*};

#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
enum Route {
    #[layout(Navbar)]
    #[route("/")]
    Home {},
}

const FAVICON: Asset = asset!("/assets/favicon.ico");
const MAIN_CSS: Asset = asset!("/assets/main.css");
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");

#[cfg(feature = "server")]
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{any, get, post},
};
#[cfg(feature = "server")]
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(feature = "server")]
use tower_http::{
    services::ServeDir,
    trace::{DefaultMakeSpan, TraceLayer},
};
#[cfg(feature = "server")]
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
#[cfg(feature = "server")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "server")]
async fn crawl_network(node_clone: Arc<Mutex<Node>>) {
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
                let url = format!("{}://{}:{}/info", protocol, peer.address, peer.public_port);
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
                        println!(
                            "Discovered self. Removing from peer list as it is redundant."
                        );
                        if let Some(peers) = node_guard.peers.as_mut() {
                            peers.retain(|p| p.pubkey != signed_node.node.pubkey);
                        }
                        continue;
                    }
                    let self_pubkey = node_guard.pubkey.clone();
                    let peer_index = node_guard.peers.as_ref().and_then(|p| {
                        p.iter().position(|p| p.pubkey == signed_node.node.pubkey)
                    });

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
                                println!("Signature from peer {} is valid.", peer_address);

                                if let Some(remote_peers) = signed_node.node.peers.clone() {
                                    if let Some(local_peers) = node_guard.peers.as_mut() {
                                        for remote_peer in remote_peers {
                                            if remote_peer.pubkey == self_pubkey {
                                                continue;
                                            }
                                            if !local_peers
                                                .iter()
                                                .any(|p| p.pubkey == remote_peer.pubkey)
                                            {
                                                local_peers.push(remote_peer);
                                            }
                                        }
                                    }
                                }

                                let peer_config =
                                    &mut node_guard.peers.as_mut().unwrap()[index];
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
                                    client_on_the_server::connect(destination, client_node_clone).await;
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
                    println!(
                        "this peer is offline: {}:{}",
                        failed_peer.address, failed_peer.public_port
                    );
                    let mut node_guard = node_clone.lock().unwrap();
                    if let Some(peer_config) = node_guard
                        .peers
                        .as_mut()
                        .and_then(|p| p.iter_mut().find(|p| p.pubkey == failed_peer.pubkey))
                    {
                        peer_config.is_connected = Some(false);
                    }
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(ping_interval as u64)).await;
    }
}

#[cfg(feature = "server")]
async fn launch_server(component: fn() -> Element) {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    // message::test();

    let node = Arc::new(Mutex::new(
        Node::load("config/config.json").expect("Failed to load node configuration"),
    ));

    let node_clone = Arc::clone(&node);
    tokio::spawn(async move {
        crawl_network(node_clone).await;
    });

    let ip =
        dioxus::cli_config::server_ip().unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    let port = dioxus::cli_config::server_port().unwrap_or(8080);
    let address = SocketAddr::new(ip, port);
    let listener = tokio::net::TcpListener::bind(address).await.unwrap();
    let router = Router::new()
        .route("/health", get(|| async { "OK" }))
        .route("/info", get(info_handler))
        .route("/send", post(send_handler))
        .route("/ws", any(server::ws_handler))
        .serve_dioxus_application(ServeConfig::new().unwrap(), App)
        .with_state(Arc::clone(&node))
        .into_make_service();
    axum::serve(listener, router).await.unwrap();
}

fn main() {
    #[cfg(feature = "web")]
    dioxus::launch(App);

    #[cfg(feature = "server")]
    {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async move {
                launch_server(App).await;
            });
    }
}

#[cfg(feature = "server")]
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
#[cfg(feature = "server")]
#[derive(Deserialize)]
struct UserMessage {
    to: String,
    text: String,
}
#[cfg(feature = "server")]
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
        _ => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Silly unwrapping error".to_string(),
            ));
        }
    };

    if let Some(peer) = node_guard
        .peers
        .as_mut()
        .and_then(|peers| peers.iter_mut().find(|p| p.pubkey == routable.pubkey))
    {
        if let Some(conn_state) = &peer.connection_state {
            if let Some(tx) = &conn_state.tx {
                if tx
                    .send(ws_types::Message::Binary(routable.payload))
                    .is_err()
                {
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


#[component]
fn App() -> Element {
    rsx! {
        body { class: "min-h-screen bg-gradient-to-br from-[var(--ctp-base)] via-[var(--ctp-mantle)] to-[var(--ctp-crust)]" }
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: MAIN_CSS }
        document::Link { rel: "stylesheet", href: TAILWIND_CSS }
        Router::<Route> {}
    }
}

#[component]
fn Navbar() -> Element {
    rsx! {
        nav {
            class: "glass-strong p-3 shadow-lg sticky top-0 z-50",
            div {
                class: "container mx-auto flex justify-between items-center",
                div {
                    class: "flex items-center gap-2",
                    svg { 
                        height: "24px", 
                        view_box: "0 0 576 512", 
                        xmlns: "http://www.w3.org/2000/svg",
                        fill: "currentColor",
                        class: "text-[var(--ctp-text)]",
                        path { d: "M64 0C28.7 0 0 28.7 0 64L0 416c0 35.3 28.7 64 64 64l16 0 16 32 64 0 16-32 224 0 16 32 64 0 16-32 16 0c35.3 0 64-28.7 64-64l0-352c0-35.3-28.7-64-64-64L64 0zM224 320a80 80 0 1 0 0-160 80 80 0 1 0 0 160zm0-240a160 160 0 1 1 0 320 160 160 0 1 1 0-320zM480 221.3L480 336c0 8.8-7.2 16-16 16s-16-7.2-16-16l0-114.7c-18.6-6.6-32-24.4-32-45.3c0-26.5 21.5-48 48-48s48 21.5 48 48c0 20.9-13.4 38.7-32 45.3z" }
                    }
                    h1 {
                        class: "text-xl font-bold text-[var(--ctp-text)]",
                        "VaultMaxxing"
                    }
                }
            }
        }
        Outlet::<Route> {}
    }
}
