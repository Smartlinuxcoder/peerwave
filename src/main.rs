mod node;
use node::Node;
use node::PublicNode;
use axum::{
    body::Bytes,
    extract::{State, ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade}},
    response::IntoResponse,
    routing::{any, get},
    Json,
    Router,
};
use std::ops::ControlFlow;
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

use axum::extract::connect_info::ConnectInfo;
use axum::extract::ws::CloseFrame;

use futures_util::{sink::SinkExt, stream::StreamExt};

#[derive(serde::Serialize, serde::Deserialize)]
struct SignedPublicNode {
    node: PublicNode,
    signature: String,
}

#[tokio::main]
async fn main() {
    let node = Arc::new(Mutex::new(
        Node::load("config/config.json").expect("Failed to load node configuration"),
    ));

    let node_clone = Arc::clone(&node);
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        loop {
            let (peers, max_retries, ping_interval) = {
                let n = node_clone.lock().unwrap();
                (n.peers.clone(), n.max_retries, n.ping_interval)
            };

            let peer_info_futures = peers.iter().flatten().map(|peer| {
                let client = client.clone();
                let protocol = if peer.secure { "https" } else { "http" };
                let url = format!("{}://{}:{}/info", protocol, peer.address, peer.public_port);
                async move {
                    let mut retries = 0;
                    while retries < max_retries {
                        match client.get(&url).send().await {
                            Ok(response) => match response.json::<SignedPublicNode>().await {
                                Ok(signed_node) => return Some(signed_node),
                                Err(_) => retries += 1,
                            },
                            Err(_) => retries += 1,
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(ping_interval as u64))
                            .await;
                    }
                    None
                }
            });

            let results = futures::future::join_all(peer_info_futures).await;
            for result in results {
                if let Some(signed_node) = result {
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
                    if let Some(peer_config) = node_guard
                        .peers
                        .as_mut()
                        .and_then(|p| p.iter_mut().find(|p| p.pubkey == signed_node.node.pubkey))
                    {
                        match node::verify_signature(
                            &peer_config.pubkey,
                            &signed_node.signature,
                            node_info_json.as_bytes(),
                        ) {
                            Ok(_) => {
                                println!("Signature from peer {} is valid.", peer_config.address);
                                *peer_config = signed_node.node.clone();
                                let now = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .expect("You time traveler!")
                                    .as_secs()
                                    as usize;
                                peer_config.last_seen = Some(now);
                                println!("Peer info for {} updated.", peer_config.address);
                            }
                            Err(e) => {
                                eprintln!(
                                    "Signature verification failed for peer {}: {}",
                                    peer_config.address, e
                                );
                            }
                        }
                    } else {
                        eprintln!(
                            "Received info from an unknown peer with public key: {}",
                            signed_node.node.pubkey
                        );
                    }
                } else {
                    println!("Failed to fetch info for a peer after max retries.");
                }
            }
            let ping_interval = { node_clone.lock().unwrap().ping_interval };
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

    let listen_port = node.lock().unwrap().listen_port.unwrap();
    let app = Router::new()
        .fallback_service(ServeDir::new(assets_dir).append_index_html_on_directories(true))
        .route("/health", get(|| async { "OK" }))
        .route("/info", get(info_handler))
        .route("/ws", any(ws_handler))
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

async fn ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {  

    println!("{addr} connected.");
    ws.on_upgrade(move |socket| handle_socket(socket, addr))
}

/// Actual websocket statemachine (one will be spawned per connection)
async fn handle_socket(mut socket: WebSocket, who: SocketAddr) {
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

    let mut send_task = tokio::spawn(async move {
        let n_msg = 20;
        for i in 0..n_msg {
            if sender
                .send(Message::Text(format!("Server message {i} ...").into()))
                .await
                .is_err()
            {
                return i;
            }

            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        }

        println!("Sending close to {who}...");
        if let Err(e) = sender
            .send(Message::Close(Some(CloseFrame {
                code: axum::extract::ws::close_code::NORMAL,
                reason: Utf8Bytes::from_static("Goodbye"),
            })))
            .await
        {
            println!("Could not send Close due to {e}");
        }
        n_msg
    });

    let mut recv_task = tokio::spawn(async move {
        let mut cnt = 0;
        while let Some(Ok(msg)) = receiver.next().await {
            cnt += 1;
            // print message and break if instructed to do so
            if process_message(msg, who).is_break() {
                break;
            }
        }
        cnt
    });

    tokio::select! {
        rv_a = (&mut send_task) => {
            match rv_a {
                Ok(a) => println!("{a} messages sent to {who}"),
                Err(a) => println!("Error sending messages {a:?}")
            }
            recv_task.abort();
        },
        rv_b = (&mut recv_task) => {
            match rv_b {
                Ok(b) => println!("Received {b} messages"),
                Err(b) => println!("Error receiving messages {b:?}")
            }
            send_task.abort();
        }
    }

    println!("Websocket context {who} destroyed");
}

fn process_message(msg: Message, who: SocketAddr) -> ControlFlow<(), ()> {
    match msg {
        Message::Text(t) => {
            println!(">>> {who} sent str: {t:?}");
        }
        Message::Binary(d) => {
            println!(">>> {who} sent {} bytes: {d:?}", d.len());
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
        // You should never need to manually handle Message::Ping, as axum's websocket library
        // will do so for you automagically by replying with Pong and copying the v according to
        // spec. But if you need the contents of the pings you can see them here.
        Message::Ping(v) => {
            println!(">>> {who} sent ping with {v:?}");
        }
    }
    ControlFlow::Continue(())
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