use crate::node::Node;
use crate::ws_types::{self, ConnectionState};
use axum::{
    body::Bytes,
    extract::State,
    extract::{
        connect_info::ConnectInfo,
        ws::{CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketUpgrade},
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

    let node_clone = Arc::clone(&node);
    let mut recv_task = tokio::spawn(async move {
        let mut cnt = 0;
        while let Some(Ok(msg)) = receiver.next().await {
            cnt += 1;
            // print message and break if instructed to do so
            let mut node_guard = node_clone.lock().unwrap();
            if process_message(msg, who, &mut conn_state, &mut node_guard).is_break() {
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

fn process_message(
    msg: Message,
    who: SocketAddr,
    conn_state: &mut ConnectionState,
    node: &mut Node,
) -> ControlFlow<(), ()> {
    match msg {
        Message::Text(t) => {
            println!(">>> {who} sent str: {t:?}");
        }
        Message::Binary(d) => {
            ws_types::handle_bin_message(d, conn_state, node);
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
