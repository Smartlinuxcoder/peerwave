use super::node::PublicNode;
use futures_util::{SinkExt, StreamExt};
use std::ops::ControlFlow;
use tokio_tungstenite::tungstenite::Utf8Bytes;
use tokio_tungstenite::{
    connect_async,
    tungstenite::protocol::{CloseFrame, Message, frame::coding::CloseCode},
};



pub async fn connect(destination: &PublicNode) {
    println!("Connecting to {}:{}", destination.address, destination.public_port);
    let server = format!(
        "{}://{}:{}",
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
            return;
        }
    };

    let (mut sender, mut receiver) = ws_stream.split();

    sender
        .send(Message::Ping(axum::body::Bytes::from_static(
            b"Hello, Server!",
        )))
        .await
        .expect("Can not send!");

    let mut send_task = tokio::spawn(async move {
        for i in 1..30 {
            if sender
                .send(Message::Text(format!("Message number {i}...").into()))
                .await
                .is_err()
            {
                return;
            }

            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        }

        if let Err(e) = sender
            .send(Message::Close(Some(CloseFrame {
                code: CloseCode::Normal,
                reason: Utf8Bytes::from_static("Goodbye"),
            })))
            .await
        {
            println!("Could not send Close due to {e:?}, probably it is ok?");
        };
    });

    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if process_message(msg).is_break() {
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
    }
}

fn process_message(msg: Message) -> ControlFlow<(), ()> {
    match msg {
        Message::Text(t) => {
            println!(">>> got str: {t:?}");
        }
        Message::Binary(d) => {
            println!(">>> got {} bytes: {d:?}", d.len());
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
            return ControlFlow::Break(());
        }

        Message::Pong(v) => {
            println!(">>> got pong with {v:?}");
        }

        Message::Ping(v) => {
            println!(">>> got ping with {v:?}");
        }

        Message::Frame(_) => {
            unreachable!("This is never supposed to happen")
        }
    }
    ControlFlow::Continue(())
}
