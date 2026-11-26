use super::{WsFramedStream, WsMessage};
use crate::{tcp::FramedStream, ResultType};
use anyhow::{bail, Context};
use bytes::{Bytes, BytesMut};
use futures::{future::Either, SinkExt, StreamExt};
use std::{net::SocketAddr, time::Duration};
use tokio::sync::mpsc;
use tokio_tungstenite::{
    accept_hdr_async, client_async,
    tungstenite::handshake::server::{Request, Response},
    MaybeTlsStream,
};

const PATH: &str = "/rustdesk/direct";

impl WsFramedStream {
    /// Negotiate RFC 6455 on a fresh TCP connection obtained from rendezvous.
    /// The caller authenticates the resulting peer with the normal RustDesk handshake.
    pub async fn on_punched_tcp(
        tcp: &mut FramedStream,
        peer: Option<SocketAddr>,
    ) -> ResultType<Self> {
        if tcp.is_secured() || !tcp.read_buffer().is_empty() || !tcp.write_buffer().is_empty() {
            bail!("WebSocket negotiation needs a fresh TCP connection");
        }
        let addr = tcp.local_addr();
        let original = std::mem::replace(tcp, FramedStream::from(tokio::io::duplex(1).0, addr));
        let io = MaybeTlsStream::Plain(original.0.into_inner());
        let websocket = match peer {
            Some(peer) => client_async(format!("ws://{peer}{PATH}"), io).await?.0,
            None => {
                accept_hdr_async(io, |request: &Request, response: Response| {
                    // A web page cannot attach to an authenticated desktop session.
                    if request.uri().path_and_query().map(|p| p.as_str()) != Some(PATH)
                        || request.headers().contains_key("origin")
                    {
                        let mut denied = tungstenite::http::Response::new(None);
                        *denied.status_mut() = tungstenite::http::StatusCode::FORBIDDEN;
                        return Err(denied);
                    }
                    Ok(response)
                })
                .await?
            }
        };
        Ok(Self {
            stream: Either::Right(websocket),
            verified_tls: false,
            addr,
            encrypt: None,
            send_timeout: 0,
        })
    }

    /// Move an authenticated WebSocket into the live path bridge. Either direction can
    /// progress while the other's socket or application queue is applying backpressure.
    pub async fn forward_authenticated(
        &mut self,
        incoming: mpsc::Sender<BytesMut>,
        mut outgoing: mpsc::Receiver<Bytes>,
    ) -> ResultType<()> {
        let mut recv_key = self.encrypt.take().context("Unsecured WebSocket path")?;
        let mut send_key = recv_key.clone();
        let timeout = Duration::from_millis(self.send_timeout.max(5_000));
        let (mut writer, mut reader) = (&mut self.stream).split();
        let read = async {
            while let Some(message) = reader.next().await {
                match message? {
                    WsMessage::Binary(data) => {
                        let mut frame = BytesMut::from(data.as_ref());
                        recv_key.dec(&mut frame)?;
                        if incoming.send(frame).await.is_err() {
                            break;
                        }
                    }
                    WsMessage::Close(_) => break,
                    WsMessage::Text(_) => bail!("Unexpected text in authenticated WebSocket"),
                    _ => {}
                }
            }
            Ok(())
        };
        let write = async {
            while let Some(frame) = outgoing.recv().await {
                let msg = WsMessage::Binary(send_key.enc(&frame).into());
                tokio::time::timeout(timeout, writer.send(msg)).await??;
            }
            Ok(())
        };
        tokio::select! { result = read => result, result = write => result }
    }
}
