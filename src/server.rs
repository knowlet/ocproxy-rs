//! Host sockets are listeners only. Every outbound connection uses `Network`.
use crate::{
    config::{ListenerKind, ListenerSpec},
    socks,
    stack::Network,
};
use std::{io, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};

pub struct BoundListener {
    pub listener: TcpListener,
    pub kind: ListenerKind,
}

/// Bind the complete configuration before exposing readiness. A failure drops
/// every previously bound socket, so startup cannot silently omit a forward.
pub async fn bind_all(specs: &[ListenerSpec]) -> io::Result<Vec<BoundListener>> {
    let mut listeners = Vec::with_capacity(specs.len());
    for spec in specs {
        let listener = TcpListener::bind(spec.bind)
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("cannot bind {}: {e}", spec.bind)))?;
        listeners.push(BoundListener {
            listener,
            kind: spec.kind.clone(),
        });
    }
    Ok(listeners)
}

/// Owns the tasks for one listener. Dropping this future aborts its client tasks.
pub async fn serve(
    bound: BoundListener,
    network: Network,
    permits: Arc<Semaphore>,
    handshake_timeout: Duration,
    connect_timeout: Duration,
) -> io::Result<()> {
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            accepted = bound.listener.accept() => {
                let (stream, peer) = accepted?;
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    tracing::debug!(%peer, "connection limit reached");
                    drop(stream);
                    continue;
                };
                let network = network.clone();
                let kind = bound.kind.clone();
                clients.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle_client(stream, kind, network, handshake_timeout, connect_timeout).await {
                        tracing::debug!(%peer, %error, "client connection ended");
                    }
                });
            }
            completed = clients.join_next(), if !clients.is_empty() => {
                if let Some(Err(error)) = completed {
                    return Err(io::Error::other(format!("client task failed: {error}")));
                }
            }
        }
    }
}

async fn handle_client(
    mut stream: TcpStream,
    kind: ListenerKind,
    network: Network,
    handshake_timeout: Duration,
    connect_timeout: Duration,
) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let is_socks = matches!(kind, ListenerKind::Socks);
    let target = match kind {
        ListenerKind::Socks => timeout(handshake_timeout, socks::handshake(&mut stream))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS handshake timed out"))??,
        ListenerKind::Forward(target) => target,
    };
    let result = timeout(connect_timeout, network.connect(target))
        .await
        .unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "VPN connection timed out",
            ))
        });
    let mut connected = match result {
        Ok(connected) => connected,
        Err(error) => {
            if is_socks {
                let _ = timeout(handshake_timeout, socks::reply(&mut stream, Err(&error))).await;
            }
            return Err(error);
        }
    };
    if is_socks {
        timeout(
            handshake_timeout,
            socks::reply(&mut stream, Ok(connected.local_addr)),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS reply timed out"))??;
    }
    // copy_bidirectional forwards EOF independently in each direction. It keeps
    // reading the response after a client shuts down its request-writing half.
    tokio::io::copy_bidirectional(&mut stream, &mut connected.stream).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn binding_failure_does_not_return_partial_service() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let specs = [
            ListenerSpec {
                bind: "127.0.0.1:0".parse().unwrap(),
                kind: ListenerKind::Socks,
            },
            ListenerSpec {
                bind: occupied.local_addr().unwrap(),
                kind: ListenerKind::Socks,
            },
        ];
        assert!(bind_all(&specs).await.is_err());
    }
}
