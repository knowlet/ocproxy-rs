#[cfg(not(unix))]
compile_error!("ocproxy-rs requires Unix and OpenConnect's --script-tun socket interface");

use anyhow::{Context, Result, bail};
use clap::Parser;
use ocproxy_rs::{
    config::{Cli, ListenerKind},
    server, stack, tunnel,
};
use std::{process::ExitCode, sync::Arc};
use tokio::{
    signal::unix::{SignalKind, signal},
    sync::Semaphore,
    task::JoinSet,
};
use tracing_subscriber::EnvFilter;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let default_filter = if cli.verbose > 0 {
        "ocproxy_rs=debug"
    } else {
        "ocproxy_rs=info"
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter)),
        )
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    let config = cli.config()?;
    let tunnel = tunnel::from_inherited_fd(config.vpn_fd).context("invalid OpenConnect VPNFD")?;
    let listeners = server::bind_all(&config.listeners).await?;
    let (network, driver) = stack::new(tunnel, config.network.clone())?;
    // OpenConnect sends SIGHUP to its script process group when the VPN ends.
    let mut hangup = signal(SignalKind::hangup())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let permits = Arc::new(Semaphore::new(config.network.max_connections));
    let mut services = JoinSet::new();
    for bound in listeners {
        let address = bound.listener.local_addr()?;
        let service = match bound.kind {
            ListenerKind::Socks => "SOCKS5",
            ListenerKind::Forward(_) => "TCP forward",
        };
        tracing::info!(%address, service, "listening");
        if !address.ip().is_loopback() {
            tracing::warn!(%address, "listener has no authentication; reachable clients can use the VPN");
        }
        services.spawn(server::serve(
            bound,
            network.clone(),
            permits.clone(),
            config.handshake_timeout,
            config.network.connect_timeout,
        ));
    }
    let mut driver = tokio::spawn(driver.run());
    tracing::info!(
        mtu = config.network.mtu,
        max_connections = config.network.max_connections,
        "proxy ready"
    );
    let outcome: Result<()> = tokio::select! {
        _ = hangup.recv() => { tracing::info!("OpenConnect hangup; stopping proxy"); Ok(()) }
        _ = interrupt.recv() => { tracing::info!("interrupt; stopping proxy"); Ok(()) }
        _ = terminate.recv() => { tracing::info!("termination; stopping proxy"); Ok(()) }
        result = &mut driver => {
            match result {
                Ok(Ok(())) => Err(anyhow::anyhow!("VPN packet driver stopped")),
                Ok(Err(error)) => Err(error).context("VPN packet driver failed"),
                Err(error) => Err(error).context("VPN packet driver task failed"),
            }
        }
        result = services.join_next() => {
            match result {
                Some(Ok(Err(error))) => Err(error).context("listener failed"),
                Some(Err(error)) => Err(error).context("listener task failed"),
                _ => Err(anyhow::anyhow!("listener stopped unexpectedly")),
            }
        }
    };
    services.shutdown().await;
    if !driver.is_finished() {
        driver.abort();
        let _ = driver.await;
    }
    drop(network);
    outcome?;
    if !services.is_empty() {
        bail!("failed to stop listeners");
    }
    Ok(())
}
