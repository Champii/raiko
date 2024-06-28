use crate::{interfaces::HostError, server::api::create_router, ProverState};
use anyhow::Context;
use std::{net::SocketAddr, str::FromStr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufWriter},
    net::{TcpListener, TcpStream},
};
use tracing::info;

pub mod api;

async fn process_worker_socket(mut socket: TcpStream) {
    let data = sp1_driver::read_data(&mut socket).await.unwrap();

    let result = sp1_driver::Sp1DistributedProver::run_as_worker(&data).await;

    match result {
        Ok(data) => {
            socket.writable().await.unwrap();
            socket.write_u64(data.len() as u64).await.unwrap();
            socket.flush().await.unwrap();
            println!("Sent size: {}", data.len() as u64);
            socket.write_all(&data).await.unwrap();
            socket.flush().await.unwrap();
            // socket.shutdown().await.unwrap();
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
        }
    }
}

pub async fn listen_worker() {
    let local_addr = std::fs::read_to_string("local_addr")
        .unwrap()
        .trim()
        .to_string();
    let listener = TcpListener::bind(local_addr).await.unwrap();

    loop {
        let (socket, addr) = listener.accept().await.unwrap();
        println!("NEW CONNECTION FROM {}", addr);
        process_worker_socket(socket).await;

        break;
    }
}

/// Starts the proverd server.
pub async fn serve(state: ProverState) -> anyhow::Result<()> {
    // TMP

    tokio::spawn(listen_worker());

    let addr = SocketAddr::from_str(&state.opts.address)
        .map_err(|_| HostError::InvalidAddress(state.opts.address.clone()))?;
    let listener = TcpListener::bind(addr).await?;

    info!("Listening on: {}", listener.local_addr()?);

    let router = create_router(
        state.opts.concurrency_limit,
        state.opts.jwt_secret.as_deref(),
    )
    .with_state(state);
    axum::serve(listener, router)
        .await
        .context("Server couldn't serve")?;

    Ok(())
}
