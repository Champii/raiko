use crate::{interfaces::HostError, server::api::create_router, ProverState};
use anyhow::Context;
use std::{net::SocketAddr, str::FromStr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufWriter},
    net::{TcpListener, TcpStream},
};
use tracing::info;

pub mod api;

async fn read_data(socket: &mut TcpStream) -> Result<Vec<u8>, std::io::Error> {
    let size = socket.read_u64().await.unwrap();

    let mut data = Vec::with_capacity(size as usize);

    let mut buf_data = BufWriter::new(&mut data);
    let mut buf = [0; 1024];
    let mut total_read = 0;

    loop {
        let n = match socket.read(&mut buf).await {
            // socket closed
            Ok(n) if n == 0 => return Ok(data),
            Ok(n) => {
                buf_data.write_all(&buf[..n]).await.unwrap();

                total_read += n;

                if total_read == size as usize {
                    return Ok(data);
                }
            }
            Err(e) => {
                eprintln!("failed to read from socket; err = {:?}", e);
                return Err(e);
            }
        };
    }
}

async fn process_worker_socket(mut socket: TcpStream) {
    let data = read_data(&mut socket).await.unwrap();

    let result = sp1_driver::Sp1DistributedProver::run_as_worker(&data).await;

    match result {
        Ok(data) => {
            socket.write_u64(data.len() as u64).await.unwrap();
            socket.write_all(&data).await.unwrap();
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
        }
    }
}

pub async fn listen_worker() {
    let listener = TcpListener::bind("0.0.0.0:8081").await.unwrap();

    loop {
        let (socket, _) = listener.accept().await.unwrap();
        process_worker_socket(socket).await;
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
