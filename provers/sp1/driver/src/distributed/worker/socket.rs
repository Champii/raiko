use raiko_lib::prover::WorkerError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{WorkerEnvelope, WorkerProtocol, WorkerRequest, WorkerResponse};

// 128MB
const PAYLOAD_MAX_SIZE: usize = 1 << 27;

pub struct WorkerSocket {
    socket: tokio::net::TcpStream,
}

impl WorkerSocket {
    pub async fn connect(url: &str) -> Result<Self, WorkerError> {
        let socket = tokio::net::TcpStream::connect(url).await?;

        Ok(WorkerSocket::from_stream(socket))
    }

    pub fn from_stream(socket: tokio::net::TcpStream) -> Self {
        WorkerSocket { socket }
    }

    pub async fn send(&mut self, packet: WorkerProtocol) -> Result<(), WorkerError> {
        let envelope: WorkerEnvelope = packet.into();

        let data = bincode::serialize(&envelope)?;

        log::debug!("Sending data with size: {:?}", data.len());

        if data.len() > PAYLOAD_MAX_SIZE {
            return Err(WorkerError::PayloadTooBig);
        }

        self.socket.write_u64(data.len() as u64).await?;
        self.socket.write_all(&data).await?;

        Ok(())
    }

    pub async fn receive(&mut self) -> Result<WorkerProtocol, WorkerError> {
        let data = self.read_data().await?;

        let envelope: WorkerEnvelope = bincode::deserialize(&data)?;

        envelope.data()
    }

    // TODO: Add a timeout
    async fn read_data(&mut self) -> Result<Vec<u8>, WorkerError> {
        let size = self.socket.read_u64().await? as usize;

        log::debug!("Receiving data with size: {:?}", size);

        if size > PAYLOAD_MAX_SIZE {
            return Err(WorkerError::PayloadTooBig);
        }

        let mut data = Vec::new();

        let mut buf = [0; 1024];
        let mut total_read = 0;

        loop {
            match self.socket.read(&mut buf).await {
                // socket closed
                Ok(n) if n == 0 => {
                    return Err(WorkerError::IO(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "unexpected EOF",
                    )));
                }
                Ok(n) => {
                    data.extend_from_slice(&buf[..n]);

                    total_read += n;

                    if total_read == size {
                        return Ok(data);
                    }

                    // TODO: handle the case where the data is bigger than expected
                }
                Err(e) => {
                    log::error!("failed to read from socket; err = {:?}", e);

                    return Err(e.into());
                }
            };
        }
    }

    pub async fn request(&mut self, request: WorkerRequest) -> Result<WorkerResponse, WorkerError> {
        self.send(request.into()).await?;

        let response = self.receive().await?;

        match response {
            WorkerProtocol::Response(response) => Ok(response),
            _ => Err(WorkerError::InvalidResponse),
        }
    }
}
