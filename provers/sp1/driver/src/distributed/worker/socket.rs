use raiko_lib::prover::WorkerError;
use sp1_core::{stark::ShardProof, utils::BabyBearPoseidon2};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};

use crate::{PartialProofRequest, WorkerEnvelope, WorkerProtocol};

// 64MB
const PAYLOAD_MAX_SIZE: usize = 1 << 26;

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
    pub async fn read_data(&mut self) -> Result<Vec<u8>, WorkerError> {
        let size = self.socket.read_u64().await? as usize;

        if size > PAYLOAD_MAX_SIZE {
            return Err(WorkerError::PayloadTooBig);
        }

        let mut data = Vec::new();

        let mut buf_data = BufWriter::new(&mut data);
        let mut buf = [0; 1024];
        let mut total_read = 0;

        loop {
            match self.socket.read(&mut buf).await {
                // socket closed
                Ok(n) if n == 0 => {
                    if total_read != size {
                        return Err(WorkerError::IO(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "unexpected EOF",
                        )));
                    }

                    buf_data.flush().await?;

                    return Ok(data);
                }
                Ok(n) => {
                    buf_data.write_all(&buf[..n]).await?;

                    total_read += n;

                    if total_read == size {
                        buf_data.flush().await?;

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

    pub async fn ping(&mut self) -> Result<(), WorkerError> {
        self.send(WorkerProtocol::Ping).await?;

        let response = self.receive().await?;

        match response {
            WorkerProtocol::Pong => Ok(()),
            _ => Err(WorkerError::InvalidResponse),
        }
    }

    pub async fn partial_proof_request(
        &mut self,
        request: PartialProofRequest,
    ) -> Result<Vec<ShardProof<BabyBearPoseidon2>>, WorkerError> {
        self.send(WorkerProtocol::PartialProofRequest(request))
            .await?;

        let response = self.receive().await?;

        if let WorkerProtocol::PartialProofResponse(partial_proofs) = response {
            Ok(partial_proofs)
        } else {
            Err(WorkerError::InvalidResponse)
        }
    }
}
