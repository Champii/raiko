use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

use super::pool::{WorkerRequest, WorkerResponse};

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerProtocol {
    Ping,
    Pong,

    Request(WorkerRequest),
    Response(WorkerResponse),
}

impl From<WorkerRequest> for WorkerProtocol {
    fn from(req: WorkerRequest) -> Self {
        WorkerProtocol::Request(req)
    }
}

impl From<WorkerResponse> for WorkerProtocol {
    fn from(res: WorkerResponse) -> Self {
        WorkerProtocol::Response(res)
    }
}

impl Display for WorkerProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerProtocol::Ping => write!(f, "Ping"),
            WorkerProtocol::Pong => write!(f, "Pong"),
            WorkerProtocol::Request(req) => write!(f, "Request({})", req),
            WorkerProtocol::Response(res) => write!(f, "Response({})", res),
        }
    }
}
