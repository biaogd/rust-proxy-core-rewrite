use thiserror::Error;

#[derive(Debug, Error)]
pub enum TunError {
    #[error("TUN device error: {0}")]
    Device(#[from] std::io::Error),
    #[error("TUN stack error: {0}")]
    Stack(String),
    #[error("unsupported TUN platform operation: {0}")]
    Unsupported(String),
}
