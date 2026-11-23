//! Portable library boundary for SIVault formats.
#[cfg(not(target_arch = "wasm32"))]
pub mod controlled_channel;
pub mod controlled_credential;
pub mod crypto;
pub mod fixed;
#[cfg(not(target_arch = "wasm32"))]
pub mod owner;
pub mod standard;

use std::{fmt, io};

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    InvalidFormat,
    Authentication,
    InvalidPassword,
    InvalidName,
    ReadOnly,
    Busy,
    Limit,
    Random,
    Unsupported,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Io(_) => "The file operation could not be completed.",
            Self::InvalidFormat => "The safe is damaged or uses an unsupported format.",
            Self::Authentication => "The password is incorrect or the safe is damaged.",
            Self::InvalidPassword => "Use a valid password of 1 to 1024 normalized UTF-8 bytes.",
            Self::InvalidName => "The name or destination is not supported.",
            Self::ReadOnly => "The safe is open read-only.",
            Self::Busy => "The safe is in use or needs to be reopened after a failed write.",
            Self::Limit => "The safe's prototype limit has been reached.",
            Self::Random => "Secure random generation failed.",
            Self::Unsupported => "This filesystem operation is not supported.",
        })
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
