//! Static failure kinds. Display text never includes a token, a key, or a
//! settings body.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    Usage,
    Config(&'static str),
    Io(std::io::Error),
    Closed(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Usage => f.write_str("usage"),
            Error::Config(what) => write!(f, "config: {what}"),
            Error::Io(err) => write!(f, "io: {err}"),
            Error::Closed(what) => write!(f, "closed: {what}"),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

pub fn store_err() -> Error {
    Error::Io(std::io::Error::other("store"))
}
