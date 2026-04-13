use thiserror::Error;

#[derive(Error, Debug)]
pub enum DynoError {
    #[error("Missing file: {0}")]
    MissingFile(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("XML parsing error: {0}")]
    XmlParse(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Tool error: {0}")]
    Tool(String),

    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),
}

pub type Result<T> = std::result::Result<T, DynoError>;
