//! Error type for the `otsniff-privacy` crate.

#[derive(thiserror::Error, Debug)]
pub enum PrivacyError {
    #[error("{kind}: {message}")]
    Leak { kind: String, message: String },
}
