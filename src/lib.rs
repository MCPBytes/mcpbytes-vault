//! Local vault helper: generates secrets from OS randomness and saves them locally, returning references.
//! The optional `remote` feature mixes in an encrypted contribution from the MCPBytes service.
pub mod app;
pub mod config;
pub mod install;
mod journal;
pub mod protocol;
#[cfg(feature = "remote")]
pub mod remote;
pub mod storage;
