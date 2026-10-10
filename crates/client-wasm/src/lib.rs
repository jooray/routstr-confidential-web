//! Browser build of the client side of routstr confidential mode (protocol
//! v2): the 2PC handshake and the session's proof channel, compiled to
//! `wasm32-unknown-unknown` and driven from JavaScript.
//!
//! [`driver`] holds the executor-agnostic logic (tested natively);
//! `web` the wasm-bindgen surface: `TwoPcClient`, `ProofChannelClient`,
//! `ProverJob`, each fed frames by JS (`push(channel, bytes)`) and emitting
//! frames through a JS callback `(channel, bytes) => void`.

pub mod driver;

#[cfg(target_arch = "wasm32")]
mod web;
