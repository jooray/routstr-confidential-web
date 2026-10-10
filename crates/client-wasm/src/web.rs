//! wasm-bindgen surface. Each object owns one driver; JS feeds it frames with
//! `push(channel, bytes)` and receives frames via the callback given to the
//! constructor. Single-threaded: run it in a dedicated Worker to keep the
//! page responsive (the garbled-circuit evaluation is CPU-bound).

use futures::StreamExt;
use futures::channel::mpsc::{UnboundedSender, unbounded};
use wasm_bindgen::prelude::*;

use crate::driver::{self, Frame};

#[wasm_bindgen(start)]
fn start() {
    console_error_panic_hook::set_once();
}

/// Delivers the driver's output frames to `cb(channel, Uint8Array)`.
fn sink(cb: js_sys::Function) -> driver::Out {
    let (tx, mut rx) = unbounded::<Frame>();
    wasm_bindgen_futures::spawn_local(async move {
        while let Some((ch, data)) = rx.next().await {
            let arr = js_sys::Uint8Array::from(&data[..]);
            let _ = cb.call2(&JsValue::NULL, &JsValue::from(ch), &arr);
        }
    });
    tx
}

struct Input(Option<UnboundedSender<Frame>>);

impl Input {
    fn push(&self, channel: u8, data: &[u8]) -> Result<(), JsValue> {
        match &self.0 {
            Some(tx) => tx
                .unbounded_send((channel, data.to_vec()))
                .map_err(|_| JsValue::from_str("driver has stopped")),
            None => Err(JsValue::from_str("closed")),
        }
    }
}

/// Client side of the 2PC handshake (same frames as the `cu-2pc` binary).
#[wasm_bindgen]
pub struct TwoPcClient {
    input: Input,
}

#[wasm_bindgen]
impl TwoPcClient {
    /// Starts preprocessing immediately; `on_frame(channel, bytes)` receives
    /// protocol bytes (channel 0, for the `twopc` WebSocket) and events
    /// (channel 1, JSON).
    #[wasm_bindgen(constructor)]
    pub fn new(on_frame: js_sys::Function) -> TwoPcClient {
        TwoPcClient { input: Input(Some(driver::spawn_twopc(sink(on_frame)))) }
    }

    /// Feed one frame: channel 0 = bytes from the WebSocket, 1 = command JSON.
    pub fn push(&self, channel: u8, data: &[u8]) -> Result<(), JsValue> {
        self.input.push(channel, data)
    }

    /// End of input (like closing the process's stdin).
    pub fn close(&mut self) {
        self.input.0 = None;
    }
}

/// Client end of the session's proof channel (`cu-prover --channel`).
#[wasm_bindgen]
pub struct ProofChannelClient {
    input: Input,
}

#[wasm_bindgen]
impl ProofChannelClient {
    /// `prealloc_nk`/`prealloc_cp` = 0 keep the defaults.
    #[wasm_bindgen(constructor)]
    pub fn new(on_frame: js_sys::Function, prealloc_nk: u32, prealloc_cp: u32) -> ProofChannelClient {
        let mut pre = zkbench::channel::Prealloc::default();
        if prealloc_nk > 0 {
            pre.nk = prealloc_nk as usize;
        }
        if prealloc_cp > 0 {
            pre.cp = prealloc_cp as usize;
        }
        ProofChannelClient { input: Input(Some(driver::spawn_zkchan(pre, sink(on_frame)))) }
    }

    pub fn push(&self, channel: u8, data: &[u8]) -> Result<(), JsValue> {
        self.input.push(channel, data)
    }

    pub fn close(&mut self) {
        self.input.0 = None;
    }
}

/// One proof over its own connection (the per-proof fallback,
/// `cu-prover --job-stdin`). `job` is the JSON job.
#[wasm_bindgen]
pub struct ProverJob {
    input: Input,
}

#[wasm_bindgen]
impl ProverJob {
    #[wasm_bindgen(constructor)]
    pub fn new(on_frame: js_sys::Function, job: &[u8]) -> ProverJob {
        ProverJob { input: Input(Some(driver::spawn_prover_job(job, sink(on_frame)))) }
    }

    pub fn push(&self, channel: u8, data: &[u8]) -> Result<(), JsValue> {
        self.input.push(channel, data)
    }

    pub fn close(&mut self) {
        self.input.0 = None;
    }
}

/// zkbench v2 fixtures (params + witness) as JSON, for benchmarks only.
#[wasm_bindgen(js_name = fixturesV2)]
pub fn fixtures_v2() -> String {
    driver::fixtures_v2_json()
}

#[wasm_bindgen(js_name = buildInfo)]
pub fn build_info() -> String {
    format!("client-wasm {} (protocol v2; routstr-confidential@0903e77, mpz2@8f89783)", env!("CARGO_PKG_VERSION"))
}
