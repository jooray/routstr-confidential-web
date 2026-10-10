//! wasm32 tests of the bindings (run with wasm-bindgen-test-runner; in Node by
//! default, in a browser with WASM_BINDGEN_USE_BROWSER / a webdriver). The
//! full protocol in real browsers is covered by scripts/browser-bench.mjs.
#![cfg(target_arch = "wasm32")]

use client_wasm::driver;
use futures::StreamExt;
use futures::channel::mpsc::unbounded;
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn fixtures_parse() {
    let v: serde_json::Value = serde_json::from_str(&driver::fixtures_v2_json()).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 3);
}

#[wasm_bindgen_test]
async fn twopc_driver_reports_bad_control_json() {
    let (out, mut rx) = unbounded();
    let input = driver::spawn_twopc(out);
    input.unbounded_send((1, b"{nope".to_vec())).unwrap();
    // The driver starts preprocessing (channel-0 bytes) and reports the error on channel 1.
    loop {
        let (ch, data) = rx.next().await.expect("driver output");
        if ch == 1 {
            let v: serde_json::Value = serde_json::from_slice(&data).unwrap();
            assert_eq!(v["ev"], "error");
            break;
        }
    }
}

#[wasm_bindgen_test]
async fn rt_timeout_and_spawn_work_on_wasm() {
    use std::time::Duration;
    let h = twopc::rt::spawn(async { 41 + 1 });
    assert_eq!(h.await.unwrap(), 42);
    let r = twopc::rt::timeout(Duration::from_millis(10), futures::future::pending::<()>()).await;
    assert!(r.is_err());
    let t = twopc::rt::Instant::now();
    twopc::rt::sleep(Duration::from_millis(5)).await;
    assert!(t.elapsed() >= Duration::from_millis(4));
}
