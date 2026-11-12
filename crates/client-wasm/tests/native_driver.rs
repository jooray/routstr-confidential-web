//! The driver (the code the browser runs) against the real node side, natively:
//! the 2PC C driver vs `twopc::Party` as N, and the proof-channel driver vs a
//! `ZkChannel` node serving the zkbench fixtures. The byte streams cross an
//! in-memory duplex exactly as they would cross the node's WebSockets.
#![cfg(not(target_arch = "wasm32"))]

use client_wasm::driver::{self, Frame};
use futures::StreamExt;
use futures::channel::mpsc::{UnboundedReceiver, unbounded};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::compat::TokioAsyncReadCompatExt;

/// Wires a driver's channel-0 frames to one end of a duplex; returns the
/// other end and the control-event receiver.
fn wire(
    start: impl FnOnce(driver::Out) -> driver::Input,
) -> (tokio::io::DuplexStream, UnboundedReceiver<Value>, driver::Input) {
    let (a, b) = tokio::io::duplex(1 << 22);
    let (mut ar, mut aw) = tokio::io::split(a);
    let (out_tx, mut out_rx) = unbounded::<Frame>();
    let (ev_tx, ev_rx) = unbounded::<Value>();
    let input = start(out_tx);
    tokio::spawn(async move {
        while let Some((ch, data)) = out_rx.next().await {
            if ch == 0 {
                if aw.write_all(&data).await.is_err() {
                    break;
                }
            } else {
                let _ = ev_tx.unbounded_send(serde_json::from_slice(&data).unwrap());
            }
        }
        // Driver done: close our direction (a split half does not on drop).
        let _ = aw.shutdown().await;
    });
    let inp = input.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match ar.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if inp.unbounded_send((0, buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
            }
        }
    });
    (b, ev_rx, input)
}

async fn next_ev(rx: &mut UnboundedReceiver<Value>, want: &str) -> Value {
    loop {
        let v = rx.next().await.expect("driver ended");
        let ev = v["ev"].as_str().unwrap_or("").to_string();
        if ev == want {
            return v;
        }
        assert_ne!(ev, "error", "driver error: {v}");
    }
}

fn cmd(input: &driver::Input, v: Value) {
    input.unbounded_send((1, serde_json::to_vec(&v).unwrap())).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn twopc_driver_against_node_party() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let s = (p256::ProjectivePoint::GENERATOR * p256::Scalar::from(9u64)).to_affine().to_encoded_point(false);
    let s: [u8; 65] = s.as_bytes().try_into().unwrap();
    let (th_sh, th_sf) = ([3u8; 32], [4u8; 32]);

    let (node_io, mut ev, input) = wire(driver::spawn_twopc);
    let node = tokio::spawn(async move {
        let mut p = twopc::Party::new(twopc::Role::N, node_io.compat()).await.unwrap();
        p.preprocess().await.unwrap();
        p.key_share().await.unwrap();
        let hs = p.handshake(&s, th_sh).await.unwrap();
        let ap = p.application(th_sf).await.unwrap();
        p.close().await;
        (hs, ap)
    });
    let ks = next_ev(&mut ev, "key_share").await;
    assert_eq!(ks["p"].as_str().unwrap().len(), 130);
    cmd(&input, json!({"cmd":"handshake","s":hex::encode(s),"th_sh":hex::encode(th_sh)}));
    let hs = next_ev(&mut ev, "hs").await;
    cmd(&input, json!({"cmd":"app","th_sf":hex::encode(th_sf)}));
    let ap = next_ev(&mut ev, "ap").await;
    let (nhs, nap) = node.await.unwrap();
    // Both parties hold the same handshake secrets and public anchors.
    assert_eq!(hs["c_hs"], json!(hex::encode(nhs.c_hs)));
    assert_eq!(hs["s_hs"], json!(hex::encode(nhs.s_hs)));
    let twopc::ApOut::N { h1, h2, hk, .. } = nap else { panic!("node output") };
    assert_eq!(ap["h1"], json!(hex::encode(h1)));
    assert_eq!(ap["h2"], json!(hex::encode(h2)));
    assert_eq!(ap["hk"], json!(hex::encode(hk)));
    // The client's private outputs match the anchors.
    use sha2::{Digest, Sha256};
    let c_ap_1 = hex::decode(ap["c_ap_1"].as_str().unwrap()).unwrap();
    assert_eq!(hex::encode(Sha256::digest(&c_ap_1)), ap["h1"].as_str().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn twopc_driver_rejects_bad_commands() {
    let (_node_io, mut ev, input) = wire(driver::spawn_twopc);
    input.unbounded_send((1, b"not json".to_vec())).unwrap();
    let e = ev.next().await.unwrap();
    assert_eq!(e["ev"], "error");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zkchan_driver_against_node_channel() {
    use zkbench::channel::{Party, Prealloc, ZkChannel};
    let (node_io, mut ev, input) = wire(|o| driver::spawn_zkchan(Prealloc::default(), o));
    let node = tokio::spawn(async move {
        let mut ch = ZkChannel::open(node_io.compat(), Party::Node, Prealloc::default()).await.unwrap();
        let fx = zkbench::fixtures::all();
        let mut served = Vec::new();
        while let Ok(Some(req)) = ch.next_request().await {
            if req.proof == "topup" {
                ch.serve_topup(true).await.unwrap();
                continue;
            }
            let (_, params, witness) = fx.iter().find(|(n, _, _)| *n == req.proof).unwrap();
            let w = if req.proof == "pi_nk" { Some(witness) } else { None };
            let r = ch.serve(&req.proof, params, w).await.unwrap();
            served.push((req.proof.clone(), r.iter().all(|c| c.ok)));
        }
        served
    });
    next_ev(&mut ev, "ready").await;
    eprintln!("zkchan: ready");
    for (i, (name, params, witness)) in zkbench::fixtures::all().into_iter().enumerate() {
        let c = if name == "pi_nk" {
            json!({"cmd":"verify","id":i,"proof":name,"params":params,"witness":null})
        } else {
            json!({"cmd":"prove","id":i,"proof":name,"params":params,"witness":witness})
        };
        cmd(&input, c);
        let d = next_ev(&mut ev, "done").await;
        assert_eq!(d["ok"], true, "{name}: {d}");
        eprintln!("zkchan: {name} ok");
    }
    // Between requests: a top-up refills the proof chain (one step), a second
    // finds it full; the next proof only consumes.
    cmd(&input, json!({"cmd":"topup","id":20,"timeout_ms":60000}));
    let d = next_ev(&mut ev, "done").await;
    assert_eq!((d["ok"].as_bool(), d["granted"].as_bool()), (Some(true), Some(true)), "{d}");
    assert!(d["bytes"].as_u64().unwrap() > 100_000, "{d}");
    cmd(&input, json!({"cmd":"topup","id":21}));
    let d = next_ev(&mut ev, "done").await;
    assert_eq!((d["ok"].as_bool(), d["granted"].as_bool(), d["bytes"].as_u64()), (Some(true), Some(false), Some(0)), "{d}");
    let (_, wp, ww) = zkbench::fixtures::all().remove(1);
    cmd(&input, json!({"cmd":"prove","id":22,"proof":"pi_win","params":wp,"witness":ww}));
    let d = next_ev(&mut ev, "done").await;
    assert_eq!(d["ok"], true, "{d}");
    assert!(d["bytes_recv"].as_u64().unwrap() < 100_000, "the proof after a top-up extended online: {d}");
    eprintln!("zkchan: top-up ok");
    // Params for another statement than the command names are refused
    // before anything reaches the channel (the channel stays usable).
    let (_, win_params, win_w) = zkbench::fixtures::all().remove(1);
    cmd(&input, json!({"cmd":"prove","id":8,"proof":"pi_c3s","params":win_params,"witness":win_w}));
    let d = next_ev(&mut ev, "done").await;
    assert_eq!(d["ok"], false);
    assert!(d["err"].as_str().unwrap().contains("the params are for pi_win"), "{d}");
    // The client may not prove what the node proves.
    let (_, nk_params, nk_w) = zkbench::fixtures::all().remove(0);
    cmd(&input, json!({"cmd":"prove","id":9,"proof":"pi_nk","params":nk_params,"witness":nk_w}));
    let d = next_ev(&mut ev, "done").await;
    assert_eq!(d["ok"], false);
    eprintln!("zkchan: refusal ok");
    cmd(&input, json!({"cmd":"close"}));
    let exit = tokio::time::timeout(std::time::Duration::from_secs(20), next_ev(&mut ev, "exit")).await;
    eprintln!("zkchan: driver exit {}", exit.is_ok());
    let end = tokio::time::timeout(std::time::Duration::from_secs(10), ev.next()).await;
    eprintln!("zkchan: output closed {:?}", end.as_ref().map(|v| v.is_none()));
    let served = node.await.unwrap();
    assert_eq!(served.len(), 4);
    assert!(served.iter().all(|(_, ok)| *ok), "{served:?}");
}

#[test]
fn fixtures_are_valid_json() {
    let v: Value = serde_json::from_str(&driver::fixtures_v2_json()).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prover_job_refuses_params_for_another_proof() {
    let (_, win_params, win_w) = zkbench::fixtures::all().remove(1);
    let job = serde_json::to_vec(&json!({"proof":"pi_c3s","role":"prover","params":win_params,"witness":win_w})).unwrap();
    let (_node_io, mut ev, _input) = wire(|o| driver::spawn_prover_job(&job, o));
    let d = next_ev(&mut ev, "done").await;
    assert_eq!(d["ok"], false);
    assert!(d["err"].as_str().unwrap().contains("its params are for pi_win"), "{d}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn input_backlog_is_bounded() {
    // No node: the 2PC driver never reads past its first message, so input
    // queues up until the limit, then the input closes and the driver stops.
    // The flood is no valid tag, so without one the driver would stop at its
    // first byte (`twopc_version_mismatch`) and the input end with `Stopped`:
    // the node's version tag goes first, then the driver waits in its
    // preprocessing for a message the zeros never complete.
    let (out_tx, mut out_rx) = unbounded::<Frame>();
    let input = driver::spawn_twopc(out_tx);
    input.unbounded_send((0, twopc::VERSION_TAG.to_vec())).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let chunk = vec![0u8; 8 << 20];
    let mut sent = 0usize;
    let err = loop {
        match input.unbounded_send((0, chunk.clone())) {
            Ok(()) => sent += chunk.len(),
            Err(e) => break e,
        }
        assert!(sent <= driver::MAX_PENDING_INPUT + (8 << 20), "never refused");
    };
    assert_eq!(err, driver::InputError::Backlog);
    assert!(input.pending() <= driver::MAX_PENDING_INPUT);
    // Closed: later frames are refused too, and the driver ends.
    assert!(input.unbounded_send((1, b"{}".to_vec())).is_err());
    let ended = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while let Some((ch, data)) = out_rx.next().await {
            if ch == 1 && serde_json::from_slice::<Value>(&data).unwrap()["ev"] == "exit" {
                return true;
            }
        }
        false
    })
    .await;
    assert_eq!(ended, Ok(true));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn twopc_version_mismatch_is_reported() {
    // A peer whose first bytes are another version tag (a v2 node sends no
    // tag at all and starts with its own protocol bytes).
    let (out_tx, mut out_rx) = unbounded::<Frame>();
    let input = driver::spawn_twopc(out_tx);
    input.unbounded_send((0, b"routstr-2pc/v2-other\n".to_vec())).unwrap();
    let ev = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while let Some((ch, data)) = out_rx.next().await {
            let v: Value = serde_json::from_slice(&data).unwrap_or(Value::Null);
            if ch == 1 && v["ev"] == "error" {
                return v;
            }
        }
        Value::Null
    })
    .await
    .unwrap();
    assert_eq!(ev["code"], "twopc_version_mismatch", "{ev}");
}
