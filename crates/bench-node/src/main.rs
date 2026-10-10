//! `bench-node`: a local stand-in for the node's side of protocol v2, for
//! benchmarks and browser tests that need no credential and no provider.
//!
//! ```text
//! bench-node serve [--port 7450]          WebSocket server:
//!     /twopc   the NODE side of the 2PC (preprocess, key share, phase A, phase B)
//!              with a fixed server share S = 5·G and fixed transcript hashes
//!     /zkchan  the NODE side of the proof channel, serving the zkbench fixtures
//!     /params  one text message: {"s","th_sh","th_sf"} (the fixed values)
//! bench-node client [--url ws://127.0.0.1:7450] [--runs N]
//!     the native client driver against the server (same code the wasm runs)
//! ```
//!
//! There is no TLS server: the transcript hashes are constants, so the 2PC
//! outputs are the key schedule of a fictitious handshake. That is all a
//! timing comparison needs. Nothing here touches a real node or credential.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use futures::{SinkExt, StreamExt};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::compat::TokioAsyncReadCompatExt;

const TH_SH: [u8; 32] = [0x11; 32];
const TH_SF: [u8; 32] = [0x22; 32];

fn server_share() -> [u8; 65] {
    let p = p256::ProjectivePoint::GENERATOR * p256::Scalar::from(5u64);
    p.to_affine().to_encoded_point(false).as_bytes().try_into().unwrap()
}

fn arg(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1).cloned())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("serve") => serve(arg(&args, "--port").unwrap_or_else(|| "7450".into()).parse()?).await,
        Some("client") => {
            let url = arg(&args, "--url").unwrap_or_else(|| "ws://127.0.0.1:7450".into());
            let runs: usize = arg(&args, "--runs").unwrap_or_else(|| "3".into()).parse()?;
            for i in 0..runs {
                let r = native_client(&url).await?;
                println!("{}", json!({"run": i, "native": r}));
            }
            Ok(())
        }
        _ => {
            eprintln!("usage: bench-node serve [--port P] | client [--url U] [--runs N]");
            std::process::exit(2)
        }
    }
}

// ---------------------------------------------------------------------------
// server
// ---------------------------------------------------------------------------

async fn serve(port: u16) -> Result<()> {
    let l = TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("bench-node: listening on ws://127.0.0.1:{port} (/twopc, /zkchan, /params)");
    loop {
        let (tcp, _) = l.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle(tcp).await {
                eprintln!("bench-node: connection failed: {e:#}");
            }
        });
    }
}

async fn handle(tcp: TcpStream) -> Result<()> {
    let mut path = String::new();
    let ws = tokio_tungstenite::accept_hdr_async(tcp, |req: &tokio_tungstenite::tungstenite::handshake::server::Request, resp| {
        path = req.uri().path().to_string();
        Ok(resp)
    })
    .await?;
    match path.as_str() {
        "/params" => {
            let (mut tx, _rx) = ws.split();
            let p = json!({"s":hex::encode(server_share()),"th_sh":hex::encode(TH_SH),"th_sf":hex::encode(TH_SF)});
            tx.send(Message::Text(p.to_string().into())).await?;
            tx.close().await.ok();
            Ok(())
        }
        "/twopc" => {
            let io = ws_bridge(ws);
            let t0 = Instant::now();
            let mut p = twopc::Party::new(twopc::Role::N, io.compat()).await?;
            p.preprocess().await?;
            p.key_share().await?;
            p.handshake(&server_share(), TH_SH).await?;
            p.application(TH_SF).await?;
            let steps: Vec<Value> =
                p.take_timings().iter().map(|t| json!({"step":t.step,"ms":(t.ms * 10.0).round() / 10.0})).collect();
            p.close().await;
            eprintln!("bench-node: twopc done in {:.0} ms, node steps {}", t0.elapsed().as_secs_f64() * 1e3, Value::from(steps));
            Ok(())
        }
        "/zkchan" => {
            use zkbench::channel::{Party, Prealloc, ZkChannel};
            let io = ws_bridge(ws);
            let mut ch = ZkChannel::open(io.compat(), Party::Node, Prealloc::default()).await?;
            let fx = zkbench::fixtures::all_v2();
            while let Some(req) = ch.next_request().await? {
                let Some((_, params, witness)) = fx.iter().find(|(n, _, _)| *n == req.proof) else {
                    bail!("unknown proof {}", req.proof);
                };
                let w = if req.proof == "pi_nk" { Some(witness) } else { None };
                let r = ch.serve(&req.proof, params, w).await?;
                eprintln!("bench-node: served {} ok={}", req.proof, r.iter().all(|c| c.ok));
            }
            ch.close().await;
            Ok(())
        }
        p => bail!("unknown path {p}"),
    }
}

/// A WebSocket as a byte stream (binary messages ↔ bytes).
fn ws_bridge<S>(ws: tokio_tungstenite::WebSocketStream<S>) -> tokio::io::DuplexStream
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mine, theirs) = tokio::io::duplex(4 << 20);
    let (mut rd, mut wr) = tokio::io::split(theirs);
    let (mut tx, mut rx) = ws.split();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = tx.close().await;
    });
    tokio::spawn(async move {
        while let Some(Ok(m)) = rx.next().await {
            match m {
                Message::Binary(b) => {
                    if wr.write_all(&b).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        let _ = wr.shutdown().await;
    });
    mine
}

// ---------------------------------------------------------------------------
// native client (the same driver code the wasm build runs)
// ---------------------------------------------------------------------------

/// Connects a driver to a WebSocket: channel-0 frames ↔ binary messages;
/// returns the receiver of control events and the input sender.
async fn connect(
    url: &str,
    start: impl FnOnce(client_wasm::driver::Out) -> futures::channel::mpsc::UnboundedSender<client_wasm::driver::Frame>,
) -> Result<(futures::channel::mpsc::UnboundedReceiver<Value>, futures::channel::mpsc::UnboundedSender<client_wasm::driver::Frame>)> {
    let (ws, _) = tokio_tungstenite::connect_async(url).await.with_context(|| format!("connect {url}"))?;
    let (mut tx, mut rx) = ws.split();
    let (out_tx, mut out_rx) = futures::channel::mpsc::unbounded();
    let (ev_tx, ev_rx) = futures::channel::mpsc::unbounded::<Value>();
    let input = start(out_tx);
    tokio::spawn(async move {
        while let Some((ch, data)) = out_rx.next().await {
            if ch == 0 {
                if tx.send(Message::Binary(data.into())).await.is_err() {
                    break;
                }
            } else if let Ok(v) = serde_json::from_slice::<Value>(&data) {
                let _ = ev_tx.unbounded_send(v);
            }
        }
        let _ = tx.close().await;
    });
    let inp = input.clone();
    tokio::spawn(async move {
        while let Some(Ok(m)) = rx.next().await {
            if let Message::Binary(b) = m {
                if inp.unbounded_send((0, b.to_vec())).is_err() {
                    break;
                }
            }
        }
    });
    Ok((ev_rx, input))
}

async fn wait_ev(rx: &mut futures::channel::mpsc::UnboundedReceiver<Value>, want: &str, steps: &mut Vec<Value>) -> Result<Value> {
    loop {
        let v = tokio::time::timeout(Duration::from_secs(180), rx.next()).await?.context("driver ended")?;
        match v.get("ev").and_then(|e| e.as_str()) {
            Some(e) if e == want => return Ok(v),
            Some("timing") => steps.push(v),
            Some("error") => bail!("driver error: {}", v["msg"]),
            Some("done") if want != "done" => bail!("unexpected done"),
            _ => {}
        }
    }
}

async fn native_client(base: &str) -> Result<Value> {
    let t0 = Instant::now();
    let mut steps = Vec::new();
    let (mut ev, input) = connect(&format!("{base}/twopc"), client_wasm::driver::spawn_twopc).await?;
    let (mut zev, zin) = connect(&format!("{base}/zkchan"), |o| {
        client_wasm::driver::spawn_zkchan(zkbench::channel::Prealloc::default(), o)
    })
    .await?;
    wait_ev(&mut ev, "key_share", &mut steps).await?;
    let t_ks = t0.elapsed();
    let cmd = json!({"cmd":"handshake","s":hex::encode(server_share()),"th_sh":hex::encode(TH_SH)});
    let t1 = Instant::now();
    input.unbounded_send((1, cmd.to_string().into_bytes()))?;
    wait_ev(&mut ev, "hs", &mut steps).await?;
    let t_a = t1.elapsed();
    let t2 = Instant::now();
    input.unbounded_send((1, json!({"cmd":"app","th_sf":hex::encode(TH_SF)}).to_string().into_bytes()))?;
    wait_ev(&mut ev, "ap", &mut steps).await?;
    let t_b = t2.elapsed();
    drop(input);

    let mut zsteps = Vec::new();
    let ready = wait_ev(&mut zev, "ready", &mut zsteps).await?;
    let t_zready = t0.elapsed();
    let mut proofs = serde_json::Map::new();
    for (i, (name, params, witness)) in zkbench::fixtures::all_v2().into_iter().enumerate() {
        let cmd = if name == "pi_nk" {
            json!({"cmd":"verify","id":i,"proof":name,"params":params,"witness":null})
        } else {
            json!({"cmd":"prove","id":i,"proof":name,"params":params,"witness":witness})
        };
        let t = Instant::now();
        zin.unbounded_send((1, cmd.to_string().into_bytes()))?;
        let d = wait_ev(&mut zev, "done", &mut zsteps).await?;
        if d["ok"] != json!(true) {
            bail!("{name} failed: {}", d["err"]);
        }
        proofs.insert(name.into(), json!({"wall_ms": t.elapsed().as_secs_f64() * 1e3, "inner_ms": d["ms"]}));
    }
    let _ = zin.unbounded_send((1, br#"{"cmd":"close"}"#.to_vec()));
    Ok(json!({
        "key_share_ms": t_ks.as_secs_f64() * 1e3,
        "phase_a_ms": t_a.as_secs_f64() * 1e3,
        "phase_b_ms": t_b.as_secs_f64() * 1e3,
        "zkchan_ready_ms": t_zready.as_secs_f64() * 1e3,
        "zkchan_steps": ready["timings"],
        "proofs": proofs,
        "steps": steps,
    }))
}
