//! Executor-agnostic drivers: the same frame protocol as the native
//! `cu-2pc` and `cu-prover --channel` / `--job-stdin` processes, with the
//! process's stdin/stdout replaced by two in-memory frame queues.
//!
//! Frames are `(channel, payload)`: channel 0 = protocol bytes to/from the
//! node's WebSocket, channel 1 = control JSON (one object per frame). The
//! JSON events and commands are byte-for-byte those of the binaries, so the
//! TypeScript side (`twopc.ts`, `zkchan.ts` in routstr-sdk) only swaps
//! "spawn a process" for "start a driver".
//!
//! Secrets (the 2PC outputs, proof witnesses) only ever travel on channel 1
//! between the driver and its owner; nothing is logged.

use std::time::Duration;

use futures::StreamExt;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender, unbounded};
use futures::channel::oneshot;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::compat::TokioAsyncReadCompatExt;
use twopc::rt;
use twopc::{ApOut, Party, Role};

/// Largest frame accepted from the owner (as the binaries' stdin limit).
pub const MAX_FRAME: usize = 16 << 20;

pub type Frame = (u8, Vec<u8>);
pub type Out = UnboundedSender<Frame>;

fn emit(out: &Out, v: Value) {
    let _ = out.unbounded_send((1, serde_json::to_vec(&v).expect("json")));
}

/// Pumps protocol bytes between the owner's frames and an in-memory duplex,
/// and routes control JSON to `ctl`. Returns the owner's input sender and the
/// protocol end of the duplex.
fn bridge(
    out: &Out,
    ctl: Option<UnboundedSender<Value>>,
) -> (UnboundedSender<Frame>, tokio::io::DuplexStream, oneshot::Sender<()>) {
    let (in_tx, mut in_rx) = unbounded::<Frame>();
    // Fired when the driver finished: the input task then lets go of its
    // `out` clone, so the output stream ends even if the owner keeps its
    // input sender (no cycle through the transport).
    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
    let (party_io, bridge) = tokio::io::duplex(4 << 20);
    let (mut br, mut bw) = tokio::io::split(bridge);

    // protocol → owner (channel 0)
    let net_out = out.clone();
    rt::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match br.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if net_out.unbounded_send((0, buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
            }
        }
    });

    // owner → protocol / control
    let err_out = out.clone();
    rt::spawn(async move {
        loop {
            let next = match futures::future::select(in_rx.next(), &mut stop_rx).await {
                futures::future::Either::Left((Some(f), _)) => f,
                _ => break,
            };
            let (ch, data) = next;
            if data.len() > MAX_FRAME {
                emit(&err_out, json!({"ev":"error","msg":"input frame too large"}));
                break;
            }
            match ch {
                0 => {
                    if bw.write_all(&data).await.is_err() {
                        break;
                    }
                }
                1 => match (serde_json::from_slice::<Value>(&data), &ctl) {
                    (Ok(v), Some(c)) => {
                        let _ = c.unbounded_send(v);
                    }
                    (Ok(_), None) => {}
                    (Err(_), _) => emit(&err_out, json!({"ev":"error","msg":"bad control JSON"})),
                },
                _ => {}
            }
        }
        // Input closed: the protocol input ends too (and so does `ctl`).
        let _ = bw.shutdown().await;
    });
    (in_tx, party_io, stop_tx)
}

// ---------------------------------------------------------------------------
// cu-2pc
// ---------------------------------------------------------------------------

fn emit_timings(out: &Out, p: &mut Party) {
    for t in p.take_timings() {
        emit(
            out,
            json!({"ev":"timing","step":t.step,"ms":(t.ms * 1000.0).round() / 1000.0,
                   "bytes_sent":t.bytes_sent,"bytes_recv":t.bytes_recv}),
        );
    }
}

fn hex_arr<const N: usize>(v: &Value, k: &str) -> Result<[u8; N], String> {
    let s = v.get(k).and_then(|x| x.as_str()).ok_or_else(|| format!("missing field {k}"))?;
    let b = hex::decode(s).map_err(|_| format!("field {k}: bad hex"))?;
    b.try_into().map_err(|_| format!("field {k}: expected {N} bytes"))
}

async fn next_cmd(ctl: &mut UnboundedReceiver<Value>, want: &str) -> Result<Value, String> {
    let v = ctl.next().await.ok_or("control channel closed")?;
    match v.get("cmd").and_then(|c| c.as_str()) {
        Some(c) if c == want => Ok(v),
        Some(c) => Err(format!("unexpected command {c:?}, expected {want:?}")),
        None => Err("control message without cmd".into()),
    }
}

async fn run_twopc(out: Out, mut ctl: UnboundedReceiver<Value>, io: tokio::io::DuplexStream) -> Result<(), String> {
    let mut p = Party::new(Role::C, io.compat()).await.map_err(|e| e.to_string())?;
    p.preprocess().await.map_err(|e| e.to_string())?;
    emit_timings(&out, &mut p);
    let joint = p.key_share().await.map_err(|e| e.to_string())?;
    emit_timings(&out, &mut p);
    emit(&out, json!({"ev":"key_share","p":hex::encode(joint)}));

    let cmd = next_cmd(&mut ctl, "handshake").await?;
    let s: [u8; 65] = hex_arr(&cmd, "s")?;
    let th_sh: [u8; 32] = hex_arr(&cmd, "th_sh")?;
    let hs = p.handshake(&s, th_sh).await.map_err(|e| e.to_string())?;
    emit_timings(&out, &mut p);
    emit(&out, json!({"ev":"hs","c_hs":hex::encode(hs.c_hs),"s_hs":hex::encode(hs.s_hs)}));

    let cmd = next_cmd(&mut ctl, "app").await?;
    let th_sf: [u8; 32] = hex_arr(&cmd, "th_sf")?;
    let ap = p.application(th_sf).await.map_err(|e| e.to_string())?;
    emit_timings(&out, &mut p);
    match &ap {
        ApOut::C { s_ap_0, c_ap_1, h1, h2, hk } => emit(
            &out,
            json!({"ev":"ap","s_ap_0":hex::encode(s_ap_0),"c_ap_1":hex::encode(c_ap_1),
                   "h1":hex::encode(h1),"h2":hex::encode(h2),"hk":hex::encode(hk)}),
        ),
        ApOut::N { .. } => return Err("unexpected output role".into()),
    }
    p.close().await;
    Ok(())
}

/// Starts the client side of the 2PC (`cu-2pc`). Returns the input sender;
/// dropping it is the equivalent of closing the process's stdin.
pub fn spawn_twopc(out: Out) -> UnboundedSender<Frame> {
    let (ctl_tx, ctl_rx) = unbounded::<Value>();
    let (in_tx, party_io, stop) = bridge(&out, Some(ctl_tx));
    rt::spawn(async move {
        if let Err(msg) = run_twopc(out.clone(), ctl_rx, party_io).await {
            emit(&out, json!({"ev":"error","msg":msg}));
        }
        emit(&out, json!({"ev":"exit"}));
        let _ = stop.send(());
    });
    in_tx
}

// ---------------------------------------------------------------------------
// cu-prover --channel
// ---------------------------------------------------------------------------

async fn run_channel(
    out: Out,
    mut ctl: UnboundedReceiver<Value>,
    io: tokio::io::DuplexStream,
    prealloc: zkbench::channel::Prealloc,
) -> anyhow::Result<()> {
    use zkbench::Role as ZRole;
    use zkbench::channel::{Party as ZParty, ZkChannel};
    use zkbench::statements::{Params, Witness};

    let mut ch = ZkChannel::open(io.compat(), ZParty::Client, prealloc).await?;
    let timings = serde_json::to_value(ch.take_timings()).unwrap_or_default();
    let (nk, cp) = ch.available();
    emit(&out, json!({"ev":"ready","timings":timings,"avail":[nk,cp]}));
    while let Some(cmd) = ctl.next().await {
        let id = cmd.get("id").cloned().unwrap_or(Value::Null);
        let name = cmd.get("cmd").and_then(|c| c.as_str()).unwrap_or("");
        if name == "close" {
            break;
        }
        if name != "prove" && name != "verify" {
            emit(&out, json!({"ev":"done","id":id,"ok":false,"err":format!("unknown command {name:?}")}));
            continue;
        }
        let proof = cmd.get("proof").and_then(|p| p.as_str()).unwrap_or("").to_string();
        let res: anyhow::Result<Vec<zkbench::proofs::CheckResult>> = async {
            let want = if name == "prove" { ZRole::Prover } else { ZRole::Verifier };
            if ch.role_for(&proof)? != want {
                anyhow::bail!("{proof}: the client does not {name} on the channel");
            }
            let params: Params = serde_json::from_value(cmd.get("params").cloned().unwrap_or_default())
                .map_err(|e| anyhow::anyhow!("bad params: {e}"))?;
            // Never echo the witness parser's message: it may quote the value.
            let witness: Option<Witness> = match cmd.get("witness") {
                Some(w) if !w.is_null() => {
                    Some(serde_json::from_value(w.clone()).map_err(|_| anyhow::anyhow!("bad witness"))?)
                }
                _ => None,
            };
            if want == ZRole::Prover && witness.is_none() {
                anyhow::bail!("{proof}: prove needs a witness");
            }
            match rt::timeout(Duration::from_secs(60), ch.request(&params, witness.as_ref())).await {
                Ok(r) => r,
                Err(_) => {
                    ch.poison();
                    anyhow::bail!("{proof}: timed out on the proof channel")
                }
            }
        }
        .await;
        let t = ch.take_timings();
        let (ms, sent, recv) = t.last().map(|x| (x.ms, x.bytes_sent, x.bytes_recv)).unwrap_or((0.0, 0, 0));
        match res {
            Ok(checks) => {
                let cs: Vec<_> = checks.iter().map(|c| json!({"label":c.label,"ok":c.ok})).collect();
                emit(
                    &out,
                    json!({"ev":"done","id":id,"proof":proof,"ok":true,"checks":cs,
                           "ms":(ms * 1000.0).round() / 1000.0,"bytes_sent":sent,"bytes_recv":recv}),
                );
            }
            Err(e) => emit(&out, json!({"ev":"done","id":id,"proof":proof,"ok":false,"err":format!("{e:#}"),"ms":ms})),
        }
    }
    ch.close().await;
    Ok(())
}

/// Starts the client end of the session's proof channel
/// (`cu-prover --channel`).
pub fn spawn_zkchan(prealloc: zkbench::channel::Prealloc, out: Out) -> UnboundedSender<Frame> {
    let (ctl_tx, ctl_rx) = unbounded::<Value>();
    let (in_tx, party_io, stop) = bridge(&out, Some(ctl_tx));
    rt::spawn(async move {
        if let Err(e) = run_channel(out.clone(), ctl_rx, party_io, prealloc).await {
            emit(&out, json!({"ev":"error","msg":format!("{e:#}")}));
        }
        emit(&out, json!({"ev":"exit"}));
        let _ = stop.send(());
    });
    in_tx
}

// ---------------------------------------------------------------------------
// cu-prover --job-stdin (per-proof fallback)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct Job {
    proof: String,
    role: String,
    params: zkbench::statements::Params,
    #[serde(default)]
    witness: Option<zkbench::statements::Witness>,
}

/// One proof on its own connection (the per-proof `/zk?proof=…` path).
/// `job` is `{"proof","role":"prover"|"verifier","params","witness"}`. Emits
/// `{"ev":"done","ok":..,"checks":[..]}` (or `ok:false,"err"`) on channel 1.
pub fn spawn_prover_job(job: &[u8], out: Out) -> UnboundedSender<Frame> {
    let (in_tx, party_io, stop) = bridge(&out, None);
    let job: Result<Job, String> = serde_json::from_slice(job).map_err(|_| "bad job".to_string());
    rt::spawn(async move {
        let res: anyhow::Result<(String, Vec<zkbench::proofs::CheckResult>)> = async {
            let job = job.map_err(|e| anyhow::anyhow!(e))?;
            let role = match job.role.as_str() {
                "prover" => zkbench::Role::Prover,
                "verifier" => zkbench::Role::Verifier,
                r => anyhow::bail!("unknown role {r}"),
            };
            let checks = zkbench::proofs::run_io(party_io.compat(), role, &job.params, job.witness.as_ref()).await?;
            Ok((job.proof, checks))
        }
        .await;
        match res {
            Ok((proof, checks)) => {
                let ok = checks.iter().all(|c| c.ok);
                let cs: Vec<_> = checks.iter().map(|c| json!({"label":c.label,"ok":c.ok})).collect();
                emit(&out, json!({"ev":"done","proof":proof,"ok":ok,"checks":cs}));
            }
            Err(e) => emit(&out, json!({"ev":"done","ok":false,"err":format!("{e:#}")})),
        }
        emit(&out, json!({"ev":"exit"}));
        let _ = stop.send(());
    });
    in_tx
}

/// The zkbench v2 fixtures (`pi_nk`, `pi_c2s`, `pi_c3s`: params + witness),
/// for benchmarks against the bench node. Test data only.
pub fn fixtures_v2_json() -> String {
    let v: Vec<Value> = zkbench::fixtures::all_v2()
        .into_iter()
        .map(|(name, p, w)| json!({"proof":name,"params":p,"witness":w}))
        .collect();
    serde_json::to_string(&v).expect("json")
}
