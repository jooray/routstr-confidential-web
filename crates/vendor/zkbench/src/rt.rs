//! Runtime shims so the protocol code runs both natively (tokio, the
//! `cu-prover`/`cu-2pc` binaries and the node) and in the browser
//! (`wasm32-unknown-unknown`, single-threaded, futures driven by
//! `wasm-bindgen-futures`).
//!
//! Only these few primitives differ; everything else (tokio's in-memory
//! `duplex`, `mpsc`, `Mutex`, `select!`) is executor-agnostic and compiles on
//! wasm with tokio's `sync`/`macros`/`io-util` features.

use std::future::Future;
use std::time::Duration;

/// `std::time::Instant` natively; `performance.now()` based in the browser
/// (`std::time::Instant::now()` panics on wasm32-unknown-unknown).
pub use web_time::Instant;

/// A timeout elapsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elapsed;

impl std::fmt::Display for Elapsed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("deadline has elapsed")
    }
}

impl std::error::Error for Elapsed {}

#[cfg(not(target_arch = "wasm32"))]
mod imp {
    use super::*;

    pub use tokio::task::{JoinError, JoinHandle};

    pub fn spawn<F>(f: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        tokio::spawn(f)
    }

    /// CPU-bound work off the async worker threads.
    pub async fn spawn_blocking<F, R>(f: F) -> Result<R, JoinError>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        tokio::task::spawn_blocking(f).await
    }

    pub async fn sleep(d: Duration) {
        tokio::time::sleep(d).await
    }

    pub async fn timeout<F: Future>(d: Duration, f: F) -> Result<F::Output, Elapsed> {
        tokio::time::timeout(d, f).await.map_err(|_| Elapsed)
    }
}

#[cfg(target_arch = "wasm32")]
mod imp {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use futures::channel::oneshot;
    use futures::future::{AbortHandle, Either, abortable, select};

    /// The task was aborted (or panicked) before it produced its output.
    #[derive(Debug)]
    pub struct JoinError;

    impl std::fmt::Display for JoinError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("task cancelled")
        }
    }

    impl std::error::Error for JoinError {}

    /// Handle of a task spawned on the browser's event loop.
    pub struct JoinHandle<T> {
        rx: oneshot::Receiver<T>,
        abort: AbortHandle,
    }

    impl<T> JoinHandle<T> {
        pub fn abort(&self) {
            self.abort.abort();
        }
    }

    impl<T> Future for JoinHandle<T> {
        type Output = Result<T, JoinError>;
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            Pin::new(&mut self.rx).poll(cx).map_err(|_| JoinError)
        }
    }

    pub fn spawn<F>(f: F) -> JoinHandle<F::Output>
    where
        F: Future + 'static,
        F::Output: 'static,
    {
        let (tx, rx) = oneshot::channel();
        let (fut, abort) = abortable(f);
        wasm_bindgen_futures::spawn_local(async move {
            if let Ok(v) = fut.await {
                let _ = tx.send(v);
            }
        });
        JoinHandle { rx, abort }
    }

    /// Single-threaded: the work runs inline when the future is first polled
    /// (run the whole protocol in a Web Worker to keep a page responsive).
    pub async fn spawn_blocking<F, R>(f: F) -> Result<R, JoinError>
    where
        F: FnOnce() -> R,
    {
        Ok(f())
    }

    pub async fn sleep(d: Duration) {
        gloo_timers::future::sleep(d).await
    }

    pub async fn timeout<F: Future>(d: Duration, f: F) -> Result<F::Output, Elapsed> {
        let f = std::pin::pin!(f);
        let s = std::pin::pin!(sleep(d));
        match select(f, s).await {
            Either::Left((v, _)) => Ok(v),
            Either::Right(_) => Err(Elapsed),
        }
    }
}

pub use imp::*;
