/**
 * Release versioning and automatic update (house rule: never rely on a hard
 * refresh). The running version is compiled in (__APP_VERSION__); the
 * deployed one is read from version.json (no-store) on load, when the tab
 * becomes visible and every 5 minutes. A new version makes the service
 * worker update; the new worker activates at once (skipWaiting +
 * clients.claim) and the page reloads on `controllerchange` — deferred while
 * a confidential request is in flight — and then shows "Updated to vX".
 */

declare const __APP_VERSION__: string;
declare const __APP_BUILD__: string;

export const APP_VERSION = __APP_VERSION__;
export const APP_BUILD = __APP_BUILD__;

const CHECK_MS = 5 * 60_000;
const FLAG = "routstr-confidential:updated-from";

let busy = () => false;
let pendingReload = false;
let toast: (msg: string) => void = () => {};

function reload(): void {
  if (busy()) {
    pendingReload = true;
    toast("A new version is ready; it loads when the current answer finishes.");
    return;
  }
  try {
    sessionStorage.setItem(FLAG, APP_VERSION);
  } catch {
    /* ignore */
  }
  location.reload();
}

/** Call when a request finished, to apply a deferred update. */
export function idle(): void {
  if (pendingReload && !busy()) reload();
}

async function remoteVersion(): Promise<string | undefined> {
  try {
    const r = await fetch(`./version.json?t=${Date.now()}`, { cache: "no-store" });
    if (!r.ok) return undefined;
    const j = (await r.json()) as { version?: string };
    return typeof j.version === "string" ? j.version : undefined;
  } catch {
    return undefined;
  }
}

export function setupPwa(opts: { isBusy: () => boolean; toast: (msg: string) => void }): void {
  busy = opts.isBusy;
  toast = opts.toast;
  try {
    const from = sessionStorage.getItem(FLAG);
    if (from) {
      sessionStorage.removeItem(FLAG);
      if (from !== APP_VERSION) toast(`Updated to v${APP_VERSION}`);
    }
  } catch {
    /* ignore */
  }
  if (!("serviceWorker" in navigator) || import.meta.env.DEV) return;
  let reg: ServiceWorkerRegistration | undefined;
  const hadController = !!navigator.serviceWorker.controller;
  navigator.serviceWorker.addEventListener("controllerchange", () => {
    // The first install takes control without a new version: no reload.
    if (hadController) reload();
  });
  navigator.serviceWorker
    .register("./sw.js", { scope: "./", updateViaCache: "none" })
    .then((r) => {
      reg = r;
      r.addEventListener("updatefound", () => {
        const w = r.installing;
        w?.addEventListener("statechange", () => {
          if (w.state === "installed" && navigator.serviceWorker.controller) w.postMessage("skipWaiting");
        });
      });
    })
    .catch(() => {});
  const check = async () => {
    const v = await remoteVersion();
    if (!v || v === APP_VERSION) return;
    if (reg) {
      await reg.update().catch(() => {});
      // If no worker change arrives (e.g. blocked SW), reload anyway.
      setTimeout(() => {
        if (!pendingReload) reload();
      }, 10_000);
    } else reload();
  };
  void check();
  setInterval(check, CHECK_MS);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") void check();
  });
}
