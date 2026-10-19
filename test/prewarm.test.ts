import { describe, expect, it, vi } from "vitest";
import { Prewarmer } from "../src/client";

/** A fake session whose arm() resolves when the test says so. */
function fakeSession(len: number) {
  let finish!: () => void;
  const armed = new Promise<void>((r) => (finish = r));
  return {
    s: {
      bodyLength: len,
      startedAt: Date.now(),
      armedAt: 0,
      healthy: true,
      isArmed: true,
      closed: false,
      arm: () => armed,
      close() {
        this.closed = true;
      },
    },
    finish,
  };
}

function fakeClient() {
  const sessions: ReturnType<typeof fakeSession>[] = [];
  let gate: (() => void) | undefined;
  const client = {
    credential: "sk-test",
    // the offer fetch can be held open to test the window before registration
    offer: () => (gate ? new Promise((r) => { const g = gate!; gate = () => { g(); r({ price_list: { m: {} } }); }; }) : Promise.resolve({ price_list: { m: {} } })),
    api: { balance: async () => ({ balance: 10_000_000, reserved: 0 }) },
    pricing: async () => [{ id: "m", reservationMsat: 1000 }],
    newSession: (_o: unknown, _c: string, _m: string, _t: number, len: number) => {
      const f = fakeSession(len);
      sessions.push(f);
      return f.s;
    },
    emit: () => {},
  };
  return { client, sessions, holdOffer: () => (gate = () => {}), releaseOffer: () => gate?.() };
}

const tick = () => new Promise((r) => setTimeout(r, 0));

describe("pre-warm pool", () => {
  it("arms nothing before user activity, or while the reservation is unknown", async () => {
    const { client, sessions } = fakeClient();
    const pw = new Prewarmer(client as never, { onlyWhenVisible: false });
    pw.setTarget("m", 100); // choosing a model (e.g. at page load) is not activity
    await tick();
    expect(sessions.length).toBe(0);
    client.pricing = async () => [{ id: "m" }] as never;
    pw.activity();
    await tick();
    expect(sessions.length).toBe(0); // no pricing: no blind arm
    client.pricing = async () => [{ id: "m", reservationMsat: 1000 }];
    pw.activity();
    await tick();
    expect(sessions.length).toBe(1);
    pw.stop?.();
  });

  it("a request sent while a session is arming uses that session", async () => {
    const { client, sessions } = fakeClient();
    const pw = new Prewarmer(client as never, { onlyWhenVisible: false });
    pw.setTarget("m", 100);
    pw.activity();
    await tick();
    expect(sessions.length).toBe(1); // arming started
    const lease = pw.take("m", 100, 300);
    expect(lease).toBeDefined();
    let got: unknown;
    void lease!.then((s) => (got = s));
    await tick();
    expect(got).toBeUndefined(); // still arming: the request waits
    sessions[0]!.finish();
    await tick();
    expect(got).toBe(sessions[0]!.s); // and gets that same session
    expect(sessions.length).toBe(1); // no second, cold preparation
    pw.stop?.();
  });

  it("the next session starts arming as soon as the claimed one is ready", async () => {
    const { client, sessions } = fakeClient();
    const pw = new Prewarmer(client as never, { onlyWhenVisible: false });
    pw.setTarget("m", 100);
    pw.activity();
    await tick();
    const lease = pw.take("m", 100, 300)!;
    pw.beginPreparing();
    void lease.then(() => pw.endPreparing());
    await tick();
    expect(sessions.length).toBe(1); // not while the claimed one is still preparing
    sessions[0]!.finish();
    await tick();
    await tick();
    expect(sessions.length).toBe(2); // next arm started, while the answer would still stream
    pw.stop?.();
  });

  it("a request in the window before the arm is registered waits for it", async () => {
    const { client, sessions, holdOffer, releaseOffer } = fakeClient();
    holdOffer();
    const pw = new Prewarmer(client as never, { onlyWhenVisible: false });
    pw.setTarget("m", 100);
    pw.activity();
    await tick();
    expect(sessions.length).toBe(0); // still checking the offer
    const lease = pw.take("m", 100, 300);
    expect(lease).toBeDefined(); // waits instead of going cold
    releaseOffer();
    await tick();
    await tick();
    expect(sessions.length).toBe(1);
    let got: unknown;
    void lease!.then((s) => (got = s));
    sessions[0]!.finish();
    await tick();
    await tick();
    expect(got).toBe(sessions[0]!.s);
    pw.stop?.();
  });

  it("backs off, doubling, when armed sessions keep dying before use", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      const { client, sessions } = fakeClient();
      const pw = new Prewarmer(client as never, { onlyWhenVisible: false, backoffMs: 30_000 });
      const killArmed = async () => {
        await tick();
        sessions[sessions.length - 1]!.finish();
        await tick();
        sessions[sessions.length - 1]!.s.healthy = false;
        (pw as unknown as { tick(): void }).tick();
        await tick();
      };
      pw.setTarget("m", 100);
      pw.activity();
      await killArmed();
      expect(sessions.length).toBe(1);
      expect(pw.status).toBe("backoff");
      pw.activity(); // traffic does not override the backoff
      await tick();
      expect(sessions.length).toBe(1);
      vi.advanceTimersByTime(31_000);
      pw.activity();
      await killArmed();
      expect(sessions.length).toBe(2);
      vi.advanceTimersByTime(31_000); // the second death waits 60 s
      pw.activity();
      await tick();
      expect(sessions.length).toBe(2);
      vi.advanceTimersByTime(30_000);
      pw.activity();
      await tick();
      expect(sessions.length).toBe(3);
      // A warm request served resets the count.
      sessions[2]!.finish();
      await tick();
      const lease = pw.take("m", 100, 300);
      expect(lease).toBeDefined();
      pw.servedWarm();
      pw.activity();
      await killArmed(); // arms the next one and it dies: back to 30 s
      expect(sessions.length).toBe(4);
      vi.advanceTimersByTime(31_000);
      pw.activity();
      await tick();
      expect(sessions.length).toBe(5);
      pw.stop();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("pre-warm options", () => {
  it("clamps maxAgeMs to at least 60 s and keeps the default when unset", () => {
    const { client } = fakeClient();
    const short = new Prewarmer(client as never, { onlyWhenVisible: false, enabled: false, maxAgeMs: 10 });
    expect(short.cfg.maxAgeMs).toBe(60_000);
    short.stop();
    const unset = new Prewarmer(client as never, { onlyWhenVisible: false, enabled: false, maxAgeMs: undefined });
    expect(unset.cfg.maxAgeMs).toBe(480_000);
    unset.stop();
  });
});
