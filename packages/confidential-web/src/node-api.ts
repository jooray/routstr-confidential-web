/**
 * The node's ordinary HTTP endpoints the browser needs around confidential
 * sessions: models, balance, funding (Cashu, Lightning) and refunds. Nothing
 * here is confidential-specific; it is the routstr-core API every client uses.
 */

export interface NodeModel {
  id: string;
  name?: string;
  description?: string;
  context_length?: number;
  top_provider?: { context_length?: number | null; max_completion_tokens?: number | null } | null;
  [k: string]: unknown;
}

export interface BalanceInfo {
  api_key: string;
  /** msats, including reserved. */
  balance: number;
  /** msats held by open reservations (armed sessions, requests in flight). */
  reserved: number;
  total_requests?: number;
  total_spent?: number;
}

export interface LightningInvoice {
  invoice_id: string;
  bolt11: string;
  amount_sats: number;
  expires_at: number;
  payment_hash: string;
}

export interface LightningInvoiceStatus {
  status: "pending" | "paid" | "expired" | string;
  api_key?: string | null;
  amount_sats: number;
  paid_at?: number | null;
}

export class NodeApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body?: unknown,
  ) {
    super(message);
    this.name = "NodeApiError";
  }
}

export class NodeApi {
  readonly base: string;

  constructor(
    base: string,
    private readonly fetchImpl: typeof fetch = (...a) => fetch(...a),
  ) {
    this.base = base.replace(/\/$/, "");
  }

  private async json<T>(path: string, init: RequestInit = {}, bearer?: string): Promise<T> {
    const headers = new Headers(init.headers);
    if (bearer) headers.set("Authorization", `Bearer ${bearer}`);
    if (init.body && !headers.has("content-type")) headers.set("content-type", "application/json");
    const res = await this.fetchImpl(`${this.base}${path}`, { ...init, headers });
    const text = await res.text();
    let body: unknown;
    try {
      body = text ? JSON.parse(text) : undefined;
    } catch {
      body = text;
    }
    if (!res.ok) {
      const d = (body as { detail?: unknown; error?: { message?: string } } | undefined) ?? {};
      const msg =
        typeof d.detail === "string"
          ? d.detail
          : typeof (d.detail as { error?: { message?: string } })?.error?.message === "string"
            ? (d.detail as { error: { message: string } }).error.message
            : d.error?.message ?? `HTTP ${res.status}`;
      throw new NodeApiError(`${path}: ${msg}`, res.status, body);
    }
    return body as T;
  }

  async models(): Promise<NodeModel[]> {
    const r = await this.json<{ data?: NodeModel[] }>("/v1/models");
    return Array.isArray(r?.data) ? r.data : [];
  }

  balance(key: string): Promise<BalanceInfo> {
    return this.json<BalanceInfo>("/v1/balance/info", {}, key);
  }

  /** Create an `sk-` key funded by a Cashu token (the token is redeemed by the node). */
  createKeyFromCashu(token: string): Promise<{ api_key: string; balance: number }> {
    return this.json("/v1/balance/create", { method: "POST", body: JSON.stringify({ initial_balance_token: token }) });
  }

  /** Top up an existing key with a Cashu token. */
  topupCashu(key: string, token: string): Promise<{ msats?: number; [k: string]: unknown }> {
    return this.json("/v1/balance/topup", { method: "POST", body: JSON.stringify({ cashu_token: token }) }, key);
  }

  /** A Lightning invoice that creates a new key (`purpose: create`) or tops up `key`. */
  lightningInvoice(amountSats: number, key?: string): Promise<LightningInvoice> {
    return this.json(
      "/lightning/invoice",
      { method: "POST", body: JSON.stringify({ amount_sats: amountSats, purpose: key ? "topup" : "create" }) },
      key,
    );
  }

  lightningStatus(invoiceId: string): Promise<LightningInvoiceStatus> {
    return this.json(`/lightning/invoice/${encodeURIComponent(invoiceId)}/status`);
  }

  /**
   * Withdraw the key's whole remaining balance: as a Cashu token by default,
   * or to a Lightning address. The key is emptied.
   */
  refund(key: string, lightningAddress?: string): Promise<{ token?: string; [k: string]: unknown }> {
    return this.json(
      "/v1/balance/refund",
      { method: "POST", body: JSON.stringify(lightningAddress ? { lightning_address: lightningAddress } : {}) },
      key,
    );
  }
}
