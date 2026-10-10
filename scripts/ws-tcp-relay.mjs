// Test-only WebSocket→TCP relay: ws://127.0.0.1:7451 → api.venice.ai:443
// (used by the TLS diagnostic in bench.html?tls=…). Not part of the protocol.
import { createServer, connect } from "node:net";
import { WebSocketServer } from "ws";
const [, , port = "7451", target = "api.venice.ai:443"] = process.argv;
const [host, tport] = target.split(":");
const wss = new WebSocketServer({ port: Number(port), host: "127.0.0.1" });
wss.on("connection", (ws) => {
  const sock = connect(Number(tport), host);
  sock.on("data", (d) => ws.send(d));
  sock.on("close", () => ws.close());
  sock.on("error", () => ws.close());
  ws.on("message", (m) => sock.write(m));
  ws.on("close", () => sock.destroy());
});
console.log(`relay ws://127.0.0.1:${port} -> ${target}`);
void createServer;
