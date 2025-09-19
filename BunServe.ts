// server.ts (Bun)
const TCP_HOST = process.env.REPL_HOST ?? "127.0.0.1";
const TCP_PORT = parseInt(process.env.REPL_PORT ?? "9000", 10);

function isAuthorized(req: Request): boolean {
  // TODO: Replace with real auth (JWT/cookies/session)
  const token = req.headers.get("x-auth-token");
  return !!token && token.length > 10;
}

Bun.serve({
  port: parseInt(process.env.PORT ?? "8080", 10),
  fetch(req, server) {
    const { pathname } = new URL(req.url);
    if (pathname === "/ws") {
      if (!server.upgrade(req)) {
        return new Response("Upgrade failed", { status: 426 });
      }
      return;
    }
    return new Response("OK");
  },
  websocket: {
    open(ws) {
      const req = ws.data as Request | undefined;
      // Optional per-connection init
    },
    async message(ws, message) {
      // We attach TCP socket to ws.data.tcp on connection (see 'open' below)
      const tcp = (ws as any).tcp as Bun.Socket | undefined;
      if (!tcp || tcp.readyState !== "open") return;
      try {
        // Ensure line endings: REPL expects line-based input (you already trim in Rust)
        // If 'message' is string or ArrayBuffer, just forward raw; client should send "\n".
        await tcp.write(message);
      } catch {
        try { ws.close(); } catch {}
      }
    },
    async open(ws) {
      // Access the original Request for auth; Bun provides it via ws.data in some setups.
      // If your Bun version doesn’t inject it, move the auth into fetch() and store state.
      // For safety, perform auth in fetch() before upgrade.
      // Using a simple env for demo purposes:
      // NOTE: The recommended place to auth is in fetch() pre-upgrade.
      // Here we assume upgrade only happens after auth.

      // Connect to Rust TCP REPL
      const tcp = await Bun.connect({ hostname: TCP_HOST, port: TCP_PORT });
      (ws as any).tcp = tcp;

      // TCP->WS relay
      tcp.ondata = (chunk: Uint8Array) => {
        try { ws.send(chunk); } catch { try { tcp.end(); } catch {} }
      };
      tcp.onclose = () => {
        try { ws.close(); } catch {}
      };
      tcp.onerror = () => {
        try { ws.close(); } catch {}
      };

      // Heartbeat (optional)
      const pingInt = setInterval(() => {
        try { ws.ping(); } catch {}
      }, 30000);
      (ws as any).pingInt = pingInt;
    },
    close(ws) {
      const tcp = (ws as any).tcp as Bun.Socket | undefined;
      const pingInt = (ws as any).pingInt as any;
      if (pingInt) clearInterval(pingInt);
      try { tcp?.end(); } catch {}
    },
  },
});