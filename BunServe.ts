import { serve, file, type Server } from "bun";

// server.ts (Bun)
const TCP_HOST = process.env.REPL_HOST ?? "127.0.0.1";
const TCP_PORT = parseInt(process.env.REPL_PORT ?? "9000", 10);

function isAuthorized(req: Request): boolean {
  // TODO: Replace with real auth (JWT/cookies/session)
  const url = new URL(req.url);
  const token = url.searchParams.get("token") || "";
  // Or parse cookies: req.headers.get("cookie")
  return token.length > 10; // replace with real check
}

serve({
  port: parseInt(process.env.BUN_PORT ?? "3000", 10),
  fetch(req, server) {
    const { pathname } = new URL(req.url);
    if (pathname === "/ws") {
      if (!isAuthorized(req)) {
        return new Response("Unauthorized", { status: 401 });
      }
      // Pass request into ws.data via upgrade options
      if (!server.upgrade(req, { data: { req } })) {
        return new Response("Upgrade failed", { status: 426 });
      }
      return;
    }
    return new Response(file("./app.html"));
  },
  websocket: {
    async message(ws, message) {
      const tcp: any = (ws as any).tcp;
      if (!tcp) return;
      try {
        await tcp.write(message);
      } catch {
        try { ws.close(); } catch {}
      }
    },
    async open(ws) {
      // Optional: indicate WS is up before backend connect
      try { ws.send("[ws] connected, initializing..."); } catch {}

      // Connect to Rust TCP REPL and wire event handlers
      try {
        await Bun.connect({
          hostname: TCP_HOST,
          port: TCP_PORT,
          socket: {
            open(sock) {
              (ws as any).tcp = sock;
            },
            data(sock, chunk) {
              try { ws.send(chunk as any); } catch { try { sock.end(); } catch {} }
            },
            close(_sock) {
              try { ws.close(); } catch {}
            },
            error(_sock, _err) {
              try { ws.close(); } catch {}
            },
          },
        });
      } catch (e) {
        // Backend TCP not reachable; close WS with an error code so client can retry
        try { ws.send("[ws] backend unavailable"); } catch {}
        try { ws.close(1011, "backend connect failed"); } catch {}
        return;
      }

      // Heartbeat (optional)
      const pingInt = setInterval(() => {
        try { ws.ping(); } catch {}
      }, 30000);
      (ws as any).pingInt = pingInt;
    },
    close(ws) {
      const tcp: any = (ws as any).tcp;
      const pingInt = (ws as any).pingInt as any;
      if (pingInt) clearInterval(pingInt);
      try { tcp?.end(); } catch {}
    },
  },
});