# 🌐 WikiScan 🔍

WikiScan is a fast and lightweight tool for indexing and searching Wikipedia dump files directly, without needing to fully decompress or import them.
It supports interactive keyword-based indexing, filter the indexs, search the articles in the index, and extracting the page text (either raw, plain, or json).
The app's CLI can be used accessed locally via a local or network (websocket) terminal.

## Features

- **Direct Wikipedia dump search**: Scan and search `.xml.bz2` Wikipedia dumps for article titles and keywords without full extraction.
- **Interactive REPL**: Start a session to build indexes, search, and explore articles with commands like `filter=`, `sarch=`, `show`, `back`, and more.
- **Keyword indexing**: Build in-memory or persistent indexes for fast repeated searches. Save/load index files for later use.
- **Network terminal support**: Expose the REPL over TCP using built-in server mode (`--tcp :PORT`) or external tools like `socat`/`ncat` for remote access.
- **Minimal dependencies**: No database required; works directly on compressed dumps using efficient streaming and indexing.
- **ANSI color output**: Enhanced readability in supported terminals.

## Usage

### Scan for a keyword (one-off):
```sh
cargo run --release -- "/path/to/enwiki-YYYYMMDD-pages-articles-multistream.xml.bz2" "Keyword"
```

### Start interactive REPL:
```sh
cargo run --release
```
Then set dump and search keyword:
```
W=/path/to/enwiki-YYYYMMDD-pages-articles-multistream.xml.bz2

I=Keyword Index // Create and persist an index named "Keyword".idx which holds the atticle title and byte offset into the bz2 dump file. This will take longer to build the first time. The next time the inddex is loaded from disk for faster startup.

filter=Keyword // Filters articles titles by "Keyword"; uses this to reduce the current index size to speed up your searches.
back // Go back to the previous filtered index.

search=Keyword // Searches the articles in the current index for the keyword. That's why pre-filtering improves the speed; so you're not needlessly searching irrelevant articles.
```

### Network terminal (TCP):
Run WikiScan in TCP mode:
```sh
cargo run --release -- --tcp :9000
```
Or use socat/ncat for quick experiments:
```sh
socat TCP-LISTEN:9000,reuseaddr,fork EXEC:./wikiscan
# or
ncat -lk 9000 -e ./wikiscan
```

### Websocket REPL Encapsulation:
Recommended architecture

* Bun as the WebSocket gateway
    * Authenticates the client (JWT/cookies/session).
    * On WS connect, opens a TCP connection to your Rust REPL server (wikiscan --tcp:9000).
    * Bi-directionally relays data between WS and TCP (one WS = one REPL session).
    * Terminates TLS or sits behind a reverse proxy that does.

* Rust process
    * Run your binary in TCP mode: wikiscan --tcp:9000
    * Each TCP connection = an independent REPL session.
    * Colors disabled in network mode (already implemented).
    * “Q” still cancels long-running jobs (you just send Q\n from the WS client).

* Reverse proxy (optional but recommended)
    * Caddy/Nginx/Traefik for TLS, rate-limit, logging, request size limits.
    * Can also terminate TLS and then forward to Bun (WS) and to Rust (TCP if you want to split networks).

## Bun WebSocket bridge (example)

* BunServe.ts is a compact Bun app that:
    * Auth checks a header (replace with your auth).
    * Opens a TCP connection to 127.0.0.1:9000.
    * Pipes WS -> TCP and TCP -> WS with basic backpressure handling, heartbeats, and cleanup.

### How To Run everything

* Start Rust REPL server:
```sh
wikiscan --tcp:9000
```
* Start Bun gateway:
```sh
bun run server.ts
```
* Client connects to WS:
```sh
wss://your-host/ws
```
Send text lines like W=/path/to/enwiki… followed by newline.
“Q” and Enter cancels long-running ops.

### Containerization (quick plan)

Multi-stage Dockerfile for Rust:
```Dockerfile
# Stage 1: build with cargo build --release
# Stage 2: distroless or debian-slim, copy the binary only
# Expose 9000/tcp
```
Bun Dockerfile:
```Dockerfile
FROM oven/bun
COPY server.ts package.json bun.lockb
RUN bun install
EXPOSE 8080
```
docker-compose.yml:
```yaml
service “wikiscan”: runs wikiscan --tcp:9000, mounts the dump path (or uses local SSD).
service “gateway”: runs Bun, depends_on wikiscan, exposes port 8080.
Put Caddy/Traefik in front for TLS and to expose only 443/80.
```

### Operational tips

Authentication
* Keep the TCP REPL bound to localhost or a private interface.
* Bun authenticates and is the only thing talking to the TCP port.
Backpressure and framing
* The REPL is line-based. Ensure clients send newline-delimited commands.
* Your current loop trims input and prints output promptly; we added flushes in the refactor.
Heartbeats and idle timeouts
* Use ws.ping() every 30s and close idle sessions if needed.
Cancellation
* “Q” + Enter is still the canonical cancel; WS clients send “Q\n”.
S3 data
* For large scans, copying the dump to a local ephemeral volume before starting is typically faster and more predictable than streaming directly over S3. If you need remote access, consider a pre-warmed EC2 instance with local NVMe.
Alternative: Native Rust WebSocket

If you prefer a single binary: axum + tokio-tungstenite can serve /ws, authenticate via headers/cookies, and call run_repl over a stream wrapper. It’s fast and removes the Bun dependency, but you then own auth middleware in Rust. Your current TCP + Bun split keeps concerns nicely separated.

## Notes

- Scanning large dumps is CPU/IO intensive; use release mode for best performance.
- Indexes are built in memory by default; use the `save` command to persist them.
- The REPL supports basic navigation and index management commands.
- For network use, consider security: bind to localhost or use a proxy for authentication/TLS.
- See `notes.md` for advanced usage, operational tips, and integration ideas (WebSocket, systemd, etc).

## License
MIT

Developed by Matthew Quarneri with assitance from a windsurfing ChadG

