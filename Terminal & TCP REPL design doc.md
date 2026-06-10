# WikiScan REPL Dual-Mode Design (Terminal + TCP)

This document summarizes how WikiScan supports both a local Terminal REPL and a TCP-served REPL using a shared, generic abstraction.

## Overview

- **Goal**: Run the same interactive REPL over two transports:
  - Local terminal (stdio) for developers/operators.
  - TCP server for remote access and browser/WebSocket bridging.
- **Approach**: Abstract the REPL loop behind a [ReplService](cci:2://file:///Users/mattq/Projects/WikiScan/appserv.rs:7:0-12:1) trait injected into transport containers that provide `BufRead` + `Write` streams.

## Key Components

- **[appserv.rs](cci:7://file:///Users/mattq/Projects/WikiScan/appserv.rs:0:0-0:0)**
  - Defines [ReplService](cci:2://file:///Users/mattq/Projects/WikiScan/appserv.rs:7:0-12:1) trait, [start_terminal()](cci:1://file:///Users/mattq/Projects/WikiScan/appserv.rs:14:0-21:1), and [start_tcp_server()](cci:1://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:1406:0-1413:1).
- **[wikiscan.rs](cci:7://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:0:0-0:0)**
  - Implements [WikiScanService](cci:2://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:23:0-23:23) which delegates to the concrete REPL implementation [run_repl()](cci:1://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:460:0-869:1).
  - Dispatches CLI to terminal or TCP mode.
  - Contains the REPL logic ([run_repl()](cci:1://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:460:0-869:1)), session state, and command handlers.
- **[BunServe.ts](cci:7://file:///Users/mattq/Projects/WikiScan/BunServe.ts:0:0-0:0)**
  - Optional WebSocket bridge for browsers; proxies WS frames to the TCP REPL.

## Abstraction: ReplService and Transport Containers

- **Trait**: [ReplService](cci:2://file:///Users/mattq/Projects/WikiScan/appserv.rs:7:0-12:1) in [appserv.rs](cci:7://file:///Users/mattq/Projects/WikiScan/appserv.rs:0:0-0:0)
  - `fn run_session<R, W>(&self, stdin: R, out: W, enable_colors: bool) -> Result<()>`
  - Streams are generic: any `R: BufRead`, `W: Write`.
- **Terminal container**: [start_terminal<S: ReplService>(service: &S)](cci:1://file:///Users/mattq/Projects/WikiScan/appserv.rs:14:0-21:1)
  - Wires `io::stdin()` and `io::stdout()` to the service.
  - Auto-detects color via `NO_COLOR` env.
- **TCP container**: [start_tcp_server<S: ReplService + Clone>(service, addr)](cci:1://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:1406:0-1413:1)
  - `TcpListener::bind(addr)` loop.
  - For each connection, spawns a thread, cloning the service.
  - Disables colors for raw sockets to avoid ANSI noise.

## Service Implementation

- **[WikiScanService](cci:2://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:23:0-23:23)** in [wikiscan.rs](cci:7://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:0:0-0:0)
  - Implements [ReplService](cci:2://file:///Users/mattq/Projects/WikiScan/appserv.rs:7:0-12:1) and simply calls [run_repl(stdin, out, enable_colors)](cci:1://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:460:0-869:1).
  - Keeps REPL logic centralized and transport-agnostic.
  - Code: `impl ReplService for WikiScanService { fn run_session<R,W>(...) { run_repl(stdin, out, enable_colors) } }`

## CLI Dispatch

- **Flag**: TCP mode enabled via `--tcp:ADDR` (examples `--tcp::9000`, `--tcp:127.0.0.1:9000`).
- **Location**: [wikiscan.rs](cci:7://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:0:0-0:0)
  - `if args.len() >= 2 && args[1].starts_with("--tcp:") { ... return start_tcp_server(addr); }`
  - Terminal (default): [start_interactive()](cci:1://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:454:0-458:1) → [start_terminal(&svc)](cci:1://file:///Users/mattq/Projects/WikiScan/appserv.rs:14:0-21:1).
- **Function**: [start_tcp_server(addr: &str) -> Result<()>](cci:1://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:1406:0-1413:1) delegating to [appserv::start_tcp_server(svc, addr)](cci:1://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:1406:0-1413:1).

## REPL Core

- **Function**: [run_repl<R: BufRead, W: Write>(stdin, out, enable_colors) -> Result<()>](cci:1://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:460:0-869:1)
  - Prints banner and help.
  - Parses commands line-by-line.
  - Maintains per-session state in [Session](cci:2://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:181:0-185:1):
    - `dump_path: Option<String>`
    - `indexes: Vec<NamedIndex>` (stack: master → current).
  - Uses `settings.ini` to restore last `W=` and last `I=` on startup.

### Commands (selected)
- `W=<path>`: set dump path. Validates bzip2 readability.
- `I=<keyword>`: build/resume on-disk index `<keyword>.idx`, load as master. Supports cancel with `Q`+Enter.
- `S=<keyword>`: build in-memory index.
- `filter=<substring>`: filter current index by title; pushes a new index.
- `search=<keyword>`: rescan members in current index for matches; pushes new index.
- `Page=` / `PageText=` / `PageJSON=`: retrieve article via index offset.
- `show`, `back`, `quit`.

### Color Handling
- Colors are parameterized:
  - Terminal mode: enable by default (unless `NO_COLOR` set).
  - TCP mode: disabled by container to avoid raw ANSI sequences.

### Cancellation
- Long-running operations (index builds) support cancellation:
  - Terminal: side thread reading [/dev/tty](cci:7://file:///dev/tty:0:0-0:0) (or stdin fallback) watching for `Q\n`, toggles `AtomicBool` cancel.
  - TCP: same `Q\n` protocol works from remote clients since sessions are line-based.

## Transport Flows

- **Terminal REPL**
  - [wikiscan.rs](cci:7://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:0:0-0:0) → [start_interactive()](cci:1://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:454:0-458:1) → [start_terminal(&WikiScanService)](cci:1://file:///Users/mattq/Projects/WikiScan/appserv.rs:14:0-21:1) in [appserv.rs](cci:7://file:///Users/mattq/Projects/WikiScan/appserv.rs:0:0-0:0) → [run_repl(stdin, stdout, enable_colors=true)](cci:1://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:460:0-869:1).

- **TCP REPL**
  - [wikiscan.rs](cci:7://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:0:0-0:0) parses `--tcp:...` → [start_tcp_server(addr)](cci:1://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:1406:0-1413:1) → [appserv::start_tcp_server(svc, addr)](cci:1://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:1406:0-1413:1).
  - Each accepted socket runs [svc.run_session(BufReader<TcpStream>, TcpStream, enable_colors=false)](cci:1://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:26:4-33:5) in a thread.
  - Per-connection session state, isolated and concurrent.

## Optional WebSocket Bridge

- **[BunServe.ts](cci:7://file:///Users/mattq/Projects/WikiScan/BunServe.ts:0:0-0:0)**
  - Accepts `ws://.../ws` after a simple auth check.
  - On WS open: connects TCP to `REPL_HOST:REPL_PORT`, attaches socket to WS.
  - Bridges WS messages → TCP bytes, and TCP bytes → WS frames.
  - Heartbeats via `ws.ping()`.
  - Recommended deployment:
    - Keep TCP REPL bound to localhost/private network.
    - Put TLS/auth in front (reverse proxy or Bun).

## Extensibility Guidelines

- **Add a new transport**: wrap [run_session()](cci:1://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:26:4-33:5) with your IO stream pair and a color policy.
- **Add commands**: extend the [run_repl()](cci:1://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:460:0-869:1) command parsing switch; keep outputs line-oriented and flush.
- **Structured outputs**: prefer adding parallel `...JSON` commands (like `PageJSON`) for machine clients.
- **Security**: never expose raw TCP unauthenticated; always place behind an authenticated gateway.

## Testing Tips

- Terminal: `cargo run --release`
- TCP: `cargo run --release -- --tcp :9000` then `nc 127.0.0.1 9000`
- WebSocket: run Bun server, connect with a WS client, send line-delimited commands.

## Code References

- **Transport abstraction**: [appserv.rs](cci:7://file:///Users/mattq/Projects/WikiScan/appserv.rs:0:0-0:0) ([ReplService](cci:2://file:///Users/mattq/Projects/WikiScan/appserv.rs:7:0-12:1), [start_terminal()](cci:1://file:///Users/mattq/Projects/WikiScan/appserv.rs:14:0-21:1), [start_tcp_server()](cci:1://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:1406:0-1413:1))
- **TCP dispatch**: [wikiscan.rs](cci:7://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:0:0-0:0) CLI parsing for `--tcp:...`
- **REPL core**: [wikiscan.rs](cci:7://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:0:0-0:0) [run_repl()](cci:1://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:460:0-869:1)
- **Service impl**: [wikiscan.rs](cci:7://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:0:0-0:0) [WikiScanService](cci:2://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:23:0-23:23) (delegates to [run_repl](cci:1://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:460:0-869:1))
- **WS bridge**: [BunServe.ts](cci:7://file:///Users/mattq/Projects/WikiScan/BunServe.ts:0:0-0:0)

# Summary

- Implemented a clean separation between transport and REPL logic via [ReplService](cci:2://file:///Users/mattq/Projects/WikiScan/appserv.rs:7:0-12:1).
- Terminal and TCP modes share the same [run_repl()](cci:1://file:///Users/mattq/Projects/WikiScan/wikiscan.rs:460:0-869:1) with only color behavior differing.
- TCP mode is enabled by `--tcp:ADDR`, with per-connection session threads.
- Optional Bun WebSocket bridge provides a browser-accessible REPL without changing Rust code.