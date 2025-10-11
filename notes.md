Every article record in the Wikipedia dump has the same standard XML schema — there isn’t per-article variation in the record type. What differs is only the content inside the <text> element (the wikitext of the article).

<page>
  <title>Tree</title>
  <ns>0</ns>                 <!-- namespace; 0 = main/article -->
  <id>12345</id>             <!-- page ID -->
  <revision>
    <id>67890</id>           <!-- revision ID -->
    <parentid>67889</parentid>
    <timestamp>2025-01-01T00:00:00Z</timestamp>
    <contributor>
      <username>SomeUser</username>
      <id>2468</id>
    </contributor>
    <comment>minor edit</comment>
    <model>wikitext</model>
    <format>text/x-wiki</format>
    <text xml:space="preserve" bytes="123456"> ... wikitext ... </text>
    <sha1>abcdef123456</sha1>
  </revision>
</page>

cargo run --release -- "/Volumes/Samsung 128/wikipedia/enwiki-20241001-pages-articles-multistream.xml.bz2" "Terminator"

Start REPL:
cargo run --release
REPL session:
W=/Volumes/Samsung 128/wikipedia/enwiki-20241001-pages-articles-multistream.xml.bz2

s=

s=Terminator

i=Terminator

Notes
Scanning the full dump is CPU/IO heavy; use release mode for speed.
i= builds the index in memory only (per your request). If you want to persist it later, we can add a simple save command to write “titleoffset” lines.


websocat -s 9001 exec:./wikiscan
* Pros: Fast way to get a “network terminal” that runs from a web page.
* Cons: 

socat TCP-LISTEN:9000,reuseaddr,fork EXEC:./wikiscan
* Cons: Per-connection process spawn; limited control over auth/TLS unless you add a proxy in front.

Use a stdio wrapper (fast to try; no code changes)
socat
One-liner to expose your current interactive REPL over TCP:
socat TCP-LISTEN:9000,reuseaddr,fork EXEC:./wikiscan
Each TCP connection spawns a process and wires its stdin/stdout to the socket. The fork option allows multiple simultaneous connections (each gets its own wikiscan process).
Pros: No code changes. Great for quick experiments.
Cons: Per-connection process spawn; limited control over auth/TLS unless you add a proxy in front.
ncat (Nmap’s netcat)
ncat -lk 9000 -e ./wikiscan
Not all netcat variants support -e. Prefer ncat for security flags and TLS if needed.
Similar pros/cons as socat.
inetd/xinetd or systemd socket activation
inetd: Adds an entry so that when a connection arrives, inetd spawns wikiscan with the socket as its stdin/stdout.
systemd socket activation: systemd binds the port and passes a ready file descriptor to the process (fd 3); your app reads/writes to that FD as if it were a socket.
Pros: Battle-tested, integrates well with service management. Your app can remain stdio-based.
Cons: Requires service config; more ops setup.
Add a native TCP mode inside the app (simple code; more control)
Add a CLI option, e.g. --tcp :9000. When set:
Use std::net::TcpListener::bind(addr)?;
On accept(), spawn a task/thread and hand the TcpStream to a connection handler that:
Reads lines from BufReader<TcpStream> instead of io::stdin()
Writes to &mut TcpStream instead of io::stdout()
You can keep your REPL unchanged by extracting the “session loop” to generic Read + Write parameters. Example shape:
fn run_repl<R: BufRead, W: Write>(r: R, mut w: W) -> Result<()>
In stdio mode: run_repl(io::BufReader::new(io::stdin()), io::stdout())
In TCP mode: run_repl(io::BufReader::new(stream.try_clone()? ), stream)
Pros: Good control over auth/logging/limits; easy to multiplex multiple clients; you can add a banner, per-connection state, etc.
Cons: Some refactor needed (cleanly separate REPL IO from core logic; you’re already close).
WebSocket/HTTP bridge (useful for browsers/terminals in the web)
If you want to surface the REPL in a browser:
Use a tiny WebSocket server and pass WS frames to your REPL’s stdin/stdout equivalents.
Or use websocat to bridge WebSocket to stdio:
websocat -s 9001 exec:./wikiscan
Pros: Fast way to get a “network terminal” that runs from a web page.
Cons: More moving parts. If you need a structured API later, a proper HTTP/JSON API is better.
Detecting “stdio vs net” mode

Simple approach: a CLI flag.
Default: stdio mode (your current behavior).
--tcp :port: network terminal mode.
Alternative: environment variable (e.g. WIKISCAN_NET=:9000).
For inetd/systemd: your app can detect if stdin is a socket using libc/nix (fstat/S_ISSOCK), and adapt automatically.
Operational notes

Security
Do NOT expose raw REPL ports to the internet unauthenticated.
Bind to localhost or put it behind a reverse proxy that handles TLS and auth (e.g., Caddy/Nginx/Traefik).
Multiplexing and state
Per-connection sessions are easy with the “spawn per connection” model (both socat and a native server can do this).
Your REPL session state (dump path, index stack) should be per connection.
Terminal quirks
What you have is line-oriented, not a full TTY. That’s fine; avoid relying on terminal control sequences beyond simple ANSI colors.
Telnet/terminal emulators inject CRLF; use .trim() as you do.
Cancellation/long-running ops
With a connection-per-session, your existing cancellation (Q then Enter) continues to work. For TCP, ensure you handle disconnects gracefully (stream EOF).
When to choose which

Want zero code changes now? Use socat or ncat. It’s perfect to validate the “network terminal” idea in minutes.
Want a maintainable “netin/out” feature you can ship? Add a --tcp mode and refactor 
start_interactive()
 to run against generic Read/Write. This keeps the UX intact and gives you room to add auth, logging, TLS via a proxy, etc.
Want a browser-based experience? Use websocat for a quick bridge, or later add a small WebSocket server (or a proper HTTP/JSON API if you want structured endpoints).
If you want, I can:

Refactor 
start_interactive()
 into a run_repl<R: BufRead, W: Write> and add a --tcp mode with TcpListener, or
Provide a one-liner socat script and add a README section explaining the network terminal usage.