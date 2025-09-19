use anyhow::Result;
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpListener;
use std::thread;

/// A service that can run an interactive session given a reader and writer.
/// Implement this for your application and pass it to the container runners.
pub trait ReplService: Send + Sync + 'static {
    fn run_session<R, W>(&self, stdin: R, out: W, enable_colors: bool) -> Result<()>
    where
        R: BufRead + Send + 'static,
        W: Write + Send + 'static;
}

/// Run a local terminal session (REPL) using the provided service.
pub fn start_terminal<S: ReplService>(service: &S) -> Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    // Auto-detect color for stdio
    let enable_colors = std::env::var("NO_COLOR").ok().is_none();
    service.run_session(BufReader::new(stdin), stdout, enable_colors)
}

/// Start a TCP server that spawns a session per connection using the provided service.
/// Connections will have colors disabled to avoid ANSI noise over raw sockets.
pub fn start_tcp_server<S>(service: S, addr: &str) -> Result<()>
where
    S: ReplService + Clone + Send + 'static,
{
    println!("listening for REPL connections on {}...", addr);
    let listener = TcpListener::bind(addr)?;
    loop {
        let (stream, peer) = listener.accept()?;
        println!("connection from {}", peer);
        let writer = stream.try_clone()?;
        let reader = io::BufReader::new(stream);
        let svc = service.clone();
        thread::spawn(move || {
            let _ = svc.run_session(reader, writer, /*enable_colors=*/ false);
        });
    }
}
