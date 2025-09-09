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

## Notes

- Scanning large dumps is CPU/IO intensive; use release mode for best performance.
- Indexes are built in memory by default; use the `save` command to persist them.
- The REPL supports basic navigation and index management commands.
- For network use, consider security: bind to localhost or use a proxy for authentication/TLS.
- See `notes.md` for advanced usage, operational tips, and integration ideas (WebSocket, systemd, etc).

## License
MIT

Developed by Matthew Quarneri with assitance from a windsurfing ChadG

