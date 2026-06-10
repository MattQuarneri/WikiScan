# WikiScan MCP Server

This project includes a Model Context Protocol (MCP) server that exposes WikiScan's functionality to AI agents.

## Features

The MCP server wraps the interactive WikiScan REPL and exposes the following tools:

- `set_dump_path`: Load a Wikipedia XML BZ2 dump.
- `load_index`: Load or build a persistent index for a keyword.
- `search_dump`: Perform a memory-only search/index for a keyword.
- `filter_index`: Filter the current index by a title substring.
- `get_page_text`: Retrieve the plain text of a page.
- `get_page_json`: Retrieve the structured JSON of a page.

## Usage

### Prerequisites

- [Bun](https://bun.sh)
- WikiScan binary built (`cargo build --release`)

### Running the Server

Start the MCP server using Bun:

```sh
bun run mcp_server.ts
```

This starts an MCP server over stdio. You can configure your MCP client (e.g., Claude Desktop, Agent) to use this script.

### Configuration

- `WIKISCAN_CMD`: Override the command to launch WikiScan (default: `target/release/wikiscan` or `cargo run --release`).

## Example Agent Workflow

1. **Initialize**: Call `set_dump_path(path=".../enwiki-...xml.bz2")`.
2. **Index**: Call `load_index(keyword="Physics")` to focus on relevant articles.
3. **Search/Filter**: Use `filter_index(substring="Quantum")` to narrow down.
4. **Read**: Call `get_page_text(title="Quantum mechanics")` to read content.

## Note on Title Formats

- WikiScan supports both spaces ("Economic sector") and underscores ("Economic_sector").
- Parentheses passed in titles are preserved (e.g., "Mercury (element)").
- The `get_page_text` tool handles output parsing automatically.
