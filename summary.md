# WikiScan

**One-liner:** A fast Rust tool that indexes and searches full Wikipedia dump files in place — without decompressing them — and exposes that power to AI agents through a Model Context Protocol (MCP) server.

## What it is
WikiScan lets you keyword-index, filter, and read articles straight out of a compressed `.xml.bz2` Wikipedia dump, with no database and no full extraction. It runs as an interactive REPL locally or over the network, and ships an MCP server so AI agents (Claude Desktop, custom agents) can drive it as a tool.

## Key capabilities
- Direct search over compressed multistream Wikipedia dumps using streaming + byte-offset indexing; build in-memory or persistent indexes and save/load them for fast repeat searches.
- Page extraction in raw, plain-text, or structured JSON form.
- Interactive REPL with commands for setting the dump, indexing, filtering, and reading.
- Network terminal: same REPL served over TCP (`--tcp:ADDR`) with an optional Bun WebSocket bridge for browsers.
- MCP server exposing six tools (`set_dump_path`, `load_index`, `search_dump`, `filter_index`, `get_page_text`, `get_page_json`) for agent-driven research workflows.

## Notable engineering / architecture
- A two-step "header-scan then validate" indexing strategy: find candidate bzip2 member offsets matching a keyword, then confirm each with a tiny capped decompression read — trading a cheap validation for accuracy, stability, and cost control.
- Transport-agnostic REPL: a generic `ReplService` trait runs the same session loop over any `BufRead`/`Write` streams, so terminal and TCP modes share one implementation and adding transports needs no REPL changes.
- Minimal dependencies; works directly on compressed data via efficient streaming rather than importing terabytes into a store.

## Signals for an AI Architect / AI Implementation Engineer role
- A clean, real-world MCP integration — turning a performance-sensitive Rust tool into agent-callable capabilities is exactly the tool-augmentation work these roles require.
- Demonstrates cost- and latency-aware design (capped validation reads, offset indexing) when exposing large data to LLMs.
- The `ReplService` trait is a textbook composability move: one core, many transports (stdio, TCP, WebSocket, MCP).
