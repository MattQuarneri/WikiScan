import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { spawn, type Subprocess } from "bun";
import { existsSync } from "node:fs";

// Configuration
const WIKISCAN_BIN = process.env.WIKISCAN_BIN || "target/release/wikiscan";
// If binary doesn't exist, we might try cargo run, but let's assume binary for now or let user config.

class WikiScanClient {
  private proc: Subprocess | null = null;
  private buffer = "";
  private currentResolver: ((output: string) => void) | null = null;
  private isReady = false;

  constructor() {
    this.start();
  }

  start() {
    let cmd = process.env.WIKISCAN_CMD 
      ? process.env.WIKISCAN_CMD.split(" ") 
      : ["cargo", "run", "--release", "--quiet"];
    
    // Check if binary exists to avoid cargo startup time
    if (!process.env.WIKISCAN_CMD && existsSync("target/release/wikiscan")) {
        cmd = ["target/release/wikiscan"];
    }

    console.error(`[WikiScan] Spawning: ${cmd.join(" ")}`);
    
    this.proc = spawn(cmd, {
      stdin: "pipe",
      stdout: "pipe",
      stderr: "pipe", // Capture stderr to avoid polluting MCP stdio
    });

    this.readLoop();
    this.readStderr();
  }

  private async readLoop() {
    if (!this.proc || !this.proc.stdout) return;
    const reader = this.proc.stdout.getReader();
    const decoder = new TextDecoder();

    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        const chunk = decoder.decode(value, { stream: true });
        this.buffer += chunk;
        this.checkPrompt();
      }
    } catch (e) {
      console.error("[WikiScan] Error reading stdout:", e);
    }
  }

  private async readStderr() {
    if (!this.proc || !this.proc.stderr) return;
    const reader = this.proc.stderr.getReader();
    const decoder = new TextDecoder();
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        // Just log stderr to MCP stderr (console.error)
        console.error(`[WikiScan stderr] ${decoder.decode(value)}`);
      }
    } catch {}
  }

  private checkPrompt() {
    // Prompts: "W > ", "I > ", "[i ... ] > "
    // Regex: /(?:W|I|\[i \d+ \(\d+\)\]) > $/
    // Note: The prompt is at the end of the buffer
    if (this.buffer.match(/(?:W|I|\[i \d+ \(\d+\)\]) > $/)) {
      if (this.currentResolver) {
        const output = this.buffer;
        this.buffer = "";
        const resolver = this.currentResolver;
        this.currentResolver = null;
        resolver(output);
      } else {
        // Initial startup prompt or unexpected prompt
        // Clear buffer so we don't accumulate
        this.buffer = ""; 
      }
      this.isReady = true;
    }
  }

  async sendCommand(cmd: string): Promise<string> {
    if (!this.proc || !this.proc.stdin) throw new Error("WikiScan not running");

    // Wait if a command is already in flight (simple mutex)
    while (this.currentResolver) {
      await new Promise((r) => setTimeout(r, 100));
    }

    // Reset buffer (careful: might lose race if prompt comes *just* now, but usually we are idle)
    // Actually, checkPrompt clears buffer when prompt arrives.
    // If we are idle, buffer should be empty-ish (setup prompt consumed).

    return new Promise((resolve) => {
      this.currentResolver = resolve;
      // Write command
      const writer = this.proc!.stdin.getWriter();
      writer.write(new TextEncoder().encode(cmd + "\n"));
      writer.releaseLock();
      // writer.close() would close stdin, we don't want that.
      // But Bun's spawn stdin is a specialized stream.
      // this.proc.stdin.write(cmd + "\n"); // Bun < 1.0, but `spawn` returns standard streams?
      // Bun's `spawn` returns ReadableStream/WritableStream.
    });
  }

  async close() {
    this.proc?.kill();
  }
}

const client = new WikiScanClient();

const server = new Server(
  {
    name: "wikiscan-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

/* Define Tools */

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "set_dump_path",
        description: "Set the path to the Wikipedia XML BZ2 dump file. Required before indexing.",
        inputSchema: {
          type: "object",
          properties: {
            path: { type: "string", description: "Absolute path to .xml.bz2 file" },
          },
          required: ["path"],
        },
      },
      {
        name: "load_index",
        description: "Load an existing persistent index or build a resumable one for a keyword.",
        inputSchema: {
          type: "object",
          properties: {
            keyword: { type: "string", description: "Keyword to index (e.g. 'Science')" },
          },
          required: ["keyword"],
        },
      },
      {
        name: "search_dump",
        description: "Scan the dump for a keyword to build a new in-memory index layer.",
        inputSchema: {
          type: "object",
          properties: {
            keyword: { type: "string", description: "Keyword to search for" },
          },
          required: ["keyword"],
        },
      },
      {
        name: "filter_index",
        description: "Filter the current index by title substring (in-memory only, fast).",
        inputSchema: {
          type: "object",
          properties: {
            substring: { type: "string" },
          },
          required: ["substring"],
        },
      },
      {
        name: "get_page_text",
        description: "Get the plain text content of a wikipedia page from the current index.",
        inputSchema: {
          type: "object",
          properties: {
            title: { type: "string", description: "Page title (exact or close match)" },
          },
          required: ["title"],
        },
      },
      {
        name: "get_page_json",
        description: "Get the JSON structure (headings, sections, raw wikitext) of a page.",
        inputSchema: {
          type: "object",
          properties: {
            title: { type: "string" },
          },
          required: ["title"],
        },
      },
       {
        name: "back",
        description: "Go back to the previous index layer (pop current index stack).",
        inputSchema: {
            type: "object",
            properties: {},
        }
      }
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    let output = "";

    switch (name) {
      case "set_dump_path": {
        const path = (args as any).path;
        output = await client.sendCommand(`W=${path}`);
        break;
      }
      case "load_index": {
        const kw = (args as any).keyword;
        output = await client.sendCommand(`I=${kw}`);
        break;
      }
      case "search_dump": {
        const kw = (args as any).keyword;
        output = await client.sendCommand(`S=${kw}`);
        break;
      }
      case "filter_index": {
        const sub = (args as any).substring;
        output = await client.sendCommand(`filter=${sub}`);
        break;
      }
      case "get_page_text": {
        const title = (args as any).title;
        output = await client.sendCommand(`PageText=${title}`);
        // Parse extracting the content between markers if found
        // Format: ===== Title (page_id: ...) =====\nCONTENT\n===== END Title =====
        const match = output.match(/===== .*? =====\n([\s\S]*?)\n===== END .*? =====/);
        if (match) {
            output = match[1];
        }
        break;
      }
      case "get_page_json": {
        const title = (args as any).title;
        output = await client.sendCommand(`PageJSON=${title}`);
        // Attempt to extract JSON logic if mixed with other text?
        // Usually wikiscan prints JSON directly.
        // But the prompt " > " is appended at the end.
        // We should strip the prompt from the output variable in all cases anyway?
        // The readLoop consumes the prompt to detect readiness. 
        // Wait, my readLoop includes the prompt in `this.buffer`. 
        // `checkPrompt` calls `resolver(output)` with the buffer *including* the prompt.
        // So I should strip the trailing prompt.
        output = output.replace(/(?:W|I|\[i \d+ \(\d+\)\]) > $/, "").trim();
        break;
      }
      case "back": {
        output = await client.sendCommand("back");
        break;
      }
      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    // Generic prompt stripping if not handled specificly
    output = output.replace(/(?:W|I|\[i \d+ \(\d+\)\]) > $/, "").trim();

    return {
      content: [{ type: "text", text: output }],
    };

  } catch (error: any) {
    return {
      content: [{ type: "text", text: `Error: ${error.message}` }],
      isError: true,
    };
  }
});

// Start server
const transport = new StdioServerTransport();
await server.connect(transport);
