// `connectivitizer mcp`: the workspace tools as a Model Context Protocol server on standard
// input and output, for AI clients. One JSON-RPC message per line in each direction; nothing
// else is written to standard output.

import { createInterface } from 'node:readline';
import type { Readable, Writable } from 'node:stream';
import { ConnectivitizerError } from '../core/errors.js';
import type { Tool, WorkspaceTools } from './tools.js';

const PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];

const INSTRUCTIONS = [
  'Manages a Connectivitizer workspace: devices, device keys, API keys, shared keys, and who may reach what.',
  'Call status first. When not signed in, call sign_in: it opens the web app in the browser, where the person approves; then call status until it says signedIn.',
  'Keys are never returned. Tools that make a key write it to the files named in saveTo (a secrets.h, secrets.json or .env of the project); do not read those files back.',
  'Three kinds of key: a device key (czd_) is what a device logs in with; an API key (czk_) is what a program that opens sessions uses; a shared key (czs_) is the end-to-end secret both ends hold and the platform never sees.',
  'Keys and devices cannot be revoked or deleted here; that is done in the web app.',
].join(' ');

interface Request {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
}

/** Serves the tools until `input` ends. */
export function serveMcp(tools: WorkspaceTools, version: string, input: Readable = process.stdin, output: Writable = process.stdout): Promise<void> {
  const byName = new Map<string, Tool>(tools.list().map((tool) => [tool.name, tool]));
  const send = (message: unknown): void => {
    output.write(JSON.stringify(message) + '\n');
  };

  const handle = async (request: Request): Promise<void> => {
    const { id, method } = request;
    const answers = id !== undefined && id !== null;
    const result = (value: unknown): void => {
      if (answers) {
        send({ jsonrpc: '2.0', id, result: value });
      }
    };
    switch (method) {
      case 'initialize': {
        const wanted = request.params?.protocolVersion;
        result({
          protocolVersion: typeof wanted === 'string' && PROTOCOL_VERSIONS.includes(wanted) ? wanted : PROTOCOL_VERSIONS[0],
          capabilities: { tools: {} },
          serverInfo: { name: 'connectivitizer', title: 'Connectivitizer', version },
          instructions: INSTRUCTIONS,
        });
        return;
      }
      case 'ping':
        result({});
        return;
      case 'tools/list':
        result({ tools: [...byName.values()].map(({ name, description, inputSchema }) => ({ name, description, inputSchema })) });
        return;
      case 'tools/call': {
        const name = request.params?.name;
        const tool = typeof name === 'string' ? byName.get(name) : undefined;
        if (!tool) {
          if (answers) {
            send({ jsonrpc: '2.0', id, error: { code: -32602, message: `Unknown tool: ${String(name)}` } });
          }
          return;
        }
        try {
          const args = request.params?.arguments;
          const value = await tool.run(args !== null && typeof args === 'object' ? (args as Record<string, unknown>) : {});
          result({ content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] });
        } catch (error) {
          // A refusal is an answer the model can act on, not a failure of the protocol.
          const code = error instanceof ConnectivitizerError ? `${error.code}: ` : '';
          result({ content: [{ type: 'text', text: code + (error instanceof Error ? error.message : String(error)) }], isError: true });
        }
        return;
      }
      default:
        if (answers) {
          send({ jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${String(method)}` } });
        }
    }
  };

  return new Promise((resolve) => {
    const lines = createInterface({ input, crlfDelay: Infinity });
    let running: Promise<void> = Promise.resolve();
    lines.on('line', (line) => {
      if (line.trim() === '') {
        return;
      }
      let request: Request;
      try {
        request = JSON.parse(line) as Request;
      } catch {
        send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
        return;
      }
      // One after the other: two tools must not write the same secrets file at once.
      running = running.then(() => handle(request)).catch(() => undefined);
    });
    lines.on('close', () => void running.then(resolve));
  });
}
