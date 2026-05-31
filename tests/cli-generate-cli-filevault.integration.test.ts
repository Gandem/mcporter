import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import { createServer } from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import express from 'express';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { z } from 'zod';
import type { ServerDefinition } from '../src/config.js';
import { vaultKeyForDefinition } from '../src/oauth-vault.js';

// Standalone harness (kept separate from cli-generate-cli.integration.test.ts on purpose):
// this fork-only test exercises the keychain -> file-vault downgrade in generated CLIs, so
// living in its own file means it never conflicts when rebasing onto upstream.
const CLI_ENTRY = fileURLToPath(new URL('../dist/cli.js', import.meta.url));

async function ensureDistBuilt(): Promise<void> {
  try {
    await fs.access(CLI_ENTRY);
  } catch {
    throw new Error('dist/cli.js is missing; run `pnpm build` before invoking this integration test directly.');
  }
}

async function runGeneratedCli(
  bundlePath: string,
  args: string[],
  env: NodeJS.ProcessEnv
): Promise<{ stdout: string; stderr: string }> {
  return await new Promise<{ stdout: string; stderr: string }>((resolve, reject) => {
    execFile(process.execPath, [bundlePath, ...args], { env }, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(`${error.message}\nSTDOUT:\n${stdout}\nSTDERR:\n${stderr}`));
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}

describe('generated CLI file-vault downgrade', () => {
  let baseUrl: URL;
  let tokenUrl: URL;
  let shutdown: (() => Promise<void>) | undefined;
  const seenAuthorizationHeaders: string[] = [];
  const refreshRequests: Array<Record<string, unknown>> = [];

  beforeAll(async () => {
    await ensureDistBuilt();
    const app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: false }));
    const server = new McpServer({ name: 'filevault', title: 'File-vault integration harness', version: '1.0.0' });
    server.registerTool(
      'ping',
      {
        title: 'Ping',
        description: 'Simple health check',
        inputSchema: { echo: z.string().optional() },
        outputSchema: { ok: z.boolean(), echo: z.string().optional() },
      },
      async ({ echo }) => ({
        content: [{ type: 'text', text: JSON.stringify({ ok: true, echo: echo ?? 'hi' }) }],
        structuredContent: { ok: true, echo: echo ?? 'hi' },
      })
    );

    app.post('/token', (req, res) => {
      refreshRequests.push({
        authorization: req.headers.authorization,
        body: req.body,
      });
      res.json({ access_token: 'refreshed-token', token_type: 'Bearer', expires_in: 3600 });
    });

    app.post('/mcp', async (req, res) => {
      if (req.headers.authorization) {
        seenAuthorizationHeaders.push(req.headers.authorization);
      }
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      res.on('close', () => {
        transport.close().catch(() => {});
      });
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    });

    const httpServer = createServer(app);
    await new Promise<void>((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
    const address = httpServer.address();
    if (!address || typeof address === 'string') {
      throw new Error('Failed to start integration server');
    }
    baseUrl = new URL(`http://127.0.0.1:${address.port}/mcp`);
    tokenUrl = new URL('/token', baseUrl);
    shutdown = async () =>
      await new Promise<void>((resolve, reject) => {
        httpServer.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      });
  }, 60_000);

  afterAll(async () => {
    if (shutdown) {
      await shutdown();
    }
  });

  it('forces the file vault in generated CLIs even when the keychain backend is requested', async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcporter-cli-generated-filevault-'));
    try {
      const bundlePath = path.join(tempDir, 'filevault.cli.js');
      const dataHome = path.join(tempDir, 'data');
      const vaultPath = path.join(dataHome, 'mcporter', 'credentials.json');

      const definition = {
        name: 'filevault-generated',
        description: 'Generated CLI file-vault harness',
        command: { kind: 'http', url: baseUrl },
        auth: 'refreshable_bearer',
        refresh: {
          tokenEndpoint: tokenUrl.toString(),
          clientAuthMethod: 'none',
        },
      } satisfies ServerDefinition;
      const vaultEntryKey = vaultKeyForDefinition(definition);
      const seedVault = () =>
        fs.writeFile(
          vaultPath,
          JSON.stringify(
            {
              version: 1,
              entries: {
                [vaultEntryKey]: {
                  serverName: definition.name,
                  serverUrl: baseUrl.toString(),
                  updatedAt: new Date().toISOString(),
                  tokens: {
                    access_token: 'expired-token',
                    refresh_token: 'refresh-token',
                    token_type: 'Bearer',
                    expires_at: 0,
                  },
                },
              },
            },
            null,
            2
          ),
          'utf8'
        );
      await fs.mkdir(path.dirname(vaultPath), { recursive: true });
      await seedVault();

      const inline = JSON.stringify({
        name: definition.name,
        description: definition.description,
        command: baseUrl.toString(),
        auth: definition.auth,
        refresh: definition.refresh,
      });
      await new Promise<void>((resolve, reject) => {
        execFile(
          process.execPath,
          [CLI_ENTRY, 'generate-cli', '--server', inline, '--bundle', bundlePath, '--runtime', 'node'],
          { cwd: tempDir, env: { ...process.env, XDG_DATA_HOME: dataHome, MCPORTER_NO_FORCE_EXIT: '1' } },
          (error, stdout, stderr) => {
            if (error) {
              reject(new Error(`${error.message}\nSTDOUT:\n${stdout}\nSTDERR:\n${stderr}`));
              return;
            }
            resolve();
          }
        );
      });

      // Reset so the generated run must refresh on its own.
      await seedVault();
      seenAuthorizationHeaders.length = 0;
      refreshRequests.length = 0;

      // Request the keychain backend; a generated CLI must downgrade to the file vault and warn once.
      const result = await runGeneratedCli(bundlePath, ['ping', '--echo', 'filevault', '--output', 'json'], {
        ...process.env,
        XDG_DATA_HOME: dataHome,
        MCPORTER_CREDENTIAL_BACKEND: 'keychain',
        MCPORTER_NO_FORCE_EXIT: '1',
      });

      expect(result.stdout).toContain('filevault');
      expect(result.stderr).toContain('keychain credential backend is not available in generated CLIs');
      expect(refreshRequests).toHaveLength(1);
      expect(refreshRequests[0]?.body).toMatchObject({
        grant_type: 'refresh_token',
        refresh_token: 'refresh-token',
      });
      expect(seenAuthorizationHeaders).toContain('Bearer refreshed-token');

      const finalVault = await fs.readFile(vaultPath, 'utf8');
      expect(finalVault).toContain('refreshed-token');
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
    }
  }, 60_000);
});
