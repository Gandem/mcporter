import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ServerDefinition } from '../src/config.js';
import { buildOAuthPersistence } from '../src/oauth-persistence.js';
import {
  clearVaultEntry,
  describeOAuthVault,
  loadVaultEntry,
  resolveOAuthVaultBackend,
  saveVaultEntry,
} from '../src/oauth-vault.js';

// Standalone keychain-backend suite. Kept out of oauth-persistence.test.ts on purpose: that file
// is the hottest one upstream churns in this functional area, so a fork-only `@napi-rs/keyring`
// mock + shared beforeEach/afterEach there would conflict on every rebase. As its own file it
// replays cleanly.
const keyringMocks = vi.hoisted(() => ({
  store: new Map<string, string>(),
  getPasswordError: undefined as Error | undefined,
}));

vi.mock('@napi-rs/keyring', () => {
  class Entry {
    private readonly storeKey: string;
    constructor(service: string, account: string) {
      this.storeKey = `${service}:${account}`;
    }
    getPassword(): string | null {
      if (keyringMocks.getPasswordError) {
        throw keyringMocks.getPasswordError;
      }
      return keyringMocks.store.get(this.storeKey) ?? null;
    }
    setPassword(password: string): void {
      keyringMocks.store.set(this.storeKey, password);
    }
  }
  return { Entry };
});

const mkDef = (name: string): ServerDefinition => ({
  name,
  description: `${name} server`,
  command: { kind: 'http', url: new URL('https://example.com/mcp') },
  auth: 'oauth',
});

describe('oauth vault keychain backend', () => {
  const originalEnv = { ...process.env };
  const tempRoots: string[] = [];
  let homedirSpy!: ReturnType<typeof vi.spyOn>;
  let platformSpy!: ReturnType<typeof vi.spyOn>;
  let hasSpy = false;
  let hasPlatformSpy = false;

  beforeEach(() => {
    keyringMocks.store.clear();
    keyringMocks.getPasswordError = undefined;
    delete process.env.MCPORTER_CREDENTIAL_BACKEND;
    delete process.env.MCPORTER_OAUTH_VAULT_BACKEND;
    delete process.env.MCPORTER_VAULT_BACKEND;
  });

  afterEach(async () => {
    vi.clearAllMocks();
    vi.unstubAllGlobals();
    keyringMocks.store.clear();
    process.env = { ...originalEnv };
    if (hasPlatformSpy) {
      platformSpy.mockRestore();
      hasPlatformSpy = false;
    }
    if (hasSpy) {
      homedirSpy.mockRestore();
      hasSpy = false;
    }
    await Promise.all(tempRoots.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })));
  });

  it('stores the shared vault in the macOS Keychain when requested', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'mcporter-oauth-keychain-'));
    tempRoots.push(tmp);
    homedirSpy = vi.spyOn(os, 'homedir').mockReturnValue(path.join(tmp, 'home'));
    platformSpy = vi.spyOn(process, 'platform', 'get').mockReturnValue('darwin');
    hasSpy = true;
    hasPlatformSpy = true;
    process.env.XDG_DATA_HOME = path.join(tmp, 'data');
    process.env.XDG_STATE_HOME = path.join(tmp, 'state');
    process.env.MCPORTER_CREDENTIAL_BACKEND = 'keychain';

    const definition = mkDef('keychain-service');
    const persistence = await buildOAuthPersistence(definition);
    await persistence.saveTokens({ access_token: 'keychain-token', token_type: 'Bearer' });

    expect(resolveOAuthVaultBackend()).toBe('keychain');
    expect(describeOAuthVault()).toMatch(/^mcporter\/oauth-vault-[0-9a-f]{16} \(macOS Keychain\)$/);
    await expect(persistence.readTokens()).resolves.toEqual({ access_token: 'keychain-token', token_type: 'Bearer' });
    await expect(loadVaultEntry(definition)).resolves.toMatchObject({
      tokens: { access_token: 'keychain-token', token_type: 'Bearer' },
    });
    await expect(fs.access(path.join(tmp, 'data', 'mcporter', 'credentials.json'))).rejects.toThrow();
    const stored = [...keyringMocks.store.entries()][0];
    expect(stored).toBeDefined();
    const [storedKey, storedValue] = stored ?? ['', ''];
    expect(storedKey).toMatch(/^mcporter:oauth-vault-[0-9a-f]{16}$/);
    expect(storedValue).toContain('keychain-token');
    expect(JSON.parse(storedValue)).toMatchObject({ version: 2 });
  });

  it('uses the data-root keychain namespace even when XDG_STATE_HOME changes', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'mcporter-oauth-keychain-namespace-'));
    tempRoots.push(tmp);
    homedirSpy = vi.spyOn(os, 'homedir').mockReturnValue(path.join(tmp, 'home'));
    platformSpy = vi.spyOn(process, 'platform', 'get').mockReturnValue('darwin');
    hasSpy = true;
    hasPlatformSpy = true;
    process.env.XDG_DATA_HOME = path.join(tmp, 'data');
    process.env.MCPORTER_CREDENTIAL_BACKEND = 'keychain';

    process.env.XDG_STATE_HOME = path.join(tmp, 'state-a');
    await saveVaultEntry(mkDef('keychain-state-a'), {
      tokens: { access_token: 'state-a-token', token_type: 'Bearer' },
    });
    const [keyAfterFirstWrite] = keyringMocks.store.keys();

    process.env.XDG_STATE_HOME = path.join(tmp, 'state-b');
    await saveVaultEntry(mkDef('keychain-state-b'), {
      tokens: { access_token: 'state-b-token', token_type: 'Bearer' },
    });

    expect([...keyringMocks.store.keys()]).toEqual([keyAfterFirstWrite]);
    const storedVault = keyringMocks.store.get(keyAfterFirstWrite ?? '');
    expect(storedVault).toBeDefined();
    expect(storedVault).toContain('state-a-token');
    expect(storedVault).toContain('state-b-token');
    await expect(fs.access(path.join(tmp, 'state-a'))).rejects.toThrow();
    await expect(fs.access(path.join(tmp, 'state-b'))).rejects.toThrow();
  });

  it('clears shared vault entries from the macOS Keychain backend', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'mcporter-oauth-keychain-clear-'));
    tempRoots.push(tmp);
    homedirSpy = vi.spyOn(os, 'homedir').mockReturnValue(path.join(tmp, 'home'));
    platformSpy = vi.spyOn(process, 'platform', 'get').mockReturnValue('darwin');
    hasSpy = true;
    hasPlatformSpy = true;
    process.env.MCPORTER_CREDENTIAL_BACKEND = 'keychain';

    const definition = mkDef('keychain-clear-service');
    await saveVaultEntry(definition, { tokens: { access_token: 'keychain-token', token_type: 'Bearer' } });
    await clearVaultEntry(definition, 'all');

    await expect(loadVaultEntry(definition)).resolves.toBeUndefined();
    expect([...keyringMocks.store.values()].join('\n')).not.toContain('keychain-token');
  });

  it('propagates unexpected macOS Keychain read errors instead of treating them as a missing entry', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'mcporter-oauth-keychain-error-'));
    tempRoots.push(tmp);
    homedirSpy = vi.spyOn(os, 'homedir').mockReturnValue(path.join(tmp, 'home'));
    platformSpy = vi.spyOn(process, 'platform', 'get').mockReturnValue('darwin');
    hasSpy = true;
    hasPlatformSpy = true;
    process.env.MCPORTER_CREDENTIAL_BACKEND = 'keychain';
    keyringMocks.getPasswordError = new Error('the keychain is locked');

    await expect(loadVaultEntry(mkDef('keychain-error'))).rejects.toThrow(/Failed to read the mcporter OAuth vault/);
  });

  it('refuses the keychain backend on non-macOS platforms', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'mcporter-oauth-keychain-platform-'));
    tempRoots.push(tmp);
    homedirSpy = vi.spyOn(os, 'homedir').mockReturnValue(path.join(tmp, 'home'));
    platformSpy = vi.spyOn(process, 'platform', 'get').mockReturnValue('linux');
    hasSpy = true;
    hasPlatformSpy = true;
    process.env.MCPORTER_CREDENTIAL_BACKEND = 'keychain';

    await expect(
      saveVaultEntry(mkDef('keychain-linux'), { tokens: { access_token: 'nope', token_type: 'Bearer' } })
    ).rejects.toThrow(/macOS/);
  });

  it('resolves backend aliases using the first non-empty value', () => {
    expect(resolveOAuthVaultBackend({ MCPORTER_OAUTH_VAULT_BACKEND: 'keychain' })).toBe('keychain');
    expect(resolveOAuthVaultBackend({ MCPORTER_VAULT_BACKEND: 'KEYCHAIN' })).toBe('keychain');
    expect(
      resolveOAuthVaultBackend({ MCPORTER_CREDENTIAL_BACKEND: ' ', MCPORTER_OAUTH_VAULT_BACKEND: 'keychain' })
    ).toBe('keychain');
    expect(
      resolveOAuthVaultBackend({ MCPORTER_CREDENTIAL_BACKEND: 'file', MCPORTER_OAUTH_VAULT_BACKEND: 'keychain' })
    ).toBe('file');
  });

  it('rejects unsupported shared vault credential backends', () => {
    process.env.MCPORTER_CREDENTIAL_BACKEND = 'unsupported';

    expect(() => resolveOAuthVaultBackend()).toThrow("Unsupported mcporter credential backend 'unsupported'");
  });
});
