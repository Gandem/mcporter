import crypto from 'node:crypto';
import path from 'node:path';
import type { OAuthClientInformationMixed, OAuthDiscoveryState, OAuthTokens } from '@modelcontextprotocol/client';
import type { ServerDefinition } from './config.js';
import { readJsonFile, withFileLock, writeJsonFile } from './fs-json.js';
import { isStoredOAuthClientInformation, isStoredOAuthTokens } from './oauth-credential-validation.js';
import {
  sameOAuthClientGeneration,
  sameOAuthClientValue,
  sameOAuthTokenGeneration,
  sameOAuthTokenValue,
  withHiddenOAuthClientGeneration,
  withHiddenOAuthTokenGeneration,
  withOAuthClientGeneration,
  withOAuthTokenGeneration,
} from './oauth-token-generation.js';
import { mcporterDir } from './paths.js';

type VaultKey = string;
type VaultBackend = 'file' | 'keychain';

const KEYCHAIN_SERVICE = 'mcporter';
const KEYCHAIN_ACCOUNT_PREFIX = 'oauth-vault';
const KEYCHAIN_NAMESPACE_HASH_LENGTH = 16;
const KEYRING_PACKAGE = '@napi-rs/keyring';

interface KeyringEntry {
  getPassword(): string | null;
  setPassword(password: string): void;
}

interface KeyringModule {
  Entry: new (service: string, account: string) => KeyringEntry;
}

export interface VaultEntry {
  serverName: string;
  serverUrl?: string;
  tokens?: OAuthTokens;
  clientInfo?: OAuthClientInformationMixed;
  codeVerifier?: string;
  state?: string;
  discoveryState?: OAuthDiscoveryState;
  authorizationServerUrl?: string;
  resourceUrl?: string;
  updatedAt: string;
}

interface VaultFile {
  version: 1 | 2;
  entries: Record<VaultKey, VaultEntry>;
  serverUrls?: Record<string, string>;
}

interface VaultReadState {
  vault: VaultFile;
  needsRepair: boolean;
}

export interface VaultRecoveryRead {
  entry: VaultEntry | undefined;
  tokenSnapshots: ReadonlyMap<string, OAuthTokens>;
  clientSnapshots: ReadonlyMap<string, OAuthClientInformationMixed>;
}

interface SameUrlCredentials {
  tokens?: OAuthTokens;
  clientInfo?: OAuthClientInformationMixed;
  sourceKeys: VaultKey[];
}

export function getOAuthVaultPath(): string {
  return path.join(mcporterDir('data'), 'credentials.json');
}

const CREDENTIAL_BACKEND_ENV_VARS = [
  'MCPORTER_CREDENTIAL_BACKEND',
  'MCPORTER_OAUTH_VAULT_BACKEND',
  'MCPORTER_VAULT_BACKEND',
] as const;

function requestedBackendValue(env: NodeJS.ProcessEnv): string | undefined {
  return CREDENTIAL_BACKEND_ENV_VARS.map((name) => env[name]).find(
    (value): value is string => typeof value === 'string' && value.trim().length > 0
  );
}

export function resolveOAuthVaultBackend(env: NodeJS.ProcessEnv = process.env): VaultBackend {
  const raw = requestedBackendValue(env);
  if (!raw) {
    return 'file';
  }
  const normalized = raw.trim().toLowerCase();
  if (normalized === 'file' || normalized === 'keychain') {
    return normalized;
  }
  throw new Error(`Unsupported mcporter credential backend '${raw}'. Expected 'file' or 'keychain'.`);
}

/**
 * Generated CLIs cannot bundle the native keychain module, so they always use the file vault.
 * Call this once at startup, before any vault operation runs, to neutralize a requested keychain
 * backend (warning if one was requested). Backend resolution is lazy, so setting the env here
 * is sufficient.
 */
export function forceFileVaultBackend(env: NodeJS.ProcessEnv = process.env): void {
  const requested = requestedBackendValue(env);
  if (requested && requested.trim().toLowerCase() === 'keychain') {
    console.error(
      'mcporter: the keychain credential backend is not available in generated CLIs; using the file vault instead.'
    );
  }
  env.MCPORTER_CREDENTIAL_BACKEND = 'file';
  delete env.MCPORTER_OAUTH_VAULT_BACKEND;
  delete env.MCPORTER_VAULT_BACKEND;
}

export function describeOAuthVault(): string {
  if (resolveOAuthVaultBackend() === 'keychain') {
    return `${KEYCHAIN_SERVICE}/${keychainAccount()} (macOS Keychain)`;
  }
  return `${getOAuthVaultPath()} (vault)`;
}

function getOAuthVaultLockTargetPath(): string {
  if (resolveOAuthVaultBackend() === 'keychain') {
    return path.join(path.dirname(getOAuthVaultPath()), 'locks', keychainAccount());
  }
  return getOAuthVaultPath();
}

async function readVaultState(): Promise<VaultReadState> {
  try {
    const existing = await readStoredVault();
    if (isVaultFile(existing)) {
      return {
        vault: { ...existing, version: 2 },
        needsRepair: existing.version !== 2,
      };
    }
    if (existing !== undefined) {
      return { vault: emptyVault(), needsRepair: true };
    }
  } catch (error) {
    if (!(error instanceof SyntaxError)) {
      throw error;
    }
    return { vault: emptyVault(), needsRepair: true };
  }
  return { vault: emptyVault(), needsRepair: false };
}

async function readVault(): Promise<VaultFile> {
  return (await readVaultState()).vault;
}

function emptyVault(): VaultFile {
  return { version: 2, entries: {} };
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function isVaultFile(value: unknown): value is VaultFile {
  return isPlainRecord(value) && (value.version === 1 || value.version === 2) && isPlainRecord(value.entries);
}

async function readStoredVault(): Promise<unknown> {
  if (resolveOAuthVaultBackend() === 'keychain') {
    const raw = await readKeychainVault();
    return raw === undefined ? undefined : JSON.parse(raw);
  }
  return readJsonFile(getOAuthVaultPath());
}

async function writeVault(contents: VaultFile): Promise<void> {
  if (resolveOAuthVaultBackend() === 'keychain') {
    await writeKeychainVault(JSON.stringify(contents, null, 2));
    return;
  }
  await writeJsonFile(getOAuthVaultPath(), contents);
}

function keychainAccount(): string {
  const namespace = crypto
    .createHash('sha256')
    .update(getOAuthVaultPath())
    .digest('hex')
    .slice(0, KEYCHAIN_NAMESPACE_HASH_LENGTH);
  return `${KEYCHAIN_ACCOUNT_PREFIX}-${namespace}`;
}

function assertMacOSKeychainBackend(): void {
  if (process.platform !== 'darwin') {
    throw new Error(
      `Keychain credential backend currently supports macOS only. Set MCPORTER_CREDENTIAL_BACKEND=file to use the file vault on ${process.platform}.`
    );
  }
}

let keyringModulePromise: Promise<KeyringModule> | undefined;

async function loadKeyring(): Promise<KeyringModule> {
  if (keyringModulePromise === undefined) {
    keyringModulePromise = (async () => {
      try {
        return (await import('@napi-rs/keyring')) as unknown as KeyringModule;
      } catch (error) {
        keyringModulePromise = undefined;
        throw new Error(
          `The keychain credential backend requires the optional '${KEYRING_PACKAGE}' native module, which could not be loaded. Reinstall mcporter so its prebuilt binary is available, or set MCPORTER_CREDENTIAL_BACKEND=file.`,
          { cause: error }
        );
      }
    })();
  }
  return keyringModulePromise;
}

function keychainEntry(EntryCtor: KeyringModule['Entry']): KeyringEntry {
  return new EntryCtor(KEYCHAIN_SERVICE, keychainAccount());
}

async function readKeychainVault(): Promise<string | undefined> {
  assertMacOSKeychainBackend();
  const { Entry } = await loadKeyring();
  let stored: string | null;
  try {
    stored = keychainEntry(Entry).getPassword();
  } catch (error) {
    throw new Error('Failed to read the mcporter OAuth vault from the macOS Keychain.', { cause: error });
  }
  if (!stored) {
    return undefined;
  }
  return stored;
}

async function writeKeychainVault(value: string): Promise<void> {
  assertMacOSKeychainBackend();
  const { Entry } = await loadKeyring();
  try {
    keychainEntry(Entry).setPassword(value);
  } catch (error) {
    throw new Error('Failed to write the mcporter OAuth vault to the macOS Keychain.', { cause: error });
  }
}

export function vaultKeyForDefinition(definition: ServerDefinition): VaultKey {
  const descriptor = {
    name: definition.name,
    url: definition.command.kind === 'http' ? definition.command.url.toString() : null,
    command:
      definition.command.kind === 'stdio'
        ? { command: definition.command.command, args: definition.command.args ?? [] }
        : null,
  };
  const digest = crypto.hash('sha256', JSON.stringify(descriptor), 'hex').slice(0, 16);
  return `${definition.name}|${digest}`;
}

// A configured name is the user's stable identity for an MCP server. Its URL
// is therefore a trust boundary: changing it must retire every credential that
// could otherwise become reachable again if the URL is later reverted.
export async function reconcileVaultServerUrl(definition: ServerDefinition): Promise<void> {
  if (definition.command.kind !== 'http') {
    return;
  }
  const serverUrl = definition.command.url.toString();
  await withFileLock(getOAuthVaultLockTargetPath(), async () => {
    const { vault, needsRepair } = await readVaultState();
    const serverUrls = stringRecord(vault.serverUrls);
    const previousUrl = serverUrls[definition.name];
    const namedEntryUrls = Object.values(vault.entries)
      .filter((entry) => isVaultEntry(entry) && entry.serverName === definition.name)
      .flatMap((entry) => (typeof entry.serverUrl === 'string' ? [entry.serverUrl] : []));
    const urlChanged =
      (previousUrl !== undefined && previousUrl !== serverUrl) || namedEntryUrls.some((url) => url !== serverUrl);

    if (urlChanged) {
      const invalidatedUrls = new Set([serverUrl, previousUrl, ...namedEntryUrls].filter((url) => url !== undefined));
      for (const [key, entry] of Object.entries(vault.entries)) {
        if (
          isVaultEntry(entry) &&
          (entry.serverName === definition.name ||
            (isLegacyOAuthRenameCandidate(definition, entry) &&
              entry.serverUrl !== undefined &&
              invalidatedUrls.has(entry.serverUrl)))
        ) {
          delete vault.entries[key];
        }
      }
    }

    if (previousUrl === serverUrl && !urlChanged && !needsRepair) {
      return;
    }
    vault.serverUrls = { ...serverUrls, [definition.name]: serverUrl };
    await writeVault(vault);
  });
}

function stringRecord(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }
  return Object.fromEntries(
    Object.entries(value).filter((entry): entry is [string, string] => typeof entry[1] === 'string')
  );
}

/**
 * Every vault key whose credentials this definition can end up using: its own,
 * plus any same-URL legacy `<name>-oauth` entry it inherits from.
 *
 * Refresh locking needs the whole set. A renamed definition and its legacy entry
 * resolve to one shared refresh token (see resolveVaultEntry), so locking only
 * the exact key would let them redeem that token concurrently and lose the
 * family. Deliberately the broader rename-candidate set rather than the entry
 * that inheritance would pick right now: over-locking costs a little
 * serialization, under-locking costs the credential.
 */
export async function vaultCredentialKeys(definition: ServerDefinition): Promise<VaultKey[]> {
  const key = vaultKeyForDefinition(definition);
  if (definition.command.kind !== 'http') {
    return [key];
  }
  const vault = await readVault();
  return [...new Set([key, ...legacyOAuthRenameKeys(vault, definition, key)])];
}

export async function loadVaultEntry(definition: ServerDefinition): Promise<VaultEntry | undefined> {
  const vault = await readVault();
  return externalVaultEntry(resolveVaultEntry(vault, definition));
}

export async function loadVaultEntryForRecovery(definition: ServerDefinition): Promise<VaultRecoveryRead> {
  const vault = await readVault();
  const key = vaultKeyForDefinition(definition);
  const resolved = resolveVaultEntry(vault, definition);
  const tokenSnapshots = new Map<string, OAuthTokens>();
  const clientSnapshots = new Map<string, OAuthClientInformationMixed>();

  // Snapshot only the effective rejected values and exact public-value
  // duplicates. Unrelated same-URL registrations survive, while a duplicate
  // cannot become the next fallback and replay credentials already rejected.
  for (const targetKey of [key, ...legacyOAuthRenameKeys(vault, definition, key)]) {
    const candidate = isVaultEntry(vault.entries[targetKey]) ? vault.entries[targetKey] : undefined;
    if (candidate?.tokens && resolved?.tokens && sameOAuthTokenValue(candidate.tokens, resolved.tokens)) {
      tokenSnapshots.set(targetKey, candidate.tokens);
    }
    if (
      candidate?.clientInfo &&
      resolved?.clientInfo &&
      sameOAuthClientValue(candidate.clientInfo, resolved.clientInfo)
    ) {
      clientSnapshots.set(targetKey, candidate.clientInfo);
    }
  }
  return {
    entry: externalVaultEntry(resolved),
    tokenSnapshots,
    clientSnapshots,
  };
}

function resolveVaultEntry(vault: VaultFile, definition: ServerDefinition): VaultEntry | undefined {
  const key = vaultKeyForDefinition(definition);
  const exact = isVaultEntry(vault.entries[key]) ? vault.entries[key] : undefined;
  const fallback = findSameUrlCredentials(vault, definition, key, exact);
  if (!fallback.tokens && !fallback.clientInfo) {
    return exact;
  }
  if (!exact) {
    return {
      serverName: definition.name,
      serverUrl: definition.command.kind === 'http' ? definition.command.url.toString() : undefined,
      updatedAt: new Date().toISOString(),
      tokens: fallback.tokens,
      clientInfo: fallback.clientInfo,
    };
  }
  return {
    ...exact,
    tokens: exact.tokens ?? fallback.tokens,
    clientInfo: exact.clientInfo ?? (exact.tokens ? undefined : fallback.clientInfo),
  };
}

function externalVaultEntry(entry: VaultEntry | undefined): VaultEntry | undefined {
  if (!entry) {
    return entry;
  }
  const { tokens, clientInfo, ...metadata } = entry;
  return {
    ...metadata,
    ...(isStoredOAuthTokens(tokens) ? { tokens: withHiddenOAuthTokenGeneration(tokens) } : {}),
    ...(isStoredOAuthClientInformation(clientInfo) ? { clientInfo: withHiddenOAuthClientGeneration(clientInfo) } : {}),
  };
}

function findSameUrlCredentials(
  vault: VaultFile,
  definition: ServerDefinition,
  exactKey: VaultKey,
  exact: VaultEntry | undefined
): SameUrlCredentials {
  if (definition.command.kind !== 'http') {
    return { sourceKeys: [] };
  }
  const serverUrl = definition.command.url.toString();
  const candidates = Object.entries(vault.entries)
    .filter(
      ([key, entry]) =>
        key !== exactKey &&
        isVaultEntry(entry) &&
        entry.serverUrl === serverUrl &&
        isLegacyOAuthRenameCandidate(definition, entry) &&
        (entry.tokens || entry.clientInfo)
    )
    .map(([key, entry]) => ({ key, entry }))
    .toSorted((a, b) => Date.parse(b.entry.updatedAt) - Date.parse(a.entry.updatedAt));
  const requiredClientId = definition.oauthClientId ?? clientIdFromEntry(exact);
  if (requiredClientId) {
    const tokenSource = candidates.find(
      ({ entry }) => (entry.tokens || entry.clientInfo) && clientIdFromEntry(entry) === requiredClientId
    );
    return {
      tokens: tokenSource?.entry.tokens,
      clientInfo: exact?.clientInfo ? undefined : tokenSource?.entry.clientInfo,
      sourceKeys: tokenSource ? [tokenSource.key] : [],
    };
  }

  const source = candidates.find(({ entry }) => entry.clientInfo && clientIdFromEntry(entry));
  return {
    tokens: source?.entry.tokens,
    clientInfo: source?.entry.clientInfo,
    sourceKeys: source ? [source.key] : [],
  };
}

function isLegacyOAuthRenameCandidate(definition: ServerDefinition, entry: VaultEntry): boolean {
  return entry.serverName === `${definition.name}-oauth`;
}

function legacyOAuthRenameKeys(vault: VaultFile, definition: ServerDefinition, exactKey: VaultKey): VaultKey[] {
  if (definition.command.kind !== 'http') {
    return [];
  }
  const serverUrl = definition.command.url.toString();
  return Object.entries(vault.entries)
    .filter(
      ([key, entry]) =>
        key !== exactKey &&
        isVaultEntry(entry) &&
        entry.serverUrl === serverUrl &&
        isLegacyOAuthRenameCandidate(definition, entry)
    )
    .map(([key]) => key);
}

function isVaultEntry(entry: unknown): entry is VaultEntry {
  return Boolean(
    entry &&
    typeof entry === 'object' &&
    typeof (entry as VaultEntry).serverName === 'string' &&
    typeof (entry as VaultEntry).updatedAt === 'string'
  );
}

function clientIdFromEntry(entry: VaultEntry | undefined): string | undefined {
  const clientId = entry?.clientInfo?.client_id;
  return typeof clientId === 'string' && clientId.length > 0 ? clientId : undefined;
}

export async function saveVaultEntry(definition: ServerDefinition, patch: Partial<VaultEntry>): Promise<void> {
  await withFileLock(getOAuthVaultLockTargetPath(), async () => {
    const vault = await readVault();
    const key = vaultKeyForDefinition(definition);
    const existing = isVaultEntry(vault.entries[key]) ? vault.entries[key] : undefined;
    const fallback = findSameUrlCredentials(vault, definition, key, existing);
    const current = existing ?? {
      serverName: definition.name,
      serverUrl: definition.command.kind === 'http' ? definition.command.url.toString() : undefined,
      updatedAt: new Date().toISOString(),
    };
    vault.entries[key] = {
      ...current,
      ...patch,
      ...(patch.tokens ? { tokens: withOAuthTokenGeneration(patch.tokens) } : {}),
      clientInfo:
        (patch.clientInfo ? withOAuthClientGeneration(patch.clientInfo) : undefined) ??
        current.clientInfo ??
        (patch.tokens && !current.tokens ? fallback.clientInfo : undefined),
      updatedAt: new Date().toISOString(),
    };
    await writeVault(vault);
  });
}

function tokensMatch(tokens: OAuthTokens | undefined, expected: OAuthTokens | undefined): boolean {
  return expected !== undefined && sameOAuthTokenGeneration(tokens, expected);
}

// Atomically clears the rejected token and, when supplied, only the dynamic
// client registration that refresh used. A concurrent refresh generation or
// interactive auth registration is left untouched under the vault write lock.
//
// readTokens() sources tokens from the exact entry, or — when the exact entry
// has none — inherits them from a same-URL legacy rename entry (see
// loadVaultEntry). Both are compare-and-cleared so a rejected refresh token can
// never be reread and replayed from the inherited source. State and verifier
// values are intentionally outside refresh recovery.
export async function clearVaultTokensIfMatching(
  definition: ServerDefinition,
  expectedTokens?: OAuthTokens,
  expectedClientInfo?: OAuthClientInformationMixed,
  tokenSnapshots?: ReadonlyMap<string, OAuthTokens>,
  clientSnapshots?: ReadonlyMap<string, OAuthClientInformationMixed>
): Promise<void> {
  const key = vaultKeyForDefinition(definition);
  await withFileLock(getOAuthVaultLockTargetPath(), async () => {
    const { vault, needsRepair } = await readVaultState();
    const exact = isVaultEntry(vault.entries[key]) ? vault.entries[key] : undefined;
    const fallbackKeys = findSameUrlCredentials(vault, definition, key, exact).sourceKeys;
    const targetKeys =
      tokenSnapshots || clientSnapshots
        ? [...new Set([...(tokenSnapshots?.keys() ?? []), ...(clientSnapshots?.keys() ?? [])])]
        : [key, ...fallbackKeys];
    let mutated = false;
    for (const targetKey of targetKeys) {
      const entry = isVaultEntry(vault.entries[targetKey]) ? vault.entries[targetKey] : undefined;
      if (!entry) {
        continue;
      }
      const updated: VaultEntry = { ...entry };
      let entryMutated = false;
      const tokenSnapshot = tokenSnapshots ? tokenSnapshots.get(targetKey) : expectedTokens;
      const clientSnapshot = clientSnapshots ? clientSnapshots.get(targetKey) : expectedClientInfo;
      const ownTokensRejected = tokensMatch(entry.tokens, tokenSnapshot);
      if (ownTokensRejected) {
        delete updated.tokens;
        entryMutated = true;
      }
      if (clientSnapshot && sameOAuthClientGeneration(updated.clientInfo, clientSnapshot)) {
        delete updated.clientInfo;
        entryMutated = true;
      }
      if (!entryMutated) {
        continue;
      }
      updated.updatedAt = new Date().toISOString();
      vault.entries[targetKey] = updated;
      mutated = true;
    }
    if (mutated || needsRepair) {
      await writeVault(vault);
    }
  });
}

export async function clearVaultEntry(
  definition: ServerDefinition,
  scope: 'all' | 'tokens' | 'client' | 'verifier' | 'state' | 'discovery'
): Promise<void> {
  const key = vaultKeyForDefinition(definition);
  await withFileLock(getOAuthVaultLockTargetPath(), async () => {
    const { vault, needsRepair } = await readVaultState();
    const existing = isVaultEntry(vault.entries[key]) ? vault.entries[key] : undefined;
    const fallback = findSameUrlCredentials(vault, definition, key, existing);
    const inheritedKeys = scope === 'all' ? legacyOAuthRenameKeys(vault, definition, key) : fallback.sourceKeys;
    if (!existing && inheritedKeys.length === 0) {
      if (needsRepair) {
        await writeVault(vault);
      }
      return;
    }
    if (scope === 'all') {
      delete vault.entries[key];
    } else if (existing) {
      const updated: VaultEntry = { ...existing };
      if (scope === 'tokens') {
        delete updated.tokens;
      }
      if (scope === 'client') {
        delete updated.clientInfo;
      }
      if (scope === 'verifier') {
        delete updated.codeVerifier;
      }
      if (scope === 'state') {
        delete updated.state;
      }
      if (scope === 'discovery') {
        delete updated.discoveryState;
        delete updated.authorizationServerUrl;
        delete updated.resourceUrl;
      }
      updated.updatedAt = new Date().toISOString();
      vault.entries[key] = updated;
    }
    for (const fallbackKey of inheritedKeys) {
      const inherited = vault.entries[fallbackKey];
      if (!inherited) {
        continue;
      }
      if (scope === 'all') {
        delete vault.entries[fallbackKey];
        continue;
      }
      const updated: VaultEntry = { ...inherited };
      if (scope === 'tokens') {
        delete updated.tokens;
      }
      if (scope === 'client') {
        delete updated.clientInfo;
      }
      updated.updatedAt = new Date().toISOString();
      vault.entries[fallbackKey] = updated;
    }
    await writeVault(vault);
  });
}
