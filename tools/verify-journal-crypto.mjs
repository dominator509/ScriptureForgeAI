import { Buffer } from 'node:buffer';
import { webcrypto } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const mobileRoot = path.join(repoRoot, 'mobile');
const cryptoSourcePath = path.join(mobileRoot, 'src', 'lib', 'crypto.ts');
const webJournalEditorPath = path.join(repoRoot, 'web', 'src', 'components', 'JournalEditor.tsx');
const webAPIPath = path.join(repoRoot, 'web', 'src', 'lib', 'api.ts');
const webCryptoSmokePath = path.join(repoRoot, 'web', 'src', 'lib', 'crypto.smoke.mts');
const mobileJournalContainerPath = path.join(mobileRoot, 'src', 'components', 'SecureJournalContainer.tsx');
const mobileAPIPath = path.join(mobileRoot, 'src', 'lib', 'api.ts');
const mobileCryptoSmokePath = path.join(mobileRoot, 'src', 'lib', 'crypto.smoke.mts');
const mobileRequire = createRequire(path.join(mobileRoot, 'package.json'));
const packageRequirePaths = [
  path.join(mobileRoot, 'package.json'),
  path.join(repoRoot, 'web', 'package.json'),
  path.join(repoRoot, 'package.json'),
];

function loadTypeScript() {
  const resolutionErrors = [];
  for (const packageJsonPath of packageRequirePaths) {
    try {
      return createRequire(packageJsonPath)('typescript');
    } catch (error) {
      if (error?.code !== 'MODULE_NOT_FOUND') {
        throw error;
      }
      resolutionErrors.push(`${path.relative(repoRoot, packageJsonPath)}: ${error.message}`);
    }
  }
  throw new Error(`typescript is required to verify journal crypto; install web or mobile dependencies first. ${resolutionErrors.join(' | ')}`);
}

const ts = loadTypeScript();

export const journalCryptoProofMarkers = [
  'native_quick_crypto=true',
  'native_provider_bound_keys=true',
  'native_provider_harness=true',
  'native_required_fail_closed=true',
  'mobile_staging_native_required=true',
  'pbkdf2_600000=true',
  'blank_key_input_rejected=true',
  'aes_gcm_roundtrip=true',
  'unique_iv=true',
  'tamper_rejected=true',
  'associated_data_rejected=true',
  'associated_data_input_guard=true',
  'associated_data_salt_binding=true',
  'non_extractable_key=true',
  'key_disposed=true',
  'key_disposal=true',
  'revoked_key_rejected=true',
  'web_key_disposal=true',
  'buffer_zeroization=true',
  'runtime_buffer_zeroization=true',
  'import_failure_zeroization=true',
  'web_import_failure_zeroization=true',
  'base64_decode_buffer_zeroization=true',
  'mobile_passphrase_derivation_failure_cleanup=true',
  'native_device_self_test_export=true',
  'native_device_self_test_markers=true',
  'native_required_self_test_fail_closed=true',
  'backend_bootstrap_salts=true',
  'web_crypto_smoke=true',
  'mobile_crypto_smoke=true',
];

const verifierSource = fs.readFileSync(fileURLToPath(import.meta.url), 'utf8');
const source = fs.readFileSync(cryptoSourcePath, 'utf8');
const webCryptoSource = fs.readFileSync(path.join(repoRoot, 'web', 'src', 'lib', 'crypto.ts'), 'utf8');
const webAPISource = fs.readFileSync(webAPIPath, 'utf8');
const mobileAPISource = fs.readFileSync(mobileAPIPath, 'utf8');
const webCryptoSmokeSource = fs.readFileSync(webCryptoSmokePath, 'utf8');
const mobileCryptoSmokeSource = fs.readFileSync(mobileCryptoSmokePath, 'utf8');
const clientJournalSources = [
  [webJournalEditorPath, fs.readFileSync(webJournalEditorPath, 'utf8')],
  [mobileJournalContainerPath, fs.readFileSync(mobileJournalContainerPath, 'utf8')],
];
const forbiddenPatterns = [
  /Buffer\.from\(plaintext\)\.toString\(['"]base64['"]\)/,
  /from ['"]expo-crypto['"]/,
  /from ['"]expo-random['"]/,
  /require\(['"]expo-crypto['"]\)/,
  /require\(['"]expo-random['"]\)/,
  /Crypto\.digestStringAsync/,
  /ExpoCrypto/,
  /pseudoCipher/,
  /securely mocks/i,
  /do not deploy/i,
];

for (const pattern of forbiddenPatterns) {
  if (pattern.test(source)) {
    throw new Error(`mobile journal crypto still contains forbidden placeholder pattern: ${pattern}`);
  }
}

for (const [clientPath, clientSource] of clientJournalSources) {
  if (/journal:\$\{[^}]+}:v1/.test(clientSource) || /journal:[^'"]+:v1/.test(clientSource)) {
    throw new Error(`${path.relative(repoRoot, clientPath)} must use authenticated backend journal bootstrap salt material`);
  }
  if (!clientSource.includes('getJournalBootstrap')) {
    throw new Error(`${path.relative(repoRoot, clientPath)} must fetch journal bootstrap salt material from the backend`);
  }
}

const webJournalSource = fs.readFileSync(webJournalEditorPath, 'utf8');
const mobileJournalSource = fs.readFileSync(mobileJournalContainerPath, 'utf8');
for (const requiredWebLifecycleSnippet of [
  'Plaintext never leaves this component',
  'disposeJournalCryptoKey(previous);',
  'disposeJournalCryptoKey(derivedHandle);',
  'setKeyHandle((previous) =>',
  "setPlaintext('');",
]) {
  if (!webJournalSource.includes(requiredWebLifecycleSnippet)) {
    throw new Error(`web journal editor missing lifecycle control: ${requiredWebLifecycleSnippet}`);
  }
}

for (const requiredMobileLifecycleSnippet of [
  "setPlaintext('');",
  "setPassphrase('');",
  'preserveDerivedHandleOnPassphraseClear',
  'disposeJournalCryptoKey(previous);',
  'disposeJournalCryptoKey(derivedHandle);',
  'setStatus(error.message);',
]) {
  if (!mobileJournalSource.includes(requiredMobileLifecycleSnippet)) {
    throw new Error(`mobile journal container missing lifecycle control: ${requiredMobileLifecycleSnippet}`);
  }
}

const mobileDerivationFailureCleanupPattern = /\.catch\(\(error: Error\) => \{[\s\S]*?setKeyHandle\(previous => \{[\s\S]*?disposeJournalCryptoKey\(previous\);[\s\S]*?return null;[\s\S]*?\}\);[\s\S]*?setPassphrase\(''\);[\s\S]*?setStatus\(error\.message\);[\s\S]*?\}\);/;
if (!mobileDerivationFailureCleanupPattern.test(mobileJournalSource)) {
  throw new Error('mobile journal container must clear passphrase state when key derivation fails');
}

for (const requiredLifecycleSnippet of [
  'function wipeBytes',
  'bytes.fill(0)',
  'finally',
  'wipeBytes(passphraseBytes)',
  'wipeBytes(saltBytes)',
  'wipeBytes(plaintextBytes)',
  'wipeBytes(ciphertextBytes)',
  'wipeBytes(ivBytes)',
  'wipeBytes(bytes)',
  'const keyMaterial = await provider.subtle.importKey',
  'createJournalCryptoKeyHandle',
  'disposeJournalCryptoKey',
  'revokedJournalKeys',
  'Journal crypto key has been disposed',
  'Journal crypto key was not derived by client-side journal key derivation',
  'runJournalCryptoSelfTest',
]) {
  if (!source.includes(requiredLifecycleSnippet)) {
    throw new Error(`mobile journal crypto missing lifecycle control: ${requiredLifecycleSnippet}`);
  }
}

const deriveFunctionMatch = source.match(/export async function deriveIsolationKey[\s\S]*?\r?\n}\r?\n/);
if (!deriveFunctionMatch) {
  throw new Error('mobile journal crypto missing deriveIsolationKey implementation');
}
const deriveFunction = deriveFunctionMatch[0];
if (
  deriveFunction.indexOf('try {') === -1 ||
  deriveFunction.indexOf('const keyMaterial = await provider.subtle.importKey') < deriveFunction.indexOf('try {') ||
  deriveFunction.indexOf('wipeBytes(passphraseBytes)') < deriveFunction.indexOf('const keyMaterial = await provider.subtle.importKey') ||
  deriveFunction.indexOf('wipeBytes(saltBytes)') < deriveFunction.indexOf('const keyMaterial = await provider.subtle.importKey')
) {
  throw new Error('mobile journal crypto must wipe passphrase and salt bytes even when importKey fails');
}

const webDeriveFunctionMatch = webCryptoSource.match(/export async function deriveIsolationKey[\s\S]*?\r?\n}\r?\n/);
if (!webDeriveFunctionMatch) {
  throw new Error('web journal crypto missing deriveIsolationKey implementation');
}
const webDeriveFunction = webDeriveFunctionMatch[0];
if (
  webDeriveFunction.indexOf('try {') === -1 ||
  webDeriveFunction.indexOf('const keyMaterial = await window.crypto.subtle.importKey') < webDeriveFunction.indexOf('try {') ||
  webDeriveFunction.indexOf('passphraseBytes.fill(0)') < webDeriveFunction.indexOf('const keyMaterial = await window.crypto.subtle.importKey') ||
  webDeriveFunction.indexOf('saltBytes.fill(0)') < webDeriveFunction.indexOf('const keyMaterial = await window.crypto.subtle.importKey')
) {
  throw new Error('web journal crypto must wipe passphrase and salt bytes even when importKey fails');
}

const base64ToBufferMatch = source.match(/function base64ToBuffer[\s\S]*?\n}\n/);
if (!base64ToBufferMatch) {
  throw new Error('mobile journal crypto missing base64ToBuffer implementation');
}
const base64ToBufferFunction = base64ToBufferMatch[0];
for (const requiredBase64CleanupSnippet of [
  'const copied = new Uint8Array(bytes.byteLength)',
  'copied.set(bytes)',
  'finally',
  'wipeBytes(bytes)',
]) {
  if (!base64ToBufferFunction.includes(requiredBase64CleanupSnippet)) {
    throw new Error(`mobile journal crypto base64 decoder missing cleanup marker: ${requiredBase64CleanupSnippet}`);
  }
}

for (const [clientName, clientCryptoSource] of [
  ['mobile', source],
  ['web', webCryptoSource],
]) {
  if (!clientCryptoSource.includes('JOURNAL_PBKDF2_ITERATIONS = 600000')) {
    throw new Error(`${clientName} journal crypto must use the architecture PBKDF2 work factor of 600000 iterations`);
  }
  if (!clientCryptoSource.includes('iterations: JOURNAL_PBKDF2_ITERATIONS')) {
    throw new Error(`${clientName} journal crypto must derive PBKDF2 keys through JOURNAL_PBKDF2_ITERATIONS`);
  }
  if (clientCryptoSource.includes('iterations: 210000') || clientCryptoSource.includes('210,000 iterations')) {
    throw new Error(`${clientName} journal crypto still contains the old 210000 PBKDF2 work factor`);
  }
  for (const requiredKeyInputSnippet of [
    'assertJournalKeyInputs',
    'Journal passphrase is required for client-side key derivation',
    'Journal server salt material is required for client-side key derivation',
  ]) {
    if (!clientCryptoSource.includes(requiredKeyInputSnippet)) {
      throw new Error(`${clientName} journal crypto missing key-derivation input guard: ${requiredKeyInputSnippet}`);
    }
  }
  for (const requiredAssociatedDataSnippet of [
    'journalAssociatedData',
    'scriptureforge-journal:v1:salt_id=',
    'additionalData',
    'Journal associated data requires a server salt identifier',
    'Journal associated data requires a positive integer salt version',
    'Number.isInteger(saltVersion)',
  ]) {
    if (!clientCryptoSource.includes(requiredAssociatedDataSnippet)) {
      throw new Error(`${clientName} journal crypto missing AES-GCM associated-data binding marker: ${requiredAssociatedDataSnippet}`);
    }
  }
}
for (const requiredWebKeyLifecycleSnippet of [
  'createJournalCryptoKeyHandle',
  'getJournalCryptoKey',
  'disposeJournalCryptoKey',
  'revokedJournalKeys',
  'Journal crypto key handle has been disposed',
  'Journal crypto key has been disposed',
  'Journal crypto key was not derived by client-side journal key derivation',
]) {
  if (!webCryptoSource.includes(requiredWebKeyLifecycleSnippet)) {
    throw new Error(`web journal crypto missing disposable key handle control: ${requiredWebKeyLifecycleSnippet}`);
  }
}

const packageJson = JSON.parse(fs.readFileSync(path.join(mobileRoot, 'package.json'), 'utf8'));
if (!packageJson.dependencies?.['react-native-quick-crypto']) {
  throw new Error('mobile package.json must declare react-native-quick-crypto for production AES-GCM builds');
}
if (!packageJson.scripts?.smoke?.includes('src/lib/crypto.smoke.mts')) {
  throw new Error('mobile npm smoke script must run src/lib/crypto.smoke.mts');
}
const webPackageJson = JSON.parse(fs.readFileSync(path.join(repoRoot, 'web', 'package.json'), 'utf8'));
if (!webPackageJson.scripts?.smoke?.includes('src/lib/crypto.smoke.mts')) {
  throw new Error('web npm smoke script must run src/lib/crypto.smoke.mts');
}
for (const requiredMobileCryptoSmokeSnippet of [
  'tampered ciphertext',
  'JOURNAL_PBKDF2_ITERATIONS, 600000',
  'journal key derivation rejects blank passphrase or server salt',
  'non-extractable',
  'disposed handles cannot encrypt',
  'disposing a handle must revoke stale raw key references',
  'journal encryption rejects keys not derived by the journal crypto module',
  'mobile_crypto_revoked_key_rejected=true',
  'local smoke reports WebCrypto fallback as non-production provider',
  'production native-required mode fails closed',
  'journal crypto self-test emits native-device evidence markers',
  'native-required self-test must fail closed when only WebCrypto fallback is available',
  'mobile_crypto_native_required_self_test_fail_closed=true',
  'mobile_crypto_unique_iv=true',
  'runJournalCryptoSelfTest',
  'required native provider',
  'wrong associated data must reject journal ciphertext',
  'journal associated data rejects missing salt identity',
  'mobile_crypto_associated_data_input_guard=true',
  'mobile crypto zeroizes provider input buffers after operations',
  'mobile_crypto_runtime_buffer_zeroization=true',
  'assertZeroized',
  'associated_data_salt_id=journal:self-test:server-derived-salt',
  'associated_data_salt_version=1',
  'AES-GCM IVs must be unique per encryption',
]) {
  if (!mobileCryptoSmokeSource.includes(requiredMobileCryptoSmokeSnippet)) {
    throw new Error(`mobile crypto smoke missing coverage marker: ${requiredMobileCryptoSmokeSnippet}`);
  }
}
for (const requiredWebCryptoSmokeSnippet of [
  'web journal AES-GCM round-trips and rejects tampered ciphertext',
  'wrong associated data must reject web journal ciphertext',
  'web_crypto_unique_iv=true',
  'AES-GCM IVs must be unique per encryption',
  'same web journal plaintext must not produce repeated ciphertext',
  'web journal associated data rejects missing salt identity',
  'web_crypto_associated_data_input_guard=true',
  'JOURNAL_PBKDF2_ITERATIONS, 600000',
  'web journal key derivation rejects blank passphrase or server salt',
  'web journal key derivation zeroizes passphrase when import fails',
  'web_crypto_import_failure_zeroization=true',
  'synthetic importKey failure',
  'non-extractable',
  'web journal key handles dispose active key references',
  'disposing a handle must revoke stale raw key references',
  'web journal encryption rejects keys not derived by the journal crypto module',
  'web_crypto_revoked_key_rejected=true',
  'disposed web journal plaintext',
]) {
  if (!webCryptoSmokeSource.includes(requiredWebCryptoSmokeSnippet)) {
    throw new Error(`web crypto smoke missing coverage marker: ${requiredWebCryptoSmokeSnippet}`);
  }
}
if (!source.includes('const nativeProvider = getQuickCrypto()') || !source.includes('const fallbackProvider = getGlobalCrypto()')) {
  throw new Error('mobile journal crypto must prefer the native react-native-quick-crypto provider before WebCrypto fallback');
}
for (const requiredProviderBindingSnippet of [
  'const keyProviders = new WeakMap',
  'keyProviders.set(key, selected)',
  'getCryptoProviderForKey(key)',
  'Journal crypto key was not derived by the required native provider',
  'getJournalCryptoProviderStatus',
]) {
  if (!source.includes(requiredProviderBindingSnippet)) {
    throw new Error(`mobile journal crypto missing provider binding marker: ${requiredProviderBindingSnippet}`);
  }
}
for (const requiredAssociatedDataSelfTestSnippet of [
  "const saltID = 'journal:self-test:server-derived-salt'",
  'const saltVersion = 1',
  'journalAssociatedData(saltID, saltVersion)',
  '`associated_data_salt_id=${saltID}`',
  '`associated_data_salt_version=${saltVersion}`',
]) {
  if (!source.includes(requiredAssociatedDataSelfTestSnippet)) {
    throw new Error(`mobile journal crypto self-test missing associated-data salt binding marker: ${requiredAssociatedDataSelfTestSnippet}`);
  }
}
if (!source.includes("require('react-native-quick-crypto')")) {
  throw new Error('mobile journal crypto must load the native react-native-quick-crypto provider');
}
for (const requiredNativeHarnessSnippet of [
  'nativeProviderCalls',
  'native quick crypto provider did not round-trip AES-GCM plaintext',
  'native quick crypto provider was not used for',
  "specifier === 'react-native-quick-crypto'",
  'webcrypto: nativeProvider',
]) {
  if (!verifierSource.includes(requiredNativeHarnessSnippet)) {
    throw new Error(`journal crypto verifier missing native-provider harness marker: ${requiredNativeHarnessSnippet}`);
  }
}
if (!source.includes('EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO')) {
  throw new Error('mobile journal crypto must expose a production native-crypto-required flag');
}
if (!source.includes('Native secure journal crypto provider unavailable')) {
  throw new Error('mobile journal crypto must fail closed when native crypto is required but unavailable');
}
for (const requiredSelfTestSnippet of [
  'export async function runJournalCryptoSelfTest',
  "'runJournalCryptoSelfTest'",
  'provider=${status.provider}',
  'provider status ${status.provider}',
  'native-required ${status.nativeRequired}',
  'aes_gcm_roundtrip=true',
  'round-trip',
  'unique_iv=true',
  'unique IV',
  'tamper_rejected=true',
  'tamper rejected',
  'associated_data_rejected=true',
  'wrong associated data rejected',
  'key_disposal=true',
  'key disposed',
  'disposed_handle_rejected=true',
  'disposed handle rejected',
  'revoked_key_rejected=true',
  'stale raw key rejected',
  'passphrase buffer zeroized',
  'salt buffer zeroized',
  'plaintext buffer zeroized',
]) {
  if (!source.includes(requiredSelfTestSnippet)) {
    throw new Error(`mobile journal crypto missing native-device self-test marker: ${requiredSelfTestSnippet}`);
  }
}
for (const requiredMobileConfigControl of [
  'resolveMobileRuntimeConfig',
  'EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT',
  'EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO',
  'EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true is required for staging or production mobile builds',
  'assertStrictMobileURL',
  'isReservedPlaceholderHost',
  "'https:'",
  "'wss:'",
]) {
  if (!mobileAPISource.includes(requiredMobileConfigControl)) {
    throw new Error(`mobile API config missing strict production control: ${requiredMobileConfigControl}`);
  }
}
for (const requiredWebConfigControl of [
  'resolveWebRuntimeConfig',
  'NEXT_PUBLIC_DEPLOYMENT_ENVIRONMENT',
  'assertStrictWebURL',
  'isReservedPlaceholderHost',
  "'https:'",
  "'wss:'",
]) {
  if (!webAPISource.includes(requiredWebConfigControl)) {
    throw new Error(`web API config missing strict production control: ${requiredWebConfigControl}`);
  }
}

if (!globalThis.crypto?.subtle) {
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: webcrypto,
  });
}

const compiled = ts.transpileModule(source, {
  compilerOptions: {
    esModuleInterop: true,
    module: ts.ModuleKind.CommonJS,
    target: ts.ScriptTarget.ES2020,
  },
});

const loadedModule = { exports: {} };
const execute = new Function('require', 'module', 'exports', 'Buffer', compiled.outputText);
execute(mobileRequire, loadedModule, loadedModule.exports, Buffer);

const {
  createJournalCryptoKeyHandle,
  decryptJournalData,
  deriveIsolationKey,
  disposeJournalCryptoKey,
  encryptJournalData,
  journalAssociatedData,
  getJournalCryptoProviderStatus,
  getJournalCryptoKey,
} = loadedModule.exports;
const plaintext = 'Private journal note: John 1 reflection, pastoral context, and prayer details.';
const key = await deriveIsolationKey('correct horse battery staple', 'journal:v1:server-derived-salt');
const associatedData = journalAssociatedData('journal:v1:server-derived-salt', 1);
const localProviderStatus = getJournalCryptoProviderStatus();
if (localProviderStatus.provider !== 'webcrypto-fallback' || localProviderStatus.nativeRequired !== false) {
  throw new Error('local journal crypto verifier expected non-production WebCrypto fallback status');
}

if (typeof key === 'string') {
  throw new Error('derived journal key must be a non-extractable key handle, not string key material');
}

let keyWasExported = false;
try {
  await webcrypto.subtle.exportKey('raw', key);
  keyWasExported = true;
} catch {
  keyWasExported = false;
}
if (keyWasExported) {
  throw new Error('derived journal key must be non-extractable');
}

const encrypted = await encryptJournalData(plaintext, key, associatedData);
const secondEncrypted = await encryptJournalData(plaintext, key, associatedData);
const plaintextBase64 = Buffer.from(plaintext).toString('base64');

if (encrypted.ciphertext === plaintextBase64 || encrypted.ciphertext.includes(plaintext)) {
  throw new Error('journal ciphertext leaked plaintext or plaintext-equivalent base64');
}
if (secondEncrypted.iv === encrypted.iv || secondEncrypted.ciphertext === encrypted.ciphertext) {
  throw new Error('journal AES-GCM encryption reused IV material');
}

const decrypted = await decryptJournalData(encrypted, key, associatedData);
if (decrypted !== plaintext) {
  throw new Error('journal AES-GCM decrypt did not round-trip plaintext');
}

const tamperedCiphertext = encrypted.ciphertext.slice(0, -2) + 'AA';
let tamperRejected = false;
try {
  await decryptJournalData({ ...encrypted, ciphertext: tamperedCiphertext }, key, associatedData);
} catch {
  tamperRejected = true;
}
if (!tamperRejected) {
  throw new Error('journal AES-GCM decrypt accepted tampered ciphertext');
}

let wrongAssociatedDataRejected = false;
try {
  await decryptJournalData(encrypted, key, journalAssociatedData('journal:v1:different-salt', 1));
} catch {
  wrongAssociatedDataRejected = true;
}
if (!wrongAssociatedDataRejected) {
  throw new Error('journal AES-GCM decrypt accepted wrong associated data');
}

const handle = createJournalCryptoKeyHandle(key);
if (handle.disposed || getJournalCryptoKey(handle) !== key) {
  throw new Error('journal key lifecycle handle did not expose the active key before disposal');
}
disposeJournalCryptoKey(handle);
if (!handle.disposed || handle.key !== null) {
  throw new Error('journal key lifecycle handle did not clear the key reference on disposal');
}
let disposedHandleRejected = false;
try {
  await encryptJournalData(plaintext, getJournalCryptoKey(handle));
} catch {
  disposedHandleRejected = true;
}
if (!disposedHandleRejected) {
  throw new Error('journal key lifecycle allowed encryption after disposal');
}
let revokedKeyRejected = false;
try {
  await encryptJournalData(plaintext, key);
} catch (error) {
  revokedKeyRejected = /disposed/.test(error.message);
}
if (!revokedKeyRejected) {
  throw new Error('journal key lifecycle allowed encryption with a stale raw key after disposal');
}

const untrackedKey = await webcrypto.subtle.importKey(
  'raw',
  webcrypto.getRandomValues(new Uint8Array(32)),
  { name: 'AES-GCM' },
  false,
  ['encrypt', 'decrypt'],
);
let untrackedKeyRejected = false;
try {
  await encryptJournalData('untracked journal key plaintext', untrackedKey);
} catch (error) {
  untrackedKeyRejected = /not derived by client-side journal key derivation/.test(error.message);
}
if (!untrackedKeyRejected) {
  throw new Error('journal crypto accepted a key that was not derived by the journal crypto module');
}
const fallbackKeyForNativeRequired = await deriveIsolationKey(
  'correct horse battery staple',
  'journal:v1:fallback-key-native-required',
);

const previousNativeRequired = process.env.EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO;
try {
  const previousGlobalCrypto = globalThis.crypto;
  const nativeProviderCalls = { getRandomValues: 0, importKey: 0, deriveKey: 0, encrypt: 0, decrypt: 0 };
  const capturedNativeBuffers = {
    encryptIV: null,
    encryptAssociatedData: null,
    decryptIV: null,
    decryptAssociatedData: null,
  };
  const nativeProvider = {
    getRandomValues(array) {
      nativeProviderCalls.getRandomValues += 1;
      return webcrypto.getRandomValues(array);
    },
    subtle: {
      importKey(...args) {
        nativeProviderCalls.importKey += 1;
        return webcrypto.subtle.importKey(...args);
      },
      deriveKey(...args) {
        nativeProviderCalls.deriveKey += 1;
        return webcrypto.subtle.deriveKey(...args);
      },
      encrypt(...args) {
        nativeProviderCalls.encrypt += 1;
        capturedNativeBuffers.encryptIV = args[0]?.iv ?? null;
        capturedNativeBuffers.encryptAssociatedData = args[0]?.additionalData ?? null;
        return webcrypto.subtle.encrypt(...args);
      },
      decrypt(...args) {
        nativeProviderCalls.decrypt += 1;
        capturedNativeBuffers.decryptIV = args[0]?.iv ?? null;
        capturedNativeBuffers.decryptAssociatedData = args[0]?.additionalData ?? null;
        return webcrypto.subtle.decrypt(...args);
      },
    },
  };
  try {
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: undefined,
    });
    process.env.EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO = 'true';
    const nativeProviderModule = { exports: {} };
    const requireWithQuickCrypto = (specifier) => {
      if (specifier === 'react-native-quick-crypto') {
        return { webcrypto: nativeProvider };
      }
      return mobileRequire(specifier);
    };
    execute(requireWithQuickCrypto, nativeProviderModule, nativeProviderModule.exports, Buffer);

    const nativeStatus = nativeProviderModule.exports.getJournalCryptoProviderStatus();
    if (nativeStatus.provider !== 'react-native-quick-crypto' || nativeStatus.nativeRequired !== true) {
      throw new Error('native quick crypto provider status was not reported while native crypto was required');
    }
    const nativeKey = await nativeProviderModule.exports.deriveIsolationKey(
      'correct horse battery staple',
      'journal:v1:server-derived-salt',
    );
    const nativeAssociatedData = nativeProviderModule.exports.journalAssociatedData('journal:v1:server-derived-salt', 1);
    const nativeEncrypted = await nativeProviderModule.exports.encryptJournalData(plaintext, nativeKey, nativeAssociatedData);
    const nativeDecrypted = await nativeProviderModule.exports.decryptJournalData(nativeEncrypted, nativeKey, nativeAssociatedData);
    if (nativeDecrypted !== plaintext) {
      throw new Error('native quick crypto provider did not round-trip AES-GCM plaintext');
    }
    for (const [name, bytes] of Object.entries(capturedNativeBuffers)) {
      if (!(bytes instanceof Uint8Array)) {
        throw new Error(`native quick crypto provider did not expose ${name} for runtime zeroization proof`);
      }
      if (bytes.some((value) => value !== 0)) {
        throw new Error(`native quick crypto ${name} buffer was not zeroized after AES-GCM operation`);
      }
    }
    for (const [operation, count] of Object.entries(nativeProviderCalls)) {
      if (count < 1) {
        throw new Error(`native quick crypto provider was not used for ${operation}`);
      }
    }
  } finally {
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: previousGlobalCrypto,
    });
  }

  process.env.EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO = 'true';
  const nativeRequiredModule = { exports: {} };
  const requireWithoutQuickCrypto = (specifier) => {
    if (specifier === 'react-native-quick-crypto') {
      throw new Error('native quick crypto unavailable in verifier fallback test');
    }
    return mobileRequire(specifier);
  };
  execute(requireWithoutQuickCrypto, nativeRequiredModule, nativeRequiredModule.exports, Buffer);
  let fallbackKeyRejected = false;
  try {
    await loadedModule.exports.encryptJournalData(plaintext, fallbackKeyForNativeRequired);
  } catch (error) {
    fallbackKeyRejected = /required native provider/.test(error.message);
  }
  if (!fallbackKeyRejected) {
    throw new Error('production native crypto flag allowed fallback-derived key use');
  }
  let nativeRequiredRejectedFallback = false;
  try {
    await nativeRequiredModule.exports.deriveIsolationKey('correct horse battery staple', 'journal:v1:server-derived-salt');
  } catch (error) {
    nativeRequiredRejectedFallback = /Native secure journal crypto provider unavailable/.test(error.message);
  }
  if (!nativeRequiredRejectedFallback) {
    throw new Error('production native crypto flag did not reject WebCrypto fallback when react-native-quick-crypto was unavailable');
  }
} finally {
  if (previousNativeRequired === undefined) {
    delete process.env.EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO;
  } else {
    process.env.EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO = previousNativeRequired;
  }
}

console.log(`journal crypto verification passed: ${journalCryptoProofMarkers.join(', ')}`);
