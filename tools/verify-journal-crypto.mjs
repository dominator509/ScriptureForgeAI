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
const mobileJournalContainerPath = path.join(mobileRoot, 'src', 'components', 'SecureJournalContainer.tsx');
const mobileRequire = createRequire(path.join(mobileRoot, 'package.json'));
const ts = mobileRequire('typescript');

const source = fs.readFileSync(cryptoSourcePath, 'utf8');
const clientJournalSources = [
  [webJournalEditorPath, fs.readFileSync(webJournalEditorPath, 'utf8')],
  [mobileJournalContainerPath, fs.readFileSync(mobileJournalContainerPath, 'utf8')],
];
const forbiddenPatterns = [
  /Buffer\.from\(plaintext\)\.toString\(['"]base64['"]\)/,
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

for (const requiredLifecycleSnippet of [
  'function wipeBytes',
  'finally',
  'wipeBytes(passphraseBytes)',
  'wipeBytes(saltBytes)',
  'wipeBytes(plaintextBytes)',
  'wipeBytes(ciphertextBytes)',
  'wipeBytes(ivBytes)',
  'createJournalCryptoKeyHandle',
  'disposeJournalCryptoKey',
]) {
  if (!source.includes(requiredLifecycleSnippet)) {
    throw new Error(`mobile journal crypto missing lifecycle control: ${requiredLifecycleSnippet}`);
  }
}

const packageJson = JSON.parse(fs.readFileSync(path.join(mobileRoot, 'package.json'), 'utf8'));
if (!packageJson.dependencies?.['react-native-quick-crypto']) {
  throw new Error('mobile package.json must declare react-native-quick-crypto for production AES-GCM builds');
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
  getJournalCryptoKey,
} = loadedModule.exports;
const plaintext = 'Private journal note: John 1 reflection, pastoral context, and prayer details.';
const key = await deriveIsolationKey('correct horse battery staple', 'journal:v1:server-derived-salt');

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

const encrypted = await encryptJournalData(plaintext, key);
const plaintextBase64 = Buffer.from(plaintext).toString('base64');

if (encrypted.ciphertext === plaintextBase64 || encrypted.ciphertext.includes(plaintext)) {
  throw new Error('journal ciphertext leaked plaintext or plaintext-equivalent base64');
}

const decrypted = await decryptJournalData(encrypted, key);
if (decrypted !== plaintext) {
  throw new Error('journal AES-GCM decrypt did not round-trip plaintext');
}

const tamperedCiphertext = encrypted.ciphertext.slice(0, -2) + 'AA';
let tamperRejected = false;
try {
  await decryptJournalData({ ...encrypted, ciphertext: tamperedCiphertext }, key);
} catch {
  tamperRejected = true;
}
if (!tamperRejected) {
  throw new Error('journal AES-GCM decrypt accepted tampered ciphertext');
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

console.log('journal crypto verification passed');
