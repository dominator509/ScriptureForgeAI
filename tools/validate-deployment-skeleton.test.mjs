import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { validatePlatformRuntimeConfig } from './validate-deployment-skeleton.mjs';

test('validatePlatformRuntimeConfig accepts the platform engine runtime guard', async () => {
  const source = await readFile('cmd/platform-engine/main.go', 'utf8');
  assert.doesNotThrow(() => validatePlatformRuntimeConfig(source));
});

test('validatePlatformRuntimeConfig rejects missing production grpc guard', async () => {
  const source = await readFile('cmd/platform-engine/main.go', 'utf8');
  const broken = source.replace('case "staging", "production", "prod":', 'case "development":');
  assert.notEqual(broken, source, 'test fixture must remove the production runtime guard marker');
  assert.throws(
    () => validatePlatformRuntimeConfig(broken),
    /explicit GRPC_ENGINE_ADDRESS/,
  );
});

test('validatePlatformRuntimeConfig rejects missing local fallback marker', async () => {
  const source = await readFile('cmd/platform-engine/main.go', 'utf8');
  const broken = source.replace('grpcAddr = "localhost:50051"', 'grpcAddr = ""');
  assert.notEqual(broken, source, 'test fixture must remove the local runtime fallback marker');
  assert.throws(
    () => validatePlatformRuntimeConfig(broken),
    /localhost:50051/,
  );
});
