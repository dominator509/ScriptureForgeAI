import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import {
  validateTerraformImageDigestInputs,
  validatePlatformRuntimeConfig,
  validateTerraformSecretInputs,
} from './validate-deployment-skeleton.mjs';

async function terraformSecretFixtures() {
  const [variables, tfvarsExample, app] = await Promise.all([
    readFile('build/terraform/variables.tf', 'utf8'),
    readFile('build/terraform/terraform.tfvars.example', 'utf8'),
    readFile('build/terraform/app.tf', 'utf8'),
  ]);
  return { variables, tfvarsExample, app };
}

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

test('validateTerraformSecretInputs accepts current secret input wiring', async () => {
  const { variables, tfvarsExample, app } = await terraformSecretFixtures();
  assert.doesNotThrow(() => validateTerraformSecretInputs(variables, tfvarsExample, app));
});

test('validateTerraformSecretInputs rejects database root password defaults', async () => {
  const { variables, tfvarsExample, app } = await terraformSecretFixtures();
  const broken = variables.replace(
    'sensitive   = true',
    'sensitive   = true\n  default     = "replace-with-at-least-16-characters"',
  );
  assert.notEqual(broken, variables, 'test fixture must add a root password default');
  assert.throws(
    () => validateTerraformSecretInputs(broken, tfvarsExample, app),
    /database root passphrase must not define a default value/,
  );
});

test('validateTerraformSecretInputs rejects plaintext workload secret inputs', async () => {
  const { variables, tfvarsExample, app } = await terraformSecretFixtures();
  const broken = variables.replace(
    'can(regex("^arn:aws:secretsmanager:", var.app_secret_arns.openai_api_key)),',
    'length(var.app_secret_arns.openai_api_key) > 0,',
  );
  assert.notEqual(broken, variables, 'test fixture must remove the OpenAI secret ARN validation');
  assert.throws(
    () => validateTerraformSecretInputs(broken, tfvarsExample, app),
    /app_secret_arns\.openai_api_key must be validated as a Secrets Manager ARN/,
  );
});

test('validateTerraformSecretInputs rejects workload root database URL construction', async () => {
  const { variables, tfvarsExample, app } = await terraformSecretFixtures();
  const broken = `${app}\n# regression marker aws_rds_cluster.postgres.master_password`;
  assert.throws(
    () => validateTerraformSecretInputs(variables, tfvarsExample, broken),
    /workload manifests must not read the RDS root password/,
  );
});

test('validateTerraformImageDigestInputs accepts current immutable workload image wiring', async () => {
  const { variables, tfvarsExample, app } = await terraformSecretFixtures();
  assert.doesNotThrow(() => validateTerraformImageDigestInputs(variables, tfvarsExample, app));
});

test('validateTerraformImageDigestInputs rejects mutable image tag inputs', async () => {
  const { variables, tfvarsExample, app } = await terraformSecretFixtures();
  const broken = variables.replace('@sha256:[0-9a-f]{64}$', ':[A-Za-z0-9._-]+$');
  assert.notEqual(broken, variables, 'test fixture must remove the API immutable digest validation');
  assert.throws(
    () => validateTerraformImageDigestInputs(broken, tfvarsExample, app),
    /api_image must validate immutable sha256 image digests/,
  );
});
