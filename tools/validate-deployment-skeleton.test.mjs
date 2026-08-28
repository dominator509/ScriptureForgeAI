import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import {
  validateContainerBuildDefinitions,
  validateDatabaseTransportConfig,
  validateTerraformEKSSecretEncryption,
  validateLocalComposeConfig,
  validateMetricsAuthentication,
  validateTerraformImageDigestInputs,
  validatePlatformRuntimeConfig,
  validateTerraformReleaseInputGuards,
  validateTerraformSecretInputs,
  validateTerraformStorageKMSInputs,
  validateNetworkPolicies,
  validateWorkloadSecretSeparation,
} from './validate-deployment-skeleton.mjs';

async function terraformSecretFixtures() {
  const [variables, tfvarsExample, app, data, eks] = await Promise.all([
    readFile('build/terraform/variables.tf', 'utf8'),
    readFile('build/terraform/terraform.tfvars.example', 'utf8'),
    readFile('build/terraform/app.tf', 'utf8'),
    readFile('build/terraform/data.tf', 'utf8'),
    readFile('build/terraform/eks.tf', 'utf8'),
  ]);
  return { variables, tfvarsExample, app, data, eks };
}

async function terraformNetworkPolicyFixture() {
  return readFile('build/terraform/network_policy.tf', 'utf8');
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

test('validatePlatformRuntimeConfig rejects an unprotected API metrics surface', async () => {
  const source = await readFile('cmd/platform-engine/main.go', 'utf8');
  const broken = source.replace('protectedMetricsHandler(observer.MetricsHandler())', 'observer.MetricsHandler()');
  assert.notEqual(broken, source, 'test fixture must remove the protected metrics route wiring');
  assert.throws(
    () => validatePlatformRuntimeConfig(broken),
    /protectedMetricsHandler\(observer\.MetricsHandler\(\)\)/,
  );
});

test('validateMetricsAuthentication rejects a guard that does not fail closed', async () => {
  const source = await readFile('cmd/platform-engine/metrics_security.go', 'utf8');
  const broken = source.replace('http.StatusServiceUnavailable', 'http.StatusOK');
  assert.notEqual(broken, source, 'test fixture must weaken the missing-token response');
  assert.throws(
    () => validateMetricsAuthentication(broken),
    /StatusServiceUnavailable/,
  );
});

test('validateContainerBuildDefinitions accepts production workload Dockerfiles', async () => {
  const [api, rust, web] = await Promise.all([
    readFile('services/platform-engine/Dockerfile', 'utf8'),
    readFile('services/scripture-engine/Dockerfile', 'utf8'),
    readFile('web/Dockerfile', 'utf8'),
  ]);
  assert.doesNotThrow(() => validateContainerBuildDefinitions(api, rust, web));
});

test('validateContainerBuildDefinitions rejects placeholder workload entrypoints', () => {
  assert.throws(
    () => validateContainerBuildDefinitions(
      'FROM golang:1.24.3-bookworm AS build\nCOPY go.mod go.sum ./\nCOPY cmd ./cmd\nCOPY internal ./internal\ngo build -trimpath ./cmd/platform-engine\nUSER nonroot:nonroot\nENTRYPOINT ["/usr/local/bin/scriptureforge-api"]\nsleep infinity',
      'FROM rust:1.97-bookworm AS build\nCOPY proto ./proto\ncargo build --release --locked\nEXPOSE 50051 9102\nUSER scriptureforge\nENTRYPOINT ["/usr/local/bin/scriptureforge-engine"]\nsleep infinity',
      'COPY web/package.json web/package-lock.json ./web/\nnpm ci --prefix web\nnpm run build --prefix web\nnpm ci --omit=dev\nUSER node\nCMD ["npm", "run", "start"]',
    ),
    /must not use a placeholder sleep entrypoint/,
  );
});

test('validateLocalComposeConfig accepts the current local service wiring', async () => {
  const compose = await readFile('docker-compose.yml', 'utf8');
  assert.doesNotThrow(() => validateLocalComposeConfig(compose));
});

test('validateLocalComposeConfig rejects legacy service contexts and environment names', async () => {
  const compose = await readFile('docker-compose.yml', 'utf8');
  const broken = compose
    .replace('context: .', 'context: ./services/platform-engine')
    .replace('DATABASE_URL:', 'DB_HOST: postgres\n      DATABASE_URL:');
  assert.notEqual(broken, compose, 'test fixture must reintroduce legacy Compose wiring');
  assert.throws(
    () => validateLocalComposeConfig(broken),
    /local Docker Compose config must not retain (context: \.\/services\/platform-engine|DB_HOST:)/,
  );
});

test('validateDatabaseTransportConfig accepts strict Go and Rust TLS guards', async () => {
  const [goSource, rustSource] = await Promise.all([
    readFile('cmd/platform-engine/main.go', 'utf8'),
    readFile('services/scripture-engine/src/main.rs', 'utf8'),
  ]);
  assert.doesNotThrow(() => validateDatabaseTransportConfig(goSource, rustSource));
});

test('validateDatabaseTransportConfig rejects removed strict TLS enforcement', async () => {
  const [goSource, rustSource] = await Promise.all([
    readFile('cmd/platform-engine/main.go', 'utf8'),
    readFile('services/scripture-engine/src/main.rs', 'utf8'),
  ]);
  const brokenGo = goSource.replace('validateDatabaseURLTransport(dbURL, requiresConfiguredGRPCAddress())', '/* database transport guard removed */');
  assert.notEqual(brokenGo, goSource, 'test fixture must remove the Go database transport guard marker');
  assert.throws(
    () => validateDatabaseTransportConfig(brokenGo, rustSource),
    /Go database transport config missing validateDatabaseURLTransport/,
  );
});

test('validateTerraformSecretInputs accepts current secret input wiring', async () => {
  const { variables, tfvarsExample, app } = await terraformSecretFixtures();
  assert.doesNotThrow(() => validateTerraformSecretInputs(variables, tfvarsExample, app));
});

test('validateTerraformSecretInputs rejects legacy database root password inputs', async () => {
  const { variables, tfvarsExample, app } = await terraformSecretFixtures();
  const broken = `${variables}\nvariable "database_root_security_passphrase" {\n  type = string\n}`;
  assert.notEqual(broken, variables, 'test fixture must add a legacy root password input');
  assert.throws(
    () => validateTerraformSecretInputs(broken, tfvarsExample, app),
    /must not accept a root database password input/,
  );
});

test('validateTerraformSecretInputs rejects root password examples', async () => {
  const { variables, tfvarsExample, app } = await terraformSecretFixtures();
  const broken = `${tfvarsExample}\ndatabase_root_security_passphrase = "replace-with-a-secret"`;
  assert.throws(
    () => validateTerraformSecretInputs(variables, broken, app),
    /terraform\.tfvars\.example must not expose a root database password input/,
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

test('validateTerraformSecretInputs rejects an unvalidated metrics auth secret ARN', async () => {
  const { variables, tfvarsExample, app } = await terraformSecretFixtures();
  const broken = variables.replace(
    'can(regex("^arn:aws:secretsmanager:", var.app_secret_arns.metrics_auth_token)),',
    'length(var.app_secret_arns.metrics_auth_token) > 0,',
  );
  assert.notEqual(broken, variables, 'test fixture must remove the metrics auth secret ARN validation');
  assert.throws(
    () => validateTerraformSecretInputs(broken, tfvarsExample, app),
    /app_secret_arns\.metrics_auth_token must be validated as a Secrets Manager ARN/,
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


test('validateWorkloadSecretSeparation keeps Rust server TLS material out of the API workload', async () => {
  const { app } = await terraformSecretFixtures();
  assert.doesNotThrow(() => validateWorkloadSecretSeparation(app));
});

test('validateWorkloadSecretSeparation rejects API access to Rust server private material', async () => {
  const { app } = await terraformSecretFixtures();
  const broken = app.replace(
    'objectAlias = "grpc_engine_tls_client_key_pem"',
    'objectAlias = "grpc_engine_tls_server_key_pem"',
  );
  assert.notEqual(broken, app, 'test fixture must add server key material to the API provider');
  assert.throws(
    () => validateWorkloadSecretSeparation(broken),
    /API workload must not receive Rust server TLS material/,
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

test('validateTerraformStorageKMSInputs accepts current storage KMS wiring', async () => {
  const { variables, tfvarsExample, data } = await terraformSecretFixtures();
  assert.doesNotThrow(() => validateTerraformStorageKMSInputs(variables, tfvarsExample, data));
});

test('validateTerraformStorageKMSInputs rejects missing RDS customer-managed KMS wiring', async () => {
  const { variables, tfvarsExample, data } = await terraformSecretFixtures();
  const broken = data.replace(/^\s*kms_key_id\s*=\s*var\.database_kms_key_arn\r?\n/m, '');
  assert.notEqual(broken, data, 'test fixture must remove RDS KMS wiring');
  assert.throws(
    () => validateTerraformStorageKMSInputs(variables, tfvarsExample, broken),
    /terraform storage KMS wiring missing .*kms_key_id.*database_kms_key_arn/,
  );
});

test('validateTerraformStorageKMSInputs rejects Terraform-managed RDS passwords', async () => {
  const { variables, tfvarsExample, data } = await terraformSecretFixtures();
  const broken = data.replace(
    '  manage_master_user_password   = true\n',
    '  master_password        = "replace-with-a-secret"\n',
  );
  assert.notEqual(broken, data, 'test fixture must replace managed RDS credentials');
  assert.throws(
    () => validateTerraformStorageKMSInputs(variables, tfvarsExample, broken),
    /terraform storage KMS wiring missing .*manage_master_user_password.*true/,
  );
});

test('validateTerraformStorageKMSInputs rejects weak Redis KMS input validation', async () => {
  const { variables, tfvarsExample, data } = await terraformSecretFixtures();
  const broken = variables.replace(' || can(regex("^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:alias/[A-Za-z0-9/_-]+$", var.redis_kms_key_arn))', '');
  assert.notEqual(broken, variables, 'test fixture must weaken Redis KMS validation marker');
  assert.throws(
    () => validateTerraformStorageKMSInputs(broken, tfvarsExample, data),
    /redis_kms_key_arn must validate customer-managed AWS KMS key or alias ARNs/,
  );
});

test('validateTerraformEKSSecretEncryption accepts current envelope encryption wiring', async () => {
  const { variables, tfvarsExample, eks } = await terraformSecretFixtures();
  assert.doesNotThrow(() => validateTerraformEKSSecretEncryption(variables, tfvarsExample, eks));
});

test('validateTerraformEKSSecretEncryption rejects missing EKS secrets encryption', async () => {
  const { variables, tfvarsExample, eks } = await terraformSecretFixtures();
  const broken = eks.replace('  encryption_config {', '  # encryption_config removed');
  assert.notEqual(broken, eks, 'test fixture must remove EKS secrets encryption');
  assert.throws(
    () => validateTerraformEKSSecretEncryption(variables, tfvarsExample, broken),
    /EKS Secret envelope encryption missing encryption_config \{/,
  );
});

test('validateTerraformReleaseInputGuards accepts current staging input validation', async () => {
  const { variables } = await terraformSecretFixtures();
  assert.doesNotThrow(() => validateTerraformReleaseInputGuards(variables));
});

test('validateTerraformReleaseInputGuards rejects default service versions', async () => {
  const { variables } = await terraformSecretFixtures();
  const broken = variables.replace(
    'variable "service_version" {\n  description = "Release or image version label attached to application telemetry."\n  type        = string\n\n  validation {',
    'variable "service_version" {\n  description = "Release or image version label attached to application telemetry."\n  type        = string\n  default     = "unversioned"\n\n  validation {',
  );
  assert.notEqual(broken, variables, 'test fixture must add a service_version default');
  assert.throws(
    () => validateTerraformReleaseInputGuards(broken),
    /service_version must not define a default value/,
  );
});

test('validateTerraformReleaseInputGuards rejects weak WebSocket origin validation', async () => {
  const { variables } = await terraformSecretFixtures();
  const broken = variables.replace(
    'startswith(trimspace(origin), "https://")',
    'length(trimspace(origin)) > 0',
  );
  assert.notEqual(broken, variables, 'test fixture must weaken allowed_ws_origins validation');
  assert.throws(
    () => validateTerraformReleaseInputGuards(broken),
    /allowed_ws_origins validation must reject or require https:\/\//,
  );
});

test('validateTerraformReleaseInputGuards rejects placeholder hostname validation drift', async () => {
  const { variables } = await terraformSecretFixtures();
  const broken = variables.replaceAll('!strcontains(lower(trimspace(var.api_hostname)), ".example") &&', '');
  assert.notEqual(broken, variables, 'test fixture must weaken api_hostname placeholder validation');
  assert.throws(
    () => validateTerraformReleaseInputGuards(broken),
    /api_hostname validation must reject \.example/,
  );
});

test('validateNetworkPolicies accepts the default-deny workload policies', async () => {
  const networkPolicy = await terraformNetworkPolicyFixture();
  assert.doesNotThrow(() => validateNetworkPolicies(networkPolicy));
});

test('validateNetworkPolicies rejects unrestricted egress', async () => {
  const networkPolicy = await terraformNetworkPolicyFixture();
  const broken = `${networkPolicy}\n# cidr = "0.0.0.0/0"`;
  assert.throws(
    () => validateNetworkPolicies(broken),
    /must not restore unrestricted egress/,
  );
});

test('validateNetworkPolicies rejects database egress without destinations', async () => {
  const networkPolicy = await terraformNetworkPolicyFixture();
  const broken = networkPolicy.replaceAll('for_each = var.data_tier_cidrs', 'for_each = var.allowed_ingress_cidrs');
  assert.notEqual(broken, networkPolicy, 'test fixture must remove data-tier destination scoping');
  assert.throws(
    () => validateNetworkPolicies(broken),
    /database-port egress must be scoped to declared data-tier CIDRs/,
  );
});
