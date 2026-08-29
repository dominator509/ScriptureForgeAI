import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const terraformDir = new URL('../build/terraform/', import.meta.url);
const platformEngineMain = new URL('../cmd/platform-engine/main.go', import.meta.url);
const platformMetricsSecurity = new URL('../cmd/platform-engine/metrics_security.go', import.meta.url);
const scriptureEngineMain = new URL('../services/scripture-engine/src/main.rs', import.meta.url);
const apiDockerfile = new URL('../services/platform-engine/Dockerfile', import.meta.url);
const rustDockerfile = new URL('../services/scripture-engine/Dockerfile', import.meta.url);
const webDockerfile = new URL('../web/Dockerfile', import.meta.url);
const composeFile = new URL('../docker-compose.yml', import.meta.url);

export const deploymentSkeletonProofMarkers = [
  'remote_state_backend=true',
  'irsa_secret_access=true',
  'secretproviderclass_sync=true',
  'database_root_secret_managed=true',
  'workload_secret_inputs_are_arns=true',
  'tls_ingress=true',
  'rds_backup_final_snapshot=true',
  'redis_runtime_wiring=true',
  'grpc_engine_wiring=true',
  'otel_runtime_wiring=true',
  'hpa_pdb_rollout_safety=true',
  'root_database_url_absent=true',
  'immutable_workload_image_digests=true',
  'customer_managed_storage_kms=true',
  'eks_secrets_envelope_encryption=true',
  'metrics_authentication=true',
  'staging_input_placeholders_rejected=true',
  'container_build_definitions=true',
  'database_tls_enforced=true',
  'network_policy=true',
];

async function readTerraform(name) {
  return readFile(new URL(name, terraformDir), 'utf8');
}

const [app, service, variables, iam, versions, tfvarsExample, backendExample, eks, networkPolicy] = await Promise.all([
  readTerraform('app.tf'),
  readTerraform('service.tf'),
  readTerraform('variables.tf'),
  readTerraform('iam.tf'),
  readTerraform('versions.tf'),
  readTerraform('terraform.tfvars.example'),
  readTerraform('backend.hcl.example'),
  readTerraform('eks.tf'),
  readTerraform('network_policy.tf'),
]);
const [platformMain, metricsSecurity, rustMain, apiContainer, rustContainer, webContainer, compose] = await Promise.all([
  readFile(platformEngineMain, 'utf8'),
  readFile(platformMetricsSecurity, 'utf8'),
  readFile(scriptureEngineMain, 'utf8'),
  readFile(apiDockerfile, 'utf8'),
  readFile(rustDockerfile, 'utf8'),
  readFile(webDockerfile, 'utf8'),
  readFile(composeFile, 'utf8'),
]);

function requireIncludes(source, snippets, label) {
  for (const snippet of snippets) {
    assert.ok(source.includes(snippet), `${label} missing ${snippet}`);
  }
}

function requireMatches(source, patterns, label) {
  for (const pattern of patterns) {
    assert.ok(pattern.test(source), `${label} missing ${pattern}`);
  }
}

export function validatePlatformRuntimeConfig(platformMain) {
  requireIncludes(
    platformMain,
    [
      'func requiresConfiguredGRPCAddress() bool',
      'DEPLOYMENT_ENVIRONMENT',
      'GRPC_ENGINE_ADDRESS environment variable is required in staging/production',
      'grpcAddr = "localhost:50051"',
      'protectedMetricsHandler(observer.MetricsHandler())',
    ],
    'platform engine runtime config',
  );
  assert.ok(
    /case "staging", "production", "prod":\s*\n\s*return true/.test(platformMain),
    'platform engine must require explicit GRPC_ENGINE_ADDRESS for staging/production/prod',
  );
  assert.ok(
    /case "", "development", "dev", "test", "local":\s*\n\s*return false/.test(platformMain),
    'platform engine must keep insecure gRPC fallback local-only',
  );
  assert.ok(
    /default:\s*\n\s*return true/.test(platformMain),
    'platform engine must fail closed for unknown deployment environments',
  );
}

export function validateMetricsAuthentication(metricsSecurity) {
  requireIncludes(
    metricsSecurity,
    [
      'func protectedMetricsHandler(next http.Handler) http.Handler',
      'METRICS_AUTH_TOKEN',
      'func requiresConfiguredMetricsAuthForEnvironment(environment string) bool',
      'metrics unavailable',
      'StatusServiceUnavailable',
      'ConstantTimeCompare',
    ],
    'platform API metrics authentication',
  );
  assert.ok(
    /case "", "development", "dev", "test", "local":\s*\n\s*return false/.test(metricsSecurity),
    'platform API metrics authentication must retain explicit local-only exceptions',
  );
  assert.ok(
    /default:\s*\n\s*return true/.test(metricsSecurity),
    'platform API metrics authentication must fail closed for unknown environments',
  );
}

export function validateDatabaseTransportConfig(platformMain, rustMain) {
  requireIncludes(
    platformMain,
    [
      '"net/url"',
      'func validateDatabaseURLTransport(rawURL string, requireTLS bool) error',
      'sslmode=require, verify-ca, or verify-full',
      'validateDatabaseURLTransport(dbURL, requiresConfiguredGRPCAddress())',
    ],
    'Go database transport config',
  );
  requireIncludes(
    rustMain,
    [
      'PgConnectOptions',
      'PgSslMode',
      'fn validate_database_url_transport(',
      'options.get_ssl_mode()',
      'validate_database_url_transport(&database_url, requires_grpc_security())?',
    ],
    'Rust database transport config',
  );
}

export function validateContainerBuildDefinitions(apiContainer, rustContainer, webContainer) {
  requireIncludes(
    apiContainer,
    [
      'FROM golang:1.24.3-bookworm AS build',
      'COPY go.mod go.sum ./',
      'COPY cmd ./cmd',
      'COPY internal ./internal',
      'go build -trimpath',
      './cmd/platform-engine',
      'USER nonroot:nonroot',
      'ENTRYPOINT ["/usr/local/bin/scriptureforge-api"]',
    ],
    'API container build',
  );
  assert.ok(!apiContainer.includes('state_wal.log'), 'API container must not package the legacy in-memory WAL service');
  assert.ok(!apiContainer.includes('sleep infinity'), 'API container must not use a placeholder sleep entrypoint');

  requireIncludes(
    rustContainer,
    [
      'FROM rust:1.97.1-bookworm AS build',
      'COPY proto ./proto',
      'cargo build --release --locked',
      'COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt',
      'EXPOSE 50051 9102',
      'USER scriptureforge',
      'ENTRYPOINT ["/usr/local/bin/scriptureforge-engine"]',
    ],
    'Rust container build',
  );
  assert.ok(!rustContainer.includes('apt-get install'), 'Rust runtime must not install unpinned apt packages');
  assert.ok(!rustContainer.includes('sleep infinity'), 'Rust container must not use a placeholder sleep entrypoint');

  requireIncludes(
    webContainer,
    [
      'COPY web/package.json web/package-lock.json ./web/',
      'npm ci --prefix web',
      'npm run build --prefix web',
      'npm ci --omit=dev',
      'USER node',
      'CMD ["npm", "run", "start"]',
    ],
    'web container build',
  );
}

export function validateLocalComposeConfig(compose) {
  requireIncludes(
    compose,
    [
      'image: pgvector/pgvector@sha256:eac621400b7b7ff52493883e41e930e3d104695fea5b68cc0c42370cf7880067',
      './migrations:/docker-entrypoint-initdb.d:ro',
      'context: .',
      'dockerfile: services/platform-engine/Dockerfile',
      'dockerfile: services/scripture-engine/Dockerfile',
      'DATABASE_URL:',
      'REDIS_URL: redis://redis:6379',
      'GRPC_ENGINE_ADDRESS: scripture-engine:50051',
      'DEPLOYMENT_ENVIRONMENT: development',
      'JOURNAL_SALT_SECRET:',
      'MFA_ENCRYPTION_KEY:',
      'ALLOWED_WS_ORIGINS: http://localhost:3000,http://127.0.0.1:3000',
      'RUST_ENGINE_BIND_ADDRESS: 0.0.0.0:50051',
      'RUST_ENGINE_METRICS_ADDRESS: 0.0.0.0:9102',
    ],
    'local Docker Compose config',
  );
  for (const forbidden of [
    'image: postgres:15',
    'DB_HOST:',
    'DB_USER:',
    'DB_PASS:',
    'DB_NAME:',
    'REDIS_HOST:',
    'REDIS_PORT:',
    'testing-secret-key-123',
    'context: ./services/platform-engine',
    'context: ./services/scripture-engine',
  ]) {
    assert.ok(!compose.includes(forbidden), `local Docker Compose config must not retain ${forbidden}`);
  }
}

function terraformVariableBlock(source, name) {
  const start = source.indexOf(`variable "${name}"`);
  assert.ok(start >= 0, `terraform variables missing ${name}`);
  const next = source.indexOf('\nvariable "', start + 1);
  return source.slice(start, next >= 0 ? next : source.length);
}

export function validateTerraformSecretInputs(variables, tfvarsExample, app) {
  assert.ok(!variables.includes('variable "database_root_security_passphrase"'), 'Terraform must not accept a root database password input');
  assert.ok(!tfvarsExample.includes('database_root_security_passphrase'), 'terraform.tfvars.example must not expose a root database password input');

  const secretARNBlock = terraformVariableBlock(variables, 'app_secret_arns');
  for (const key of ['database_url', 'jwt_secret_key', 'journal_salt_secret', 'mfa_encryption_key', 'redis_auth_token', 'openai_api_key', 'metrics_auth_token', 'zoom_credentials', 'grpc_engine_shared_secret', 'grpc_engine_tls_credentials']) {
    assert.match(secretARNBlock, new RegExp(`${key}\\s*=\\s*string`), `app_secret_arns missing ${key}`);
    assert.ok(
      secretARNBlock.includes(`can(regex("^arn:aws:secretsmanager:", var.app_secret_arns.${key}))`),
      `app_secret_arns.${key} must be validated as a Secrets Manager ARN`,
    );
    assert.ok(
      tfvarsExample.includes(`${key}`) && tfvarsExample.includes('arn:aws:secretsmanager:'),
      `terraform.tfvars.example must document ${key} as a Secrets Manager ARN`,
    );
  }
  assert.ok(!app.includes('aws_rds_cluster.postgres.master_password'), 'workload manifests must not read the RDS root password');
  assert.ok(!app.includes('aws_rds_cluster.postgres.master_username'), 'workload manifests must not construct a root database URL');
  assert.ok(!app.includes('postgres://'), 'workload manifests must source DATABASE_URL from Secrets Manager, not inline PostgreSQL URLs');
}

export function validateWorkloadSecretSeparation(app) {
  const apiStart = app.indexOf('name      = "scriptureforge-app-secrets"');
  const rustStart = app.indexOf('name      = "scriptureforge-rust-secrets"');
  assert.ok(apiStart >= 0 && rustStart > apiStart, 'workload SecretProviderClass boundaries must be present');

  const apiSecretProvider = app.slice(apiStart, rustStart);
  const rustSecretProvider = app.slice(rustStart);
  for (const forbidden of [
    'path        = "server_cert_pem"',
    'objectAlias = "grpc_engine_tls_server_cert_pem"',
    'path        = "server_key_pem"',
    'objectAlias = "grpc_engine_tls_server_key_pem"',
    'objectName = "grpc_engine_tls_server_cert_pem"',
    'objectName = "grpc_engine_tls_server_key_pem"',
    'key        = "GRPC_ENGINE_TLS_CERT_PEM"',
    'key        = "GRPC_ENGINE_TLS_KEY_PEM"',
  ]) {
    assert.ok(!apiSecretProvider.includes(forbidden), `API workload must not receive Rust server TLS material: ${forbidden}`);
  }
  for (const required of [
    'path        = "server_cert_pem"',
    'path        = "server_key_pem"',
    'objectAlias = "grpc_engine_tls_server_cert_pem"',
    'objectAlias = "grpc_engine_tls_server_key_pem"',
    'key        = "GRPC_ENGINE_TLS_CERT_PEM"',
    'key        = "GRPC_ENGINE_TLS_KEY_PEM"',
  ]) {
    assert.ok(rustSecretProvider.includes(required), `Rust workload must retain its server TLS material: ${required}`);
  }
}

export function validateTerraformImageDigestInputs(variables, tfvarsExample, app) {
  for (const name of ['api_image', 'web_image', 'rust_engine_image']) {
    const block = terraformVariableBlock(variables, name);
    assert.ok(
      block.includes('@sha256:[0-9a-f]{64}$'),
      `${name} must validate immutable sha256 image digests`,
    );
    assert.ok(
      new RegExp(`${name}\\s*=\\s*"[^"]+@sha256:[0-9a-f]{64}"`).test(tfvarsExample),
      `terraform.tfvars.example must document ${name} as an immutable sha256 image digest`,
    );
  }

  for (const requiredImageReference of [
    'image = var.api_image',
    'image = var.web_image',
    'image = var.rust_engine_image',
  ]) {
    assert.ok(app.includes(requiredImageReference), `workload manifest missing ${requiredImageReference}`);
  }
}

export function validateTerraformStorageKMSInputs(variables, tfvarsExample, data) {
  for (const name of ['database_kms_key_arn', 'redis_kms_key_arn']) {
    const block = terraformVariableBlock(variables, name);
    assert.ok(
      block.includes('arn:aws:kms:') && block.includes(':key/') && block.includes(':alias/'),
      `${name} must validate customer-managed AWS KMS key or alias ARNs`,
    );
    assert.ok(
      new RegExp(`${name}\\s*=\\s*"arn:aws:kms:[^"]+:(?:key|alias)/[^"]+"`).test(tfvarsExample),
      `terraform.tfvars.example must document ${name} as a KMS key or alias ARN`,
    );
  }

  requireMatches(
    data,
    [
      /^\s*storage_encrypted\s*=\s*true/m,
      /^\s*kms_key_id\s*=\s*var\.database_kms_key_arn/m,
      /^\s*manage_master_user_password\s*=\s*true/m,
      /^\s*master_user_secret_kms_key_id\s*=\s*var\.database_kms_key_arn/m,
      /^\s*at_rest_encryption_enabled\s*=\s*true/m,
      /^\s*transit_encryption_enabled\s*=\s*true/m,
      /^\s*kms_key_id\s*=\s*var\.redis_kms_key_arn/m,
    ],
    'terraform storage KMS wiring',
  );
  assert.ok(!/^\s*master_password\s*=/m.test(data), 'RDS cluster must not receive a Terraform-managed plaintext password');
}

export function validateTerraformEKSSecretEncryption(variables, tfvarsExample, eks) {
  const block = terraformVariableBlock(variables, 'eks_secrets_kms_key_arn');
  assert.ok(
    block.includes('arn:aws:kms:') && block.includes(':key/') && block.includes(':alias/'),
    'eks_secrets_kms_key_arn must validate customer-managed AWS KMS key or alias ARNs',
  );
  assert.ok(
    /eks_secrets_kms_key_arn\s*=\s*"arn:aws:kms:[^\"]+:(?:key|alias)\/[^\"]+"/.test(tfvarsExample),
    'terraform.tfvars.example must document eks_secrets_kms_key_arn as a KMS key or alias ARN',
  );
  requireIncludes(
    eks,
    [
      'encryption_config {',
      'resources = ["secrets"]',
      'key_arn = var.eks_secrets_kms_key_arn',
    ],
    'EKS Secret envelope encryption',
  );
}

export function validateTerraformReleaseInputGuards(variables) {
  const serviceVersionBlock = terraformVariableBlock(variables, 'service_version');
  assert.ok(!/\bdefault\s*=/.test(serviceVersionBlock), 'service_version must not define a default value');
  for (const marker of ['unversioned', 'latest', 'replace-with']) {
    assert.ok(serviceVersionBlock.includes(marker), `service_version validation must reject ${marker}`);
  }

  const allowedOriginsBlock = terraformVariableBlock(variables, 'allowed_ws_origins');
  for (const marker of ['https://', 'localhost', 'example.com', '.example', '.test', '.invalid', '*']) {
    assert.ok(allowedOriginsBlock.includes(marker), `allowed_ws_origins validation must reject or require ${marker}`);
  }

  for (const hostnameVariable of ['api_hostname', 'web_hostname']) {
    const block = terraformVariableBlock(variables, hostnameVariable);
    assert.ok(
      block.includes('can(regex("^[A-Za-z0-9][A-Za-z0-9.-]+[.][A-Za-z]{2,}$",'),
      `${hostnameVariable} must validate DNS hostname shape`,
    );
    for (const marker of ['localhost', 'example.com', '.example', '.test', '.invalid']) {
      assert.ok(block.includes(marker), `${hostnameVariable} validation must reject ${marker}`);
    }
  }
}

export function validateTrustedProxyInputs(variables, tfvarsExample) {
  const headersBlock = terraformVariableBlock(variables, 'trust_proxy_headers');
  assert.match(headersBlock, /default\s*=\s*false/, 'trust_proxy_headers must default to disabled');
  assert.ok(
    headersBlock.includes('strips and overwrites caller-supplied forwarding headers'),
    'trust_proxy_headers must document the ingress overwrite contract',
  );

  const cidrBlock = terraformVariableBlock(variables, 'trusted_proxy_cidrs');
  assert.ok(cidrBlock.includes('cidrhost(cidr, 0)'), 'trusted_proxy_cidrs must validate CIDR addresses');
  assert.ok(cidrBlock.includes('10[.]') && cidrBlock.includes('192[.]168[.]'), 'trusted_proxy_cidrs must restrict IPv4 peers to private ranges');
  assert.ok(cidrBlock.includes('[Ff][Dd]'), 'trusted_proxy_cidrs must support private IPv6 peers');
  assert.match(tfvarsExample, /trusted_proxy_cidrs\s*=\s*\[\s*"10[.]0[.]0[.]0\/8"\s*\]/, 'terraform.tfvars.example must show a private trusted proxy CIDR');
}

export function validateNetworkPolicies(networkPolicy) {
  requireIncludes(
    networkPolicy,
    [
      'resource "kubernetes_network_policy" "app_default_deny"',
      'resource "kubernetes_network_policy" "api"',
      'resource "kubernetes_network_policy" "rust_engine"',
      'resource "kubernetes_network_policy" "web"',
      'policy_types = ["Ingress", "Egress"]',
      'for_each = var.allowed_ingress_cidrs',
      'kubernetes.io/metadata.name',
      'k8s-app',
      'kube-dns',
      'app.kubernetes.io/name',
      'prometheus',
      'app = "scriptureforge-api"',
      'app = "scriptureforge-rust-engine"',
      'app = "scriptureforge-web"',
      'port     = 8080',
      'port     = 50051',
      'port     = 5432',
      'port     = 6379',
      'port     = 443',
      'port     = 4317',
      'port     = 4318',
      'port     = 9102',
      'port     = 3000',
      'port     = 53',
    ],
    'terraform network policy',
  );
  assert.ok(!networkPolicy.includes('cidr = "0.0.0.0/0"'), 'network policies must not restore unrestricted egress');
  assert.ok(
    (networkPolicy.match(/for_each = var\.data_tier_cidrs/g) ?? []).length >= 2,
    'database-port egress must be scoped to declared data-tier CIDRs',
  );
  assert.ok(
    (networkPolicy.match(/cidr = egress\.value/g) ?? []).length >= 2,
    'database-port egress must include explicit destination CIDRs',
  );
}

requireIncludes(
  variables,
  [
    'variable "app_secret_arns"',
    'variable "data_tier_cidrs"',
    'database_url',
    'jwt_secret_key',
    'openai_api_key',
    'metrics_auth_token',
    'zoom_credentials',
    'grpc_engine_shared_secret',
    'grpc_engine_tls_credentials',
    'variable "grpc_engine_tls_server_name"',
    'variable "ingress_certificate_arn"',
    'variable "otel_exporter_otlp_endpoint"',
    'variable "service_version"',
    'variable "database_backup_retention_days"',
    'variable "ai_max_output_tokens"',
    'variable "database_preferred_backup_window"',
    'variable "database_preferred_maintenance_window"',
    'variable "database_kms_key_arn"',
    'variable "redis_kms_key_arn"',
    'variable "api_resources"',
    'variable "rust_engine_resources"',
    'variable "web_resources"',
    'variable "api_autoscaling"',
    'variable "rust_engine_autoscaling"',
    'variable "web_autoscaling"',
    'variable "zoom_http_timeout_ms"',
    'variable "zoom_max_retries"',
    'variable "trust_proxy_headers"',
    'variable "trusted_proxy_cidrs"',
    'variable "ai_allowed_provider_hosts"',
    'variable "trusted_proxy_cidrs"',
    'variable "ai_allowed_provider_hosts"',
  ],
  'terraform variables',
);

requireIncludes(
  versions,
  [
    'backend "s3"',
    'hashicorp/aws',
    'hashicorp/kubernetes',
  ],
  'terraform versions',
);

requireIncludes(
  backendExample,
  ['bucket', 'key', 'region', 'dynamodb_table', 'encrypt'],
  'backend.hcl.example',
);

requireIncludes(
  iam,
  [
    'aws_iam_openid_connect_provider',
    'data "aws_iam_policy_document" "app_secrets_assume_role"',
    'data "aws_iam_policy_document" "rust_engine_secrets_assume_role"',
    'data "aws_iam_policy_document" "rust_engine_secrets_read"',
    'secretsmanager:GetSecretValue',
    'data.aws_secretsmanager_secret.database_url.arn',
    'data.aws_secretsmanager_secret.jwt_secret_key.arn',
    'data.aws_secretsmanager_secret.openai_api_key.arn',
    'data.aws_secretsmanager_secret.metrics_auth_token.arn',
    'data.aws_secretsmanager_secret.zoom_credentials.arn',
    'data.aws_secretsmanager_secret.grpc_engine_shared_secret.arn',
    'data.aws_secretsmanager_secret.grpc_engine_tls_credentials.arn',
    'resource "aws_iam_role" "rust_engine_secrets"',
    'resource "aws_iam_role_policy_attachment" "rust_engine_secrets_read"',
  ],
  'terraform IAM',
);

requireIncludes(
  app,
  [
    'resource "kubernetes_service_account" "workload"',
    'resource "kubernetes_service_account" "rust_engine"',
    '"eks.amazonaws.com/role-arn" = aws_iam_role.app_secrets.arn',
    '"eks.amazonaws.com/role-arn" = aws_iam_role.rust_engine_secrets.arn',
    'kind       = "SecretProviderClass"',
    'provider = "aws"',
    'secretName = "scriptureforge-runtime-secrets"',
    'secretName = "scriptureforge-rust-runtime-secrets"',
    'name      = "scriptureforge-rust-secrets"',
    'driver    = "secrets-store.csi.k8s.io"',
    'service_account_name = kubernetes_service_account.workload.metadata[0].name',
    'service_account_name = kubernetes_service_account.rust_engine.metadata[0].name',
    'secretProviderClass = kubernetes_manifest.rust_secret_provider.manifest.metadata.name',
    'topology_spread_constraint',
    'topology_key       = "topology.kubernetes.io/zone"',
    'when_unsatisfiable = "ScheduleAnyway"',
    'resource "kubernetes_pod_disruption_budget_v1" "api"',
    'resource "kubernetes_pod_disruption_budget_v1" "rust_engine"',
    'resource "kubernetes_pod_disruption_budget_v1" "web"',
    'resource "kubernetes_horizontal_pod_autoscaler_v2" "api"',
    'resource "kubernetes_horizontal_pod_autoscaler_v2" "rust_engine"',
    'resource "kubernetes_horizontal_pod_autoscaler_v2" "web"',
    'min_available = 1',
    'scale_target_ref',
    'average_utilization = var.api_autoscaling.target_cpu_utilization_percentage',
    'average_utilization = var.api_autoscaling.target_memory_utilization_percentage',
    'average_utilization = var.rust_engine_autoscaling.target_cpu_utilization_percentage',
    'average_utilization = var.rust_engine_autoscaling.target_memory_utilization_percentage',
    'average_utilization = var.web_autoscaling.target_cpu_utilization_percentage',
    'average_utilization = var.web_autoscaling.target_memory_utilization_percentage',
    'requests = var.api_resources.requests',
    'limits   = var.api_resources.limits',
    'requests = var.rust_engine_resources.requests',
    'limits   = var.rust_engine_resources.limits',
    'requests = var.web_resources.requests',
    'limits   = var.web_resources.limits',
    'name = "DATABASE_URL"',
    'name = "JWT_SECRET_KEY"',
    'name = "JOURNAL_SALT_SECRET"',
    'name = "OPENAI_API_KEY"',
    'name = "METRICS_AUTH_TOKEN"',
    'name = "ZOOM_ACCOUNT_ID"',
    'name = "ZOOM_CLIENT_ID"',
    'name = "ZOOM_CLIENT_SECRET"',
    'name = "ZOOM_WEBHOOK_SECRET_TOKEN"',
    'name  = "ZOOM_HTTP_TIMEOUT_MS"',
    'name  = "ZOOM_MAX_RETRIES"',
    'name = "GRPC_ENGINE_SHARED_SECRET"',
    'name = "GRPC_ENGINE_TLS_CA_PEM"',
    'name = "GRPC_ENGINE_TLS_CERT_PEM"',
    'name = "GRPC_ENGINE_TLS_KEY_PEM"',
    'name = "GRPC_ENGINE_TLS_CLIENT_CERT_PEM"',
    'name = "GRPC_ENGINE_TLS_CLIENT_KEY_PEM"',
    'name  = "GRPC_ENGINE_TLS_SERVER_NAME"',
    'name  = "REDIS_URL"',
    'rediss://${aws_elasticache_replication_group.redis.primary_endpoint_address}:6379',
    'name  = "GRPC_ENGINE_ADDRESS"',
    'scriptureforge-rust-engine:50051',
    'name  = "TRUST_PROXY_HEADERS"',
    'value = tostring(var.trust_proxy_headers)',
    'name  = "TRUSTED_PROXY_CIDRS"',
    'value = join(",", var.trusted_proxy_cidrs)',
    'name  = "AI_ALLOWED_PROVIDER_HOSTS"',
    'name  = "AI_MAX_OUTPUT_TOKENS"',
    'value = join(",", var.ai_allowed_provider_hosts)',
    'name  = "TRUSTED_PROXY_CIDRS"',
    'value = join(",", var.trusted_proxy_cidrs)',
    'name  = "AI_ALLOWED_PROVIDER_HOSTS"',
    'value = join(",", var.ai_allowed_provider_hosts)',
    'name  = "OTEL_SERVICE_NAME"',
    'scriptureforge-rust-engine',
    'name  = "SERVICE_VERSION"',
    'name  = "DEPLOYMENT_ENVIRONMENT"',
    'name  = "OTEL_EXPORTER_OTLP_ENDPOINT"',
    'name  = "OTEL_EXPORTER_OTLP_INSECURE"',
    'path = "/live"',
    'path = "/ready"',
    'path = "/healthz"',
    'port = 9102',
    'name  = "RUST_ENGINE_BIND_ADDRESS"',
    'value = "0.0.0.0:50051"',
    'name  = "RUST_ENGINE_METRICS_ADDRESS"',
    'value = "0.0.0.0:9102"',
    'NEXT_PUBLIC_API_BASE_URL',
  ],
  'terraform app skeleton',
);

requireMatches(
  app,
  [
    /revision_history_limit\s*=\s*10/g,
    /progress_deadline_seconds\s*=\s*600/g,
    /min_ready_seconds\s*=\s*5/g,
    /type\s*=\s*"RollingUpdate"/g,
    /max_surge\s*=\s*"1"/g,
    /max_unavailable\s*=\s*"0"/g,
  ],
  'terraform app rollout settings',
);

const data = await readTerraform('data.tf');
requireIncludes(
  data,
  [
    'backup_retention_period      = var.database_backup_retention_days',
    'preferred_backup_window      = var.database_preferred_backup_window',
    'preferred_maintenance_window = var.database_preferred_maintenance_window',
    'copy_tags_to_snapshot        = true',
    'enabled_cloudwatch_logs_exports',
    '"postgresql"',
    'deletion_protection       = true',
    'skip_final_snapshot       = false',
    'final_snapshot_identifier = "${local.name_prefix}-postgres-final"',
  ],
  'terraform data skeleton',
);

requireIncludes(
  service,
  [
    'resource "kubernetes_ingress_v1" "api"',
    'resource "kubernetes_ingress_v1" "web"',
    'name        = "metrics"',
    'port        = 9102',
    '"alb.ingress.kubernetes.io/listen-ports"             = "[{\\"HTTP\\":80},{\\"HTTPS\\":443}]"',
    '"alb.ingress.kubernetes.io/certificate-arn"          = var.ingress_certificate_arn',
    '"alb.ingress.kubernetes.io/ssl-policy"               = var.ingress_ssl_policy',
    '"alb.ingress.kubernetes.io/ssl-redirect"             = "443"',
    '"alb.ingress.kubernetes.io/healthcheck-path"         = "/ready"',
    '"alb.ingress.kubernetes.io/load-balancer-attributes" = "routing.http2.enabled=true"',
    'host = var.api_hostname',
    'host = var.web_hostname',
  ],
  'terraform service skeleton',
);

requireIncludes(
  tfvarsExample,
  [
    'api_image',
    'web_image',
    'rust_engine_image',
    'api_autoscaling',
    'rust_engine_autoscaling',
    'web_autoscaling',
    'app_secret_arns',
    'database_url',
    'ingress_certificate_arn',
    'otel_exporter_otlp_endpoint',
    'database_backup_retention_days',
    'database_preferred_backup_window',
    'database_preferred_maintenance_window',
    'database_kms_key_arn',
    'data_tier_cidrs',
    'redis_kms_key_arn',
    'eks_secrets_kms_key_arn',
  ],
  'terraform.tfvars.example',
);

validateTerraformSecretInputs(variables, tfvarsExample, app);
validateWorkloadSecretSeparation(app);
validateTerraformImageDigestInputs(variables, tfvarsExample, app);
validateTerraformStorageKMSInputs(variables, tfvarsExample, data);
validateTerraformEKSSecretEncryption(variables, tfvarsExample, eks);
validateTerraformReleaseInputGuards(variables);
validateTrustedProxyInputs(variables, tfvarsExample);
validateNetworkPolicies(networkPolicy);
assert.ok(!tfvarsExample.includes('skip_final_snapshot = true'), 'tfvars example must not preserve production-hostile snapshot defaults');

validatePlatformRuntimeConfig(platformMain);
validateMetricsAuthentication(metricsSecurity);
validateContainerBuildDefinitions(apiContainer, rustContainer, webContainer);
validateLocalComposeConfig(compose);
validateDatabaseTransportConfig(platformMain, rustMain);

console.log(`deployment skeleton and runtime config invariants validated: ${deploymentSkeletonProofMarkers.join(', ')}`);
