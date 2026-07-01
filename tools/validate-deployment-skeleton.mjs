import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const terraformDir = new URL('../build/terraform/', import.meta.url);
const platformEngineMain = new URL('../cmd/platform-engine/main.go', import.meta.url);

export const deploymentSkeletonProofMarkers = [
  'remote_state_backend=true',
  'irsa_secret_access=true',
  'secretproviderclass_sync=true',
  'database_root_secret_no_default=true',
  'workload_secret_inputs_are_arns=true',
  'tls_ingress=true',
  'rds_backup_final_snapshot=true',
  'redis_runtime_wiring=true',
  'grpc_engine_wiring=true',
  'otel_runtime_wiring=true',
  'hpa_pdb_rollout_safety=true',
  'root_database_url_absent=true',
];

async function readTerraform(name) {
  return readFile(new URL(name, terraformDir), 'utf8');
}

const [app, service, variables, iam, versions, tfvarsExample, backendExample] = await Promise.all([
  readTerraform('app.tf'),
  readTerraform('service.tf'),
  readTerraform('variables.tf'),
  readTerraform('iam.tf'),
  readTerraform('versions.tf'),
  readTerraform('terraform.tfvars.example'),
  readTerraform('backend.hcl.example'),
]);
const platformMain = await readFile(platformEngineMain, 'utf8');

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
    ],
    'platform engine runtime config',
  );
  assert.ok(
    /case "staging", "production", "prod":\s*\n\s*return true/.test(platformMain),
    'platform engine must require explicit GRPC_ENGINE_ADDRESS for staging/production/prod',
  );
}

function terraformVariableBlock(source, name) {
  const start = source.indexOf(`variable "${name}"`);
  assert.ok(start >= 0, `terraform variables missing ${name}`);
  const next = source.indexOf('\nvariable "', start + 1);
  return source.slice(start, next >= 0 ? next : source.length);
}

export function validateTerraformSecretInputs(variables, tfvarsExample, app) {
  const rootSecretBlock = terraformVariableBlock(variables, 'database_root_security_passphrase');
  assert.ok(rootSecretBlock.includes('sensitive   = true'), 'database root passphrase must be marked sensitive');
  assert.ok(!/\bdefault\s*=/.test(rootSecretBlock), 'database root passphrase must not define a default value');
  assert.ok(
    /length\(var\.database_root_security_passphrase\)\s*>=\s*16/.test(rootSecretBlock),
    'database root passphrase must keep a minimum length validation',
  );

  const secretARNBlock = terraformVariableBlock(variables, 'app_secret_arns');
  for (const key of ['database_url', 'jwt_secret_key', 'openai_api_key', 'zoom_credentials']) {
    assert.ok(secretARNBlock.includes(`${key}     = string`) || secretARNBlock.includes(`${key}   = string`) || secretARNBlock.includes(`${key} = string`), `app_secret_arns missing ${key}`);
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

requireIncludes(
  variables,
  [
    'variable "app_secret_arns"',
    'database_url',
    'jwt_secret_key',
    'openai_api_key',
    'zoom_credentials',
    'variable "ingress_certificate_arn"',
    'variable "otel_exporter_otlp_endpoint"',
    'variable "service_version"',
    'variable "database_backup_retention_days"',
    'variable "database_preferred_backup_window"',
    'variable "database_preferred_maintenance_window"',
    'variable "api_resources"',
    'variable "rust_engine_resources"',
    'variable "web_resources"',
    'variable "api_autoscaling"',
    'variable "rust_engine_autoscaling"',
    'variable "web_autoscaling"',
    'variable "trust_proxy_headers"',
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
    'secretsmanager:GetSecretValue',
    'data.aws_secretsmanager_secret.database_url.arn',
    'data.aws_secretsmanager_secret.jwt_secret_key.arn',
    'data.aws_secretsmanager_secret.openai_api_key.arn',
    'data.aws_secretsmanager_secret.zoom_credentials.arn',
  ],
  'terraform IAM',
);

requireIncludes(
  app,
  [
    'resource "kubernetes_service_account" "workload"',
    '"eks.amazonaws.com/role-arn" = aws_iam_role.app_secrets.arn',
    'kind       = "SecretProviderClass"',
    'provider = "aws"',
    'secretName = "scriptureforge-runtime-secrets"',
    'driver    = "secrets-store.csi.k8s.io"',
    'service_account_name = kubernetes_service_account.workload.metadata[0].name',
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
    'name = "OPENAI_API_KEY"',
    'name = "ZOOM_ACCOUNT_ID"',
    'name = "ZOOM_CLIENT_ID"',
    'name = "ZOOM_CLIENT_SECRET"',
    'name = "ZOOM_WEBHOOK_SECRET_TOKEN"',
    'name  = "REDIS_URL"',
    'rediss://${aws_elasticache_replication_group.redis.primary_endpoint_address}:6379',
    'name  = "GRPC_ENGINE_ADDRESS"',
    'scriptureforge-rust-engine:50051',
    'name  = "TRUST_PROXY_HEADERS"',
    'value = tostring(var.trust_proxy_headers)',
    'name  = "OTEL_SERVICE_NAME"',
    'scriptureforge-rust-engine',
    'name  = "SERVICE_VERSION"',
    'name  = "DEPLOYMENT_ENVIRONMENT"',
    'name  = "OTEL_EXPORTER_OTLP_ENDPOINT"',
    'name  = "OTEL_EXPORTER_OTLP_INSECURE"',
    'path = "/live"',
    'path = "/ready"',
    'grpc {',
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
  ],
  'terraform.tfvars.example',
);

validateTerraformSecretInputs(variables, tfvarsExample, app);
assert.ok(!tfvarsExample.includes('skip_final_snapshot = true'), 'tfvars example must not preserve production-hostile snapshot defaults');

validatePlatformRuntimeConfig(platformMain);

console.log(`deployment skeleton and runtime config invariants validated: ${deploymentSkeletonProofMarkers.join(', ')}`);
