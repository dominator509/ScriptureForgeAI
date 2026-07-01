package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const apiImageDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const webImageDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const rustImageDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
const terraformStateKMSKeyID = "alias/scriptureforge-terraform-state"
const databaseKMSKeyARN = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"
const redisKMSKeyARN = "arn:aws:kms:us-east-1:123456789012:key/22222222-2222-4222-8222-222222222222"
const deploymentLoadRunID = "staging-deploy-run-123"
const deploymentLoadRunMarker = "load_run_id=" + deploymentLoadRunID
const rolloutReleaseMarkers = " release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1 " + deploymentLoadRunMarker

func stagingDeploymentConfig(timeout time.Duration) config {
	return config{
		ProbeTerraform:    true,
		ProbeKubernetes:   true,
		TerraformInitURL:  "https://deployment-artifacts.staging.scriptureforge.ai/deploy/tf-init",
		TerraformPlanURL:  "https://deployment-artifacts.staging.scriptureforge.ai/deploy/tf-plan",
		TerraformApplyURL: "https://deployment-artifacts.staging.scriptureforge.ai/deploy/tf-apply",
		K8SRolloutURL:     "https://deployment-artifacts.staging.scriptureforge.ai/deploy/rollout",
		K8SResourcesURL:   "https://deployment-artifacts.staging.scriptureforge.ai/deploy/resources",
		ReleaseCandidate:  "0123456789abcdef0123456789abcdef01234567",
		ServiceVersion:    "2026.06.27.1",
		LoadRunID:         deploymentLoadRunID,
		Timeout:           timeout,
	}
}

func TestRunRequiresProbeMode(t *testing.T) {
	var output bytes.Buffer
	err := run(config{Timeout: time.Second}, &output)
	if err == nil || !strings.Contains(err.Error(), "probe-terraform") {
		t.Fatalf("expected probe mode error, got %v", err)
	}
}

func TestRunEmitsTerraformAndKubernetesEvidenceWhenArtifactsPass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tf-init":
			_, _ = w.Write([]byte("terraform backend s3 bucket scriptureforge-state key staging/terraform.tfstate encrypt=true kms_key_id=" + terraformStateKMSKeyID + " versioning=enabled dynamodb_table scriptureforge-locks successfully initialized release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1 " + deploymentLoadRunMarker))
		case "/tf-plan":
			_, _ = w.Write([]byte("Terraform Plan: aws_eks_cluster aws_eks_node_group aws_rds_cluster aws_elasticache_replication_group aws_ecr_repository kubernetes_deployment kubernetes_ingress_v1 kubernetes_horizontal_pod_autoscaler_v2 kubernetes_pod_disruption_budget_v1 kubernetes_manifest aws_iam_role kms_key_id=" + terraformStateKMSKeyID + " database_kms_key_arn=" + databaseKMSKeyARN + " redis_kms_key_arn=" + redisKMSKeyARN + " release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1 " + deploymentLoadRunMarker))
		case "/tf-apply":
			_, _ = w.Write([]byte("Apply complete! Resources: 42 added, 0 changed, 0 destroyed. release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1 " + deploymentLoadRunMarker))
		case "/rollout":
			_, _ = w.Write([]byte("namespace staging deployment scriptureforge-api successfully rolled out ready available; deployment scriptureforge-web successfully rolled out ready available; deployment scriptureforge-rust-engine successfully rolled out ready available" + rolloutReleaseMarkers))
		case "/resources":
			_, _ = w.Write([]byte("namespace staging deployment service ingress hpa pdb ready available targets minAvailable readinessProbe livenessProbe rollingUpdate maxUnavailable=0 minReplicas maxReplicas tls SecretProviderClass image ghcr.io/scriptureforge/api@" + apiImageDigest + " ghcr.io/scriptureforge/web@" + webImageDigest + " ghcr.io/scriptureforge/rust-engine@" + rustImageDigest + " release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1 " + deploymentLoadRunMarker + " scriptureforge-api scriptureforge-web scriptureforge-rust-engine"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingDeploymentConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err != nil {
		t.Fatalf("deployment probe failed: %v\n%s", err, output.String())
	}
	var result report
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	if !result.ThresholdPass {
		t.Fatalf("expected threshold pass: %+v", result)
	}
	if result.ReleaseCandidate != "0123456789abcdef0123456789abcdef01234567" || result.ServiceVersion != "2026.06.27.1" || result.LoadRunID != deploymentLoadRunID {
		t.Fatalf("report missing exact release linkage: %+v", result)
	}
	if !containsItem(result.EvidenceItems, "DEPLOY-TF-001") || !containsItem(result.EvidenceItems, "DEPLOY-K8S-001") {
		t.Fatalf("missing deployment evidence items: %+v", result.EvidenceItems)
	}
	expectedMarkers := map[string][]string{
		"terraform-remote-backend-init":       {"staging artifact", "terraform", "s3", "backend", "bucket", "key", "encrypt=true", "kms_key_id=" + terraformStateKMSKeyID, "versioning=enabled", "dynamodb_table", "successfully initialized", "release_candidate=0123456789abcdef0123456789abcdef01234567", "service_version=2026.06.27.1", deploymentLoadRunMarker},
		"terraform-staging-plan":              {"staging artifact", "Terraform", "Plan:", "aws_eks_cluster", "aws_eks_node_group", "aws_rds_cluster", "aws_ecr_repository", "kubernetes_deployment", "kubernetes_ingress_v1", "kubernetes_horizontal_pod_autoscaler_v2", "kubernetes_pod_disruption_budget_v1", "kubernetes_manifest", "aws_iam_role", "kms_key_id=" + terraformStateKMSKeyID, "database_kms_key_arn=" + databaseKMSKeyARN, "redis_kms_key_arn=" + redisKMSKeyARN, "release_candidate=0123456789abcdef0123456789abcdef01234567", "service_version=2026.06.27.1", deploymentLoadRunMarker},
		"terraform-staging-apply-or-approval": {"staging artifact", "Apply complete", "Resources:", "0 destroyed", "release_candidate=0123456789abcdef0123456789abcdef01234567", "service_version=2026.06.27.1", deploymentLoadRunMarker, "distinct_terraform_artifacts=true"},
		"kubernetes-rollout-status":           {"staging artifact", "namespace", "staging", "deployment", "scriptureforge-api", "scriptureforge-web", "scriptureforge-rust-engine", "successfully rolled out", "ready", "available", "release_candidate=0123456789abcdef0123456789abcdef01234567", "service_version=2026.06.27.1", deploymentLoadRunMarker},
		"kubernetes-workload-resources":       {"staging artifact", "namespace", "staging", "deployment", "service", "ingress", "hpa", "pdb", "ready", "available", "targets", "minavailable", "readinessProbe", "livenessProbe", "rollingUpdate", "maxUnavailable=0", "minReplicas", "maxReplicas", "tls", "SecretProviderClass", "image", "sha256:", "scriptureforge-api@" + apiImageDigest, "scriptureforge-web@" + webImageDigest, "scriptureforge-rust-engine@" + rustImageDigest, "concrete_image_digests=3", "workload_image_digests=3", "distinct_kubernetes_artifacts=true", "release_candidate=0123456789abcdef0123456789abcdef01234567", "service_version=2026.06.27.1", deploymentLoadRunMarker, "scriptureforge-api", "scriptureforge-web", "scriptureforge-rust-engine"},
	}
	for _, probe := range result.Probes {
		for _, marker := range expectedMarkers[probe.Name] {
			if !strings.Contains(probe.ResultSummary, marker) {
				t.Fatalf("probe %s summary missing marker %q: %s", probe.Name, marker, probe.ResultSummary)
			}
		}
		if probe.Name == "terraform-remote-backend-init" && probe.TerraformStateKMSKey != terraformStateKMSKeyID {
			t.Fatalf("terraform init omitted structured state KMS key: %+v", probe)
		}
		if probe.Name == "terraform-staging-plan" {
			if probe.TerraformStateKMSKey != terraformStateKMSKeyID || probe.DatabaseKMSKeyARN != databaseKMSKeyARN || probe.RedisKMSKeyARN != redisKMSKeyARN {
				t.Fatalf("terraform plan omitted structured KMS bindings: %+v", probe)
			}
		}
		if probe.Name == "kubernetes-workload-resources" {
			if probe.ConcreteImageDigests != 3 || probe.WorkloadImageDigests != 3 {
				t.Fatalf("workload resources omitted structured digest counts: %+v", probe)
			}
			expectedDigests := map[string]string{
				"scriptureforge-api":         apiImageDigest,
				"scriptureforge-web":         webImageDigest,
				"scriptureforge-rust-engine": rustImageDigest,
			}
			for workload, digest := range expectedDigests {
				if probe.ImageDigests[workload] != digest {
					t.Fatalf("workload resources omitted structured digest for %s: %+v", workload, probe.ImageDigests)
				}
			}
		}
	}
}

func TestRunRejectsDuplicateTerraformArtifactURLs(t *testing.T) {
	cfg := stagingDeploymentConfig(time.Second)
	cfg.ProbeKubernetes = false
	cfg.TerraformPlanURL = cfg.TerraformInitURL

	var output bytes.Buffer
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "-terraform-plan-url must be a distinct artifact URL from -terraform-init-url") {
		t.Fatalf("expected duplicate Terraform artifact URL rejection, got %v", err)
	}
}

func TestRunRejectsCanonicalDuplicateTerraformArtifactURLs(t *testing.T) {
	cfg := stagingDeploymentConfig(time.Second)
	cfg.ProbeKubernetes = false
	cfg.TerraformInitURL = "https://DEPLOYMENT-ARTIFACTS.staging.scriptureforge.ai:443/tf-shared?b=2&a=1"
	cfg.TerraformPlanURL = "https://deployment-artifacts.staging.scriptureforge.ai/tf-shared?a=1&b=2"

	var output bytes.Buffer
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "-terraform-plan-url must be a distinct artifact URL from -terraform-init-url") {
		t.Fatalf("expected canonical duplicate Terraform artifact URL rejection, got %v", err)
	}
}

func TestRunRejectsDuplicateKubernetesArtifactURLs(t *testing.T) {
	cfg := stagingDeploymentConfig(time.Second)
	cfg.ProbeTerraform = false
	cfg.K8SResourcesURL = cfg.K8SRolloutURL

	var output bytes.Buffer
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "-k8s-resources-url must be a distinct artifact URL from -k8s-rollout-url") {
		t.Fatalf("expected duplicate Kubernetes artifact URL rejection, got %v", err)
	}
}

func TestRunRejectsCanonicalDuplicateKubernetesArtifactURLs(t *testing.T) {
	cfg := stagingDeploymentConfig(time.Second)
	cfg.ProbeTerraform = false
	cfg.K8SRolloutURL = "https://DEPLOYMENT-ARTIFACTS.staging.scriptureforge.ai:443/deploy/k8s-shared?b=2&a=1"
	cfg.K8SResourcesURL = "https://deployment-artifacts.staging.scriptureforge.ai/deploy/k8s-shared?a=1&b=2"

	var output bytes.Buffer
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "-k8s-resources-url must be a distinct artifact URL from -k8s-rollout-url") {
		t.Fatalf("expected canonical duplicate Kubernetes artifact URL rejection, got %v", err)
	}
}

func TestRunRequiresReleaseCandidateAndServiceVersion(t *testing.T) {
	cfg := stagingDeploymentConfig(time.Second)
	cfg.ReleaseCandidate = ""
	var output bytes.Buffer
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "release-candidate, service-version, and load-run-id") {
		t.Fatalf("expected release metadata requirement, got %v", err)
	}
}

func TestRunRequiresLoadRunID(t *testing.T) {
	cfg := stagingDeploymentConfig(time.Second)
	cfg.LoadRunID = ""
	var output bytes.Buffer
	err := runWithClient(cfg, &output, http.DefaultClient)
	if err == nil || !strings.Contains(err.Error(), "release-candidate, service-version, and load-run-id") {
		t.Fatalf("expected load run metadata requirement, got %v", err)
	}
}

func TestRunFailsWhenDeploymentArtifactsUseDifferentLoadRunID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tf-init":
			_, _ = w.Write([]byte("terraform backend s3 bucket scriptureforge-state key staging/terraform.tfstate encrypt=true kms_key_id=alias/scriptureforge-terraform-state versioning=enabled dynamodb_table scriptureforge-locks successfully initialized release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1 " + deploymentLoadRunMarker))
		case "/tf-plan":
			_, _ = w.Write([]byte("Terraform Plan: aws_eks_cluster aws_eks_node_group aws_rds_cluster aws_elasticache_replication_group aws_ecr_repository kubernetes_deployment kubernetes_ingress_v1 kubernetes_horizontal_pod_autoscaler_v2 kubernetes_pod_disruption_budget_v1 kubernetes_manifest aws_iam_role kms_key_id=" + terraformStateKMSKeyID + " database_kms_key_arn=" + databaseKMSKeyARN + " redis_kms_key_arn=" + redisKMSKeyARN + " release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1 " + deploymentLoadRunMarker))
		case "/tf-apply":
			_, _ = w.Write([]byte("Apply complete! Resources: 42 added, 0 changed, 0 destroyed. release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1 load_run_id=staging-deploy-run-999"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingDeploymentConfig(time.Second)
	cfg.ProbeKubernetes = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected mismatched deployment load run artifacts to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "terraform-staging-apply-or-approval") {
		t.Fatalf("report did not identify load-run-bound probe:\n%s", output.String())
	}
}

func TestRunFailsWhenDeploymentArtifactsUseDifferentReleaseCandidate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tf-init":
			_, _ = w.Write([]byte("terraform backend s3 bucket scriptureforge-state key staging/terraform.tfstate encrypt=true kms_key_id=alias/scriptureforge-terraform-state versioning=enabled dynamodb_table scriptureforge-locks successfully initialized release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1"))
		case "/tf-plan":
			_, _ = w.Write([]byte("Terraform Plan: aws_eks_cluster aws_eks_node_group aws_rds_cluster aws_elasticache_replication_group aws_ecr_repository kubernetes_deployment kubernetes_ingress_v1 kubernetes_horizontal_pod_autoscaler_v2 kubernetes_pod_disruption_budget_v1 kubernetes_manifest aws_iam_role kms_key_id=" + terraformStateKMSKeyID + " database_kms_key_arn=" + databaseKMSKeyARN + " redis_kms_key_arn=" + redisKMSKeyARN + " release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1"))
		case "/tf-apply":
			_, _ = w.Write([]byte("Apply complete! Resources: 42 added, 0 changed, 0 destroyed. release_candidate=fedcba9876543210fedcba9876543210fedcba98 service_version=2026.06.27.1"))
		case "/rollout":
			_, _ = w.Write([]byte("namespace staging deployment scriptureforge-api successfully rolled out ready available; deployment scriptureforge-web successfully rolled out ready available; deployment scriptureforge-rust-engine successfully rolled out ready available" + rolloutReleaseMarkers))
		case "/resources":
			_, _ = w.Write([]byte("namespace staging deployment service ingress hpa pdb ready available targets minAvailable readinessProbe livenessProbe rollingUpdate maxUnavailable=0 minReplicas maxReplicas tls SecretProviderClass image ghcr.io/scriptureforge/api@" + apiImageDigest + " ghcr.io/scriptureforge/web@" + webImageDigest + " ghcr.io/scriptureforge/rust-engine@" + rustImageDigest + " release_candidate=fedcba9876543210fedcba9876543210fedcba98 service_version=2026.06.27.1 scriptureforge-api scriptureforge-web scriptureforge-rust-engine"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runWithClient(stagingDeploymentConfig(time.Second), &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected stale release candidate artifacts to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "terraform-staging-apply-or-approval") || !strings.Contains(output.String(), "kubernetes-workload-resources") {
		t.Fatalf("report did not identify release-bound probes:\n%s", output.String())
	}
}

func TestRunFailsWhenTerraformInitAndPlanOmitReleaseLinkage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tf-init":
			_, _ = w.Write([]byte("terraform backend s3 bucket scriptureforge-state key staging/terraform.tfstate encrypt=true kms_key_id=alias/scriptureforge-terraform-state versioning=enabled dynamodb_table scriptureforge-locks successfully initialized"))
		case "/tf-plan":
			_, _ = w.Write([]byte("Terraform Plan: aws_eks_cluster aws_eks_node_group aws_rds_cluster aws_elasticache_replication_group aws_ecr_repository kubernetes_deployment kubernetes_ingress_v1 kubernetes_horizontal_pod_autoscaler_v2 kubernetes_pod_disruption_budget_v1 kubernetes_manifest aws_iam_role"))
		case "/tf-apply":
			_, _ = w.Write([]byte("Apply complete! Resources: 42 added, 0 changed, 0 destroyed. release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingDeploymentConfig(time.Second)
	cfg.ProbeKubernetes = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected Terraform init/plan artifacts without release linkage to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "terraform-remote-backend-init") || !strings.Contains(output.String(), "terraform-staging-plan") {
		t.Fatalf("report did not identify release-bound init/plan probes:\n%s", output.String())
	}
}

func TestRunFailsWhenDeploymentArtifactsAreMarkedMockOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rollout":
			_, _ = w.Write([]byte("mock namespace staging deployment scriptureforge-api successfully rolled out ready available; deployment scriptureforge-web successfully rolled out ready available; deployment scriptureforge-rust-engine successfully rolled out ready available" + rolloutReleaseMarkers))
		case "/resources":
			_, _ = w.Write([]byte("namespace staging deployment service ingress hpa pdb ready available targets minAvailable readinessProbe livenessProbe rollingUpdate maxUnavailable=0 minReplicas maxReplicas tls SecretProviderClass image ghcr.io/scriptureforge/api@" + apiImageDigest + " ghcr.io/scriptureforge/web@" + webImageDigest + " ghcr.io/scriptureforge/rust-engine@" + rustImageDigest + " release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1 scriptureforge-api scriptureforge-web scriptureforge-rust-engine"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingDeploymentConfig(time.Second)
	cfg.ProbeTerraform = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected mock deployment artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "forbidden local/mock/failure markers") {
		t.Fatalf("report did not explain weak deployment artifact rejection:\n%s", output.String())
	}
}

func TestRunFailsWhenDeploymentArtifactsAdmitFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rollout":
			_, _ = w.Write([]byte("namespace staging deployment scriptureforge-api successfully rolled out ready available; deployment scriptureforge-web successfully rolled out ready available; deployment scriptureforge-rust-engine successfully rolled out ready available" + rolloutReleaseMarkers + "; rollout failed"))
		case "/resources":
			_, _ = w.Write([]byte("namespace staging deployment service ingress hpa pdb ready available targets minAvailable readinessProbe livenessProbe rollingUpdate maxUnavailable=0 minReplicas maxReplicas tls SecretProviderClass image ghcr.io/scriptureforge/api@" + apiImageDigest + " ghcr.io/scriptureforge/web@" + webImageDigest + " ghcr.io/scriptureforge/rust-engine@" + rustImageDigest + " release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1 scriptureforge-api scriptureforge-web scriptureforge-rust-engine"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingDeploymentConfig(time.Second)
	cfg.ProbeTerraform = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected contradictory deployment artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "kubernetes-rollout-status") || !strings.Contains(output.String(), "forbidden local/mock/failure markers") {
		t.Fatalf("report did not explain contradictory deployment artifact rejection:\n%s", output.String())
	}
}

func TestRunFailsWhenKubernetesRolloutOmitsReleaseLinkage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rollout":
			_, _ = w.Write([]byte("namespace staging deployment scriptureforge-api successfully rolled out ready available; deployment scriptureforge-web successfully rolled out ready available; deployment scriptureforge-rust-engine successfully rolled out ready available"))
		case "/resources":
			_, _ = w.Write([]byte("namespace staging deployment service ingress hpa pdb ready available targets minAvailable readinessProbe livenessProbe rollingUpdate maxUnavailable=0 minReplicas maxReplicas tls SecretProviderClass image ghcr.io/scriptureforge/api@" + apiImageDigest + " ghcr.io/scriptureforge/web@" + webImageDigest + " ghcr.io/scriptureforge/rust-engine@" + rustImageDigest + " release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1 scriptureforge-api scriptureforge-web scriptureforge-rust-engine"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingDeploymentConfig(time.Second)
	cfg.ProbeTerraform = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected Kubernetes rollout without release linkage to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "kubernetes-rollout-status") {
		t.Fatalf("report did not identify weak rollout artifact:\n%s", output.String())
	}
}

func TestRunFailsWhenTerraformInitUsesBackendFalse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tf-init":
			_, _ = w.Write([]byte("terraform init -backend=false local backend successfully initialized"))
		case "/tf-plan":
			_, _ = w.Write([]byte("Terraform Plan: aws_eks_cluster aws_eks_node_group aws_rds_cluster aws_elasticache_replication_group aws_ecr_repository kubernetes_deployment kubernetes_ingress_v1 kubernetes_horizontal_pod_autoscaler_v2 kubernetes_pod_disruption_budget_v1 kubernetes_manifest aws_iam_role kms_key_id=" + terraformStateKMSKeyID + " database_kms_key_arn=" + databaseKMSKeyARN + " redis_kms_key_arn=" + redisKMSKeyARN + " release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1"))
		case "/tf-apply":
			_, _ = w.Write([]byte("Apply complete! Resources: 42 added, 0 changed, 0 destroyed. release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingDeploymentConfig(time.Second)
	cfg.ProbeKubernetes = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected backend=false init artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": false`) {
		t.Fatalf("failing report did not mark threshold false:\n%s", output.String())
	}
}

func TestRunFailsWhenTerraformInitOmitsKMSAndVersioningProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tf-init":
			_, _ = w.Write([]byte("terraform backend s3 bucket scriptureforge-state key staging/terraform.tfstate encrypt=true dynamodb_table scriptureforge-locks successfully initialized release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1 " + deploymentLoadRunMarker))
		case "/tf-plan":
			_, _ = w.Write([]byte("Terraform Plan: aws_eks_cluster aws_eks_node_group aws_rds_cluster aws_elasticache_replication_group aws_ecr_repository kubernetes_deployment kubernetes_ingress_v1 kubernetes_horizontal_pod_autoscaler_v2 kubernetes_pod_disruption_budget_v1 kubernetes_manifest aws_iam_role kms_key_id=" + terraformStateKMSKeyID + " database_kms_key_arn=" + databaseKMSKeyARN + " redis_kms_key_arn=" + redisKMSKeyARN + " release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1 " + deploymentLoadRunMarker))
		case "/tf-apply":
			_, _ = w.Write([]byte("Apply complete! Resources: 42 added, 0 changed, 0 destroyed. release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1 " + deploymentLoadRunMarker))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingDeploymentConfig(time.Second)
	cfg.ProbeKubernetes = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected init artifact without KMS/versioning proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "terraform-remote-backend-init") {
		t.Fatalf("report did not identify weak init artifact:\n%s", output.String())
	}
}

func TestRunFailsWhenKubernetesResourcesMissingPDB(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rollout":
			_, _ = w.Write([]byte("namespace staging deployment scriptureforge-api successfully rolled out ready available; deployment scriptureforge-web successfully rolled out ready available; deployment scriptureforge-rust-engine successfully rolled out ready available" + rolloutReleaseMarkers))
		case "/resources":
			_, _ = w.Write([]byte("namespace staging deployment service ingress hpa ready available targets readinessProbe livenessProbe rollingUpdate maxUnavailable=0 minReplicas maxReplicas tls SecretProviderClass image ghcr.io/scriptureforge/api@" + apiImageDigest + " ghcr.io/scriptureforge/web@" + webImageDigest + " ghcr.io/scriptureforge/rust-engine@" + rustImageDigest + " release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1 scriptureforge-api scriptureforge-web scriptureforge-rust-engine"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingDeploymentConfig(time.Second)
	cfg.ProbeTerraform = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing PDB resource artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "kubernetes-workload-resources") {
		t.Fatalf("report missing resources probe:\n%s", output.String())
	}
}

func TestRunFailsWhenKubernetesResourcesOmitImageDigestLinkage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rollout":
			_, _ = w.Write([]byte("namespace staging deployment scriptureforge-api successfully rolled out ready available; deployment scriptureforge-web successfully rolled out ready available; deployment scriptureforge-rust-engine successfully rolled out ready available" + rolloutReleaseMarkers))
		case "/resources":
			_, _ = w.Write([]byte("namespace staging deployment service ingress hpa pdb ready available targets minAvailable readinessProbe livenessProbe rollingUpdate maxUnavailable=0 minReplicas maxReplicas tls SecretProviderClass image ghcr.io/scriptureforge/api:latest release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1 scriptureforge-api scriptureforge-web scriptureforge-rust-engine"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingDeploymentConfig(time.Second)
	cfg.ProbeTerraform = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected missing immutable image digest to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "kubernetes-workload-resources") {
		t.Fatalf("report missing resources probe:\n%s", output.String())
	}
}

func TestRunFailsWhenKubernetesResourcesUseGenericDigestMarkers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rollout":
			_, _ = w.Write([]byte("namespace staging deployment scriptureforge-api successfully rolled out ready available; deployment scriptureforge-web successfully rolled out ready available; deployment scriptureforge-rust-engine successfully rolled out ready available" + rolloutReleaseMarkers))
		case "/resources":
			_, _ = w.Write([]byte("namespace staging deployment service ingress hpa pdb ready available targets minAvailable readinessProbe livenessProbe rollingUpdate maxUnavailable=0 minReplicas maxReplicas tls SecretProviderClass image ghcr.io/scriptureforge/api@sha256:abc123 ghcr.io/scriptureforge/web@sha256:def456 ghcr.io/scriptureforge/rust-engine@sha256:789abc release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1 scriptureforge-api scriptureforge-web scriptureforge-rust-engine"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingDeploymentConfig(time.Second)
	cfg.ProbeTerraform = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected generic digest markers to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "kubernetes-workload-resources") {
		t.Fatalf("report missing resources probe:\n%s", output.String())
	}
}

func TestRunFailsWhenKubernetesResourcesUseUnboundImageDigests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rollout":
			_, _ = w.Write([]byte("namespace staging deployment scriptureforge-api successfully rolled out ready available; deployment scriptureforge-web successfully rolled out ready available; deployment scriptureforge-rust-engine successfully rolled out ready available" + rolloutReleaseMarkers))
		case "/resources":
			_, _ = w.Write([]byte("namespace staging deployment service ingress hpa pdb ready available targets minAvailable readinessProbe livenessProbe rollingUpdate maxUnavailable=0 minReplicas maxReplicas tls SecretProviderClass image sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1 scriptureforge-api scriptureforge-web scriptureforge-rust-engine"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingDeploymentConfig(time.Second)
	cfg.ProbeTerraform = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected unbound digest markers to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "kubernetes-workload-resources") {
		t.Fatalf("report missing resources probe:\n%s", output.String())
	}
}

func TestRunAcceptsTerraformDeploymentApprovalInsteadOfApply(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tf-init":
			_, _ = w.Write([]byte("terraform backend s3 bucket scriptureforge-state key staging/terraform.tfstate encrypt=true kms_key_id=alias/scriptureforge-terraform-state versioning=enabled dynamodb_table scriptureforge-locks successfully initialized release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1 " + deploymentLoadRunMarker))
		case "/tf-plan":
			_, _ = w.Write([]byte("Terraform Plan: aws_eks_cluster aws_eks_node_group aws_rds_cluster aws_elasticache_replication_group aws_ecr_repository kubernetes_deployment kubernetes_ingress_v1 kubernetes_horizontal_pod_autoscaler_v2 kubernetes_pod_disruption_budget_v1 kubernetes_manifest aws_iam_role kms_key_id=" + terraformStateKMSKeyID + " database_kms_key_arn=" + databaseKMSKeyARN + " redis_kms_key_arn=" + redisKMSKeyARN + " release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1 " + deploymentLoadRunMarker))
		case "/tf-approval":
			_, _ = w.Write([]byte("deployment approval approved DEPLOY-TF-001 change_ticket=PLATFORM-123 release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1 " + deploymentLoadRunMarker))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingDeploymentConfig(time.Second)
	cfg.ProbeKubernetes = false
	cfg.TerraformApplyURL = "https://deployment-artifacts.staging.scriptureforge.ai/deploy/tf-approval"
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err != nil {
		t.Fatalf("deployment approval evidence should pass: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), "change_ticket=PLATFORM-123") {
		t.Fatalf("deployment approval summary missing structured change ticket marker:\n%s", output.String())
	}
	var result report
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	var ticket string
	for _, probe := range result.Probes {
		if probe.Name == "terraform-staging-apply-or-approval" {
			ticket = probe.ChangeTicket
		}
	}
	if ticket != "PLATFORM-123" {
		t.Fatalf("deployment approval report change_ticket = %q, want PLATFORM-123:\n%s", ticket, output.String())
	}
	if !strings.Contains(output.String(), "distinct_terraform_artifacts=true") {
		t.Fatalf("deployment approval summary missing distinct artifact marker:\n%s", output.String())
	}
}

func TestRunFailsWhenTerraformDeploymentApprovalOmitsChangeTicket(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tf-init":
			_, _ = w.Write([]byte("terraform backend s3 bucket scriptureforge-state key staging/terraform.tfstate encrypt=true kms_key_id=alias/scriptureforge-terraform-state versioning=enabled dynamodb_table scriptureforge-locks successfully initialized release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1"))
		case "/tf-plan":
			_, _ = w.Write([]byte("Terraform Plan: aws_eks_cluster aws_eks_node_group aws_rds_cluster aws_elasticache_replication_group aws_ecr_repository kubernetes_deployment kubernetes_ingress_v1 kubernetes_horizontal_pod_autoscaler_v2 kubernetes_pod_disruption_budget_v1 kubernetes_manifest aws_iam_role kms_key_id=" + terraformStateKMSKeyID + " database_kms_key_arn=" + databaseKMSKeyARN + " redis_kms_key_arn=" + redisKMSKeyARN + " release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1"))
		case "/tf-approval":
			_, _ = w.Write([]byte("deployment approval approved DEPLOY-TF-001 release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingDeploymentConfig(time.Second)
	cfg.ProbeKubernetes = false
	cfg.TerraformApplyURL = "https://deployment-artifacts.staging.scriptureforge.ai/deploy/tf-approval"
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected deployment approval without change ticket to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "terraform-staging-apply-or-approval") {
		t.Fatalf("report missing apply/approval probe:\n%s", output.String())
	}
}

func TestRunFailsWhenTerraformDeploymentApprovalOmitsChangeTicketID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tf-init":
			_, _ = w.Write([]byte("terraform backend s3 bucket scriptureforge-state key staging/terraform.tfstate encrypt=true kms_key_id=alias/scriptureforge-terraform-state versioning=enabled dynamodb_table scriptureforge-locks successfully initialized release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1"))
		case "/tf-plan":
			_, _ = w.Write([]byte("Terraform Plan: aws_eks_cluster aws_eks_node_group aws_rds_cluster aws_elasticache_replication_group aws_ecr_repository kubernetes_deployment kubernetes_ingress_v1 kubernetes_horizontal_pod_autoscaler_v2 kubernetes_pod_disruption_budget_v1 kubernetes_manifest aws_iam_role kms_key_id=" + terraformStateKMSKeyID + " database_kms_key_arn=" + databaseKMSKeyARN + " redis_kms_key_arn=" + redisKMSKeyARN + " release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1"))
		case "/tf-approval":
			_, _ = w.Write([]byte("deployment approval approved DEPLOY-TF-001 change_ticket= release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingDeploymentConfig(time.Second)
	cfg.ProbeKubernetes = false
	cfg.TerraformApplyURL = "https://deployment-artifacts.staging.scriptureforge.ai/deploy/tf-approval"
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected deployment approval without change ticket ID to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "terraform-staging-apply-or-approval") {
		t.Fatalf("report missing apply/approval probe:\n%s", output.String())
	}
}

func TestRunFailsWhenTerraformApplyOmitsReleaseLinkage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tf-init":
			_, _ = w.Write([]byte("terraform backend s3 bucket scriptureforge-state key staging/terraform.tfstate encrypt=true kms_key_id=alias/scriptureforge-terraform-state versioning=enabled dynamodb_table scriptureforge-locks successfully initialized release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1"))
		case "/tf-plan":
			_, _ = w.Write([]byte("Terraform Plan: aws_eks_cluster aws_eks_node_group aws_rds_cluster aws_elasticache_replication_group aws_ecr_repository kubernetes_deployment kubernetes_ingress_v1 kubernetes_horizontal_pod_autoscaler_v2 kubernetes_pod_disruption_budget_v1 kubernetes_manifest aws_iam_role kms_key_id=" + terraformStateKMSKeyID + " database_kms_key_arn=" + databaseKMSKeyARN + " redis_kms_key_arn=" + redisKMSKeyARN + " release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1"))
		case "/tf-apply":
			_, _ = w.Write([]byte("Apply complete! Resources: 42 added, 0 changed, 0 destroyed."))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingDeploymentConfig(time.Second)
	cfg.ProbeKubernetes = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected apply artifact without release linkage to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "terraform-staging-apply-or-approval") {
		t.Fatalf("report missing apply/approval probe:\n%s", output.String())
	}
}

func TestRunFailsWhenTerraformApplyOmitsZeroDestroyedProof(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tf-init":
			_, _ = w.Write([]byte("terraform backend s3 bucket scriptureforge-state key staging/terraform.tfstate encrypt=true kms_key_id=alias/scriptureforge-terraform-state versioning=enabled dynamodb_table scriptureforge-locks successfully initialized release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1"))
		case "/tf-plan":
			_, _ = w.Write([]byte("Terraform Plan: aws_eks_cluster aws_eks_node_group aws_rds_cluster aws_elasticache_replication_group aws_ecr_repository kubernetes_deployment kubernetes_ingress_v1 kubernetes_horizontal_pod_autoscaler_v2 kubernetes_pod_disruption_budget_v1 kubernetes_manifest aws_iam_role kms_key_id=" + terraformStateKMSKeyID + " database_kms_key_arn=" + databaseKMSKeyARN + " redis_kms_key_arn=" + redisKMSKeyARN + " release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1"))
		case "/tf-apply":
			_, _ = w.Write([]byte("Apply complete! Resources: 42 added, 0 changed. release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingDeploymentConfig(time.Second)
	cfg.ProbeKubernetes = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected apply artifact without zero-destroy proof to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "terraform-staging-apply-or-approval") {
		t.Fatalf("report missing apply/approval probe:\n%s", output.String())
	}
}

func TestRunFailsWhenTerraformPlanOmitsWorkloadsAndIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tf-init":
			_, _ = w.Write([]byte("terraform backend s3 successfully initialized"))
		case "/tf-plan":
			_, _ = w.Write([]byte("Terraform Plan: aws_eks_cluster aws_rds_cluster aws_elasticache_replication_group"))
		case "/tf-apply":
			_, _ = w.Write([]byte("Apply complete! Resources: 42 added, 0 changed, 0 destroyed. release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=2026.06.27.1"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	cfg := stagingDeploymentConfig(time.Second)
	cfg.ProbeKubernetes = false
	err := runWithClient(cfg, &output, clientForHTTPServer(t, server))
	if err == nil {
		t.Fatalf("expected incomplete Terraform plan to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "terraform-staging-plan") {
		t.Fatalf("report missing plan probe:\n%s", output.String())
	}
}

func TestRunRejectsLocalOrInsecureArtifactURLs(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*config)
		want string
	}{
		{
			name: "insecure terraform init artifact",
			edit: func(cfg *config) {
				cfg.TerraformInitURL = "http://deployment-artifacts.staging.scriptureforge.ai/deploy/tf-init"
			},
			want: "terraform-init-url",
		},
		{
			name: "reserved example terraform init artifact",
			edit: func(cfg *config) {
				cfg.TerraformInitURL = "https://artifacts.staging.example/deploy/tf-init"
			},
			want: "reserved placeholder artifact host",
		},
		{
			name: "reserved example.com terraform plan artifact",
			edit: func(cfg *config) {
				cfg.TerraformPlanURL = "https://deploy.example.com/deploy/tf-plan"
			},
			want: "reserved placeholder artifact host",
		},
		{
			name: "reserved test kubernetes rollout artifact",
			edit: func(cfg *config) {
				cfg.K8SRolloutURL = "https://deployment-artifacts.staging.test/deploy/rollout"
			},
			want: "reserved placeholder artifact host",
		},
		{
			name: "reserved invalid kubernetes resources artifact",
			edit: func(cfg *config) {
				cfg.K8SResourcesURL = "https://deployment-artifacts.invalid/deploy/resources"
			},
			want: "reserved placeholder artifact host",
		},
		{
			name: "loopback terraform plan artifact",
			edit: func(cfg *config) {
				cfg.TerraformPlanURL = "https://127.0.0.1/deploy/tf-plan"
			},
			want: "terraform-plan-url",
		},
		{
			name: "private terraform apply artifact",
			edit: func(cfg *config) {
				cfg.TerraformApplyURL = "https://10.0.0.25/deploy/tf-apply"
			},
			want: "non-private staging artifact host",
		},
		{
			name: "IPv4-mapped private terraform apply artifact",
			edit: func(cfg *config) {
				cfg.TerraformApplyURL = "https://[::ffff:10.0.0.25]/deploy/tf-apply"
			},
			want: "non-private staging artifact host",
		},
		{
			name: "localhost kubernetes resources artifact",
			edit: func(cfg *config) {
				cfg.K8SResourcesURL = "https://localhost/deploy/resources"
			},
			want: "k8s-resources-url",
		},
		{
			name: "link-local kubernetes rollout artifact",
			edit: func(cfg *config) {
				cfg.K8SRolloutURL = "https://169.254.10.20/deploy/rollout"
			},
			want: "non-private staging artifact host",
		},
		{
			name: "unspecified kubernetes resources artifact",
			edit: func(cfg *config) {
				cfg.K8SResourcesURL = "https://0.0.0.0/deploy/resources"
			},
			want: "non-private staging artifact host",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := stagingDeploymentConfig(time.Second)
			tc.edit(&cfg)
			var output bytes.Buffer
			err := runWithClient(cfg, &output, http.DefaultClient)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q URL validation error, got %v", tc.want, err)
			}
		})
	}
}

func containsItem(items []string, expected string) bool {
	for _, item := range items {
		if item == expected {
			return true
		}
	}
	return false
}

func clientForHTTPServer(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("invalid test server URL: %v", err)
	}
	baseClient := server.Client()
	baseTransport := baseClient.Transport
	return &http.Client{
		Timeout: baseClient.Timeout,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			cloned := req.Clone(req.Context())
			cloned.URL.Scheme = serverURL.Scheme
			cloned.URL.Host = serverURL.Host
			cloned.URL.Path = strings.TrimPrefix(cloned.URL.Path, "/deploy")
			return baseTransport.RoundTrip(cloned)
		}),
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
