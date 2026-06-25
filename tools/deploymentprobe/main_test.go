package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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
			_, _ = w.Write([]byte("terraform backend s3 successfully initialized"))
		case "/tf-plan":
			_, _ = w.Write([]byte("Terraform Plan: aws_eks_cluster aws_rds_cluster aws_elasticache_replication_group"))
		case "/tf-apply":
			_, _ = w.Write([]byte("Apply complete! Resources: 42 added, 0 changed, 0 destroyed. deployment approval platform-123"))
		case "/rollout":
			_, _ = w.Write([]byte("deployment scriptureforge-api successfully rolled out; deployment scriptureforge-web successfully rolled out; deployment scriptureforge-rust-engine successfully rolled out"))
		case "/resources":
			_, _ = w.Write([]byte("deployment service ingress hpa pdb scriptureforge-api scriptureforge-web scriptureforge-rust-engine"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		ProbeTerraform:    true,
		ProbeKubernetes:   true,
		TerraformInitURL:  server.URL + "/tf-init",
		TerraformPlanURL:  server.URL + "/tf-plan",
		TerraformApplyURL: server.URL + "/tf-apply",
		K8SRolloutURL:     server.URL + "/rollout",
		K8SResourcesURL:   server.URL + "/resources",
		Timeout:           time.Second,
	}, &output)
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
	if !containsItem(result.EvidenceItems, "DEPLOY-TF-001") || !containsItem(result.EvidenceItems, "DEPLOY-K8S-001") {
		t.Fatalf("missing deployment evidence items: %+v", result.EvidenceItems)
	}
}

func TestRunFailsWhenTerraformInitUsesBackendFalse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tf-init":
			_, _ = w.Write([]byte("terraform init -backend=false local backend successfully initialized"))
		case "/tf-plan":
			_, _ = w.Write([]byte("Terraform Plan: aws_eks_cluster aws_rds_cluster aws_elasticache_replication_group"))
		case "/tf-apply":
			_, _ = w.Write([]byte("Apply complete! Resources: 42 added, 0 changed, 0 destroyed. approval"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		ProbeTerraform:    true,
		TerraformInitURL:  server.URL + "/tf-init",
		TerraformPlanURL:  server.URL + "/tf-plan",
		TerraformApplyURL: server.URL + "/tf-apply",
		Timeout:           time.Second,
	}, &output)
	if err == nil {
		t.Fatalf("expected backend=false init artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `"threshold_pass": false`) {
		t.Fatalf("failing report did not mark threshold false:\n%s", output.String())
	}
}

func TestRunFailsWhenKubernetesResourcesMissingPDB(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rollout":
			_, _ = w.Write([]byte("deployment scriptureforge-api successfully rolled out; deployment scriptureforge-web successfully rolled out; deployment scriptureforge-rust-engine successfully rolled out"))
		case "/resources":
			_, _ = w.Write([]byte("deployment service ingress hpa scriptureforge-api scriptureforge-web scriptureforge-rust-engine"))
		}
	}))
	defer server.Close()

	var output bytes.Buffer
	err := run(config{
		ProbeKubernetes: true,
		K8SRolloutURL:   server.URL + "/rollout",
		K8SResourcesURL: server.URL + "/resources",
		Timeout:         time.Second,
	}, &output)
	if err == nil {
		t.Fatalf("expected missing PDB resource artifact to fail:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "kubernetes-workload-resources") {
		t.Fatalf("report missing resources probe:\n%s", output.String())
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
