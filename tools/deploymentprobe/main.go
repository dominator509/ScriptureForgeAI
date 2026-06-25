package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type config struct {
	ProbeTerraform    bool
	ProbeKubernetes   bool
	TerraformInitURL  string
	TerraformPlanURL  string
	TerraformApplyURL string
	K8SRolloutURL     string
	K8SResourcesURL   string
	Timeout           time.Duration
}

type report struct {
	ObservedAt    string        `json:"observed_at"`
	ThresholdPass bool          `json:"threshold_pass"`
	Probes        []probeResult `json:"probes"`
	EvidenceItems []string      `json:"evidence_items"`
}

type probeResult struct {
	Name          string `json:"name"`
	Target        string `json:"target"`
	Passed        bool   `json:"passed"`
	StatusCode    int    `json:"status_code,omitempty"`
	LatencyMS     int64  `json:"latency_ms,omitempty"`
	ResultSummary string `json:"result_summary"`
}

func main() {
	cfg := parseFlags()
	if err := run(cfg, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseFlags() config {
	cfg := config{}
	flag.BoolVar(&cfg.ProbeTerraform, "probe-terraform", false, "probe Terraform remote backend, plan, and apply/approval evidence")
	flag.BoolVar(&cfg.ProbeKubernetes, "probe-kubernetes", false, "probe Kubernetes rollout and workload resource evidence")
	flag.StringVar(&cfg.TerraformInitURL, "terraform-init-url", os.Getenv("STAGING_TERRAFORM_INIT_URL"), "terraform init remote-backend artifact URL")
	flag.StringVar(&cfg.TerraformPlanURL, "terraform-plan-url", os.Getenv("STAGING_TERRAFORM_PLAN_URL"), "terraform plan artifact URL")
	flag.StringVar(&cfg.TerraformApplyURL, "terraform-apply-url", os.Getenv("STAGING_TERRAFORM_APPLY_URL"), "terraform apply output or deployment approval artifact URL")
	flag.StringVar(&cfg.K8SRolloutURL, "k8s-rollout-url", os.Getenv("STAGING_K8S_ROLLOUT_URL"), "kubectl rollout status artifact URL")
	flag.StringVar(&cfg.K8SResourcesURL, "k8s-resources-url", os.Getenv("STAGING_K8S_RESOURCES_URL"), "kubectl get deploy,svc,ingress,hpa,pdb artifact URL")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "per-probe timeout")
	flag.Parse()
	return cfg
}

func run(cfg config, output io.Writer) error {
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if !cfg.ProbeTerraform && !cfg.ProbeKubernetes {
		return errors.New("at least one of -probe-terraform or -probe-kubernetes is required")
	}
	if cfg.ProbeTerraform {
		if cfg.TerraformInitURL == "" || cfg.TerraformPlanURL == "" || cfg.TerraformApplyURL == "" {
			return errors.New("-probe-terraform requires init, plan, and apply/approval artifact URLs")
		}
	}
	if cfg.ProbeKubernetes {
		if cfg.K8SRolloutURL == "" || cfg.K8SResourcesURL == "" {
			return errors.New("-probe-kubernetes requires rollout and resource artifact URLs")
		}
	}

	client := &http.Client{Timeout: cfg.Timeout}
	probes := []probeResult{}
	evidenceItems := []string{}
	if cfg.ProbeTerraform {
		probes = append(probes,
			probeArtifact(client, "terraform-remote-backend-init", cfg.TerraformInitURL, []string{"terraform", "s3", "backend", "successfully initialized"}, []string{"-backend=false", "local backend"}),
			probeArtifact(client, "terraform-staging-plan", cfg.TerraformPlanURL, []string{"Terraform", "Plan:", "aws_eks_cluster", "aws_eks_node_group", "aws_rds_cluster", "aws_elasticache_replication_group", "kubernetes_deployment", "kubernetes_ingress_v1", "kubernetes_manifest", "aws_iam_role"}, nil),
			probeArtifactAny(client, "terraform-staging-apply-or-approval", cfg.TerraformApplyURL, [][]string{
				{"Apply complete", "Resources:"},
				{"deployment approval", "approved", "DEPLOY-TF-001"},
			}, []string{"Error:", "failed"}),
		)
		evidenceItems = append(evidenceItems, "DEPLOY-TF-001")
	}
	if cfg.ProbeKubernetes {
		probes = append(probes,
			probeArtifact(client, "kubernetes-rollout-status", cfg.K8SRolloutURL, []string{"deployment", "scriptureforge-api", "scriptureforge-web", "scriptureforge-rust-engine", "successfully rolled out", "ready", "available"}, nil),
			probeArtifact(client, "kubernetes-workload-resources", cfg.K8SResourcesURL, []string{"deployment", "service", "ingress", "hpa", "pdb", "ready", "available", "targets", "minavailable", "scriptureforge-api", "scriptureforge-web", "scriptureforge-rust-engine"}, nil),
		)
		evidenceItems = append(evidenceItems, "DEPLOY-K8S-001")
	}

	result := report{
		ObservedAt:    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		ThresholdPass: true,
		Probes:        probes,
		EvidenceItems: evidenceItems,
	}
	for _, probe := range probes {
		if !probe.Passed {
			result.ThresholdPass = false
			break
		}
	}

	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return err
	}
	if !result.ThresholdPass {
		return errors.New("one or more deployment probes failed")
	}
	return nil
}

func probeArtifact(client *http.Client, name, target string, required []string, forbidden []string) probeResult {
	return probeArtifactAny(client, name, target, [][]string{required}, forbidden)
}

func probeArtifactAny(client *http.Client, name, target string, acceptableRequiredSets [][]string, forbidden []string) probeResult {
	start := time.Now()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	req.Header.Set("User-Agent", "scriptureforge-deploymentprobe/1.0")
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	text := string(body)
	passed := resp.StatusCode >= 200 && resp.StatusCode < 300 && containsAnyRequiredSet(text, acceptableRequiredSets) && containsNoneFold(text, forbidden)
	summary := fmt.Sprintf("got HTTP %d in %dms", resp.StatusCode, latency)
	if !passed {
		summary += "; artifact missing required markers or contains forbidden local/failure markers"
	}
	return probeResult{Name: name, Target: target, Passed: passed, StatusCode: resp.StatusCode, LatencyMS: latency, ResultSummary: summary}
}

func containsAnyRequiredSet(text string, sets [][]string) bool {
	for _, set := range sets {
		if containsAllFold(text, set) {
			return true
		}
	}
	return false
}

func containsAllFold(text string, needles []string) bool {
	lowerText := strings.ToLower(text)
	for _, needle := range needles {
		if !strings.Contains(lowerText, strings.ToLower(needle)) {
			return false
		}
	}
	return true
}

func containsNoneFold(text string, needles []string) bool {
	lowerText := strings.ToLower(text)
	for _, needle := range needles {
		if strings.Contains(lowerText, strings.ToLower(needle)) {
			return false
		}
	}
	return true
}

func failedProbe(name, target, summary string) probeResult {
	return probeResult{Name: name, Target: target, Passed: false, ResultSummary: summary}
}
