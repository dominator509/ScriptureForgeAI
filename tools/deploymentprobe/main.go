package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
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
	ReleaseCandidate  string
	ServiceVersion    string
	LoadRunID         string
	Timeout           time.Duration
}

type report struct {
	ObservedAt       string        `json:"observed_at"`
	ThresholdPass    bool          `json:"threshold_pass"`
	ReleaseCandidate string        `json:"release_candidate"`
	ServiceVersion   string        `json:"service_version"`
	LoadRunID        string        `json:"load_run_id"`
	Probes           []probeResult `json:"probes"`
	EvidenceItems    []string      `json:"evidence_items"`
}

type probeResult struct {
	Name                 string            `json:"name"`
	Target               string            `json:"target"`
	Passed               bool              `json:"passed"`
	StatusCode           int               `json:"status_code,omitempty"`
	LatencyMS            int64             `json:"latency_ms,omitempty"`
	ChangeTicket         string            `json:"change_ticket,omitempty"`
	ConcreteImageDigests int               `json:"concrete_image_digests,omitempty"`
	WorkloadImageDigests int               `json:"workload_image_digests,omitempty"`
	ImageDigests         map[string]string `json:"image_digests,omitempty"`
	ResultSummary        string            `json:"result_summary"`
}

var terraformApprovalTicketPattern = regexp.MustCompile(`(?i)\bchange[_ -]?ticket\s*[:=]\s*([A-Z][A-Z0-9]+-\d+)\b`)
var immutableImageDigestPattern = regexp.MustCompile(`sha256:[a-fA-F0-9]{64}`)
var kubernetesWorkloadImageDigests = map[string]*regexp.Regexp{
	"scriptureforge-api":         regexp.MustCompile(`(?i)(?:scriptureforge-api|scriptureforge/api)[^\s,;]*@(sha256:[a-f0-9]{64})\b`),
	"scriptureforge-web":         regexp.MustCompile(`(?i)(?:scriptureforge-web|scriptureforge/web)[^\s,;]*@(sha256:[a-f0-9]{64})\b`),
	"scriptureforge-rust-engine": regexp.MustCompile(`(?i)(?:scriptureforge-rust-engine|scriptureforge/rust-engine)[^\s,;]*@(sha256:[a-f0-9]{64})\b`),
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
	flag.StringVar(&cfg.ReleaseCandidate, "release-candidate", os.Getenv("STAGING_RELEASE_CANDIDATE"), "exact release candidate SHA that deployment artifacts must name")
	flag.StringVar(&cfg.ServiceVersion, "service-version", os.Getenv("STAGING_SERVICE_VERSION"), "exact deployed service version that deployment artifacts must name")
	flag.StringVar(&cfg.LoadRunID, "load-run-id", os.Getenv("STAGING_LOAD_RUN_ID"), "exact staging deployment/load run identifier that every deployment artifact must name")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "per-probe timeout")
	flag.Parse()
	return cfg
}

func run(cfg config, output io.Writer) error {
	return runWithClient(cfg, output, &http.Client{Timeout: cfg.Timeout})
}

func runWithClient(cfg config, output io.Writer, client *http.Client) error {
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if !cfg.ProbeTerraform && !cfg.ProbeKubernetes {
		return errors.New("at least one of -probe-terraform or -probe-kubernetes is required")
	}
	cfg.ReleaseCandidate = strings.TrimSpace(cfg.ReleaseCandidate)
	cfg.ServiceVersion = strings.TrimSpace(cfg.ServiceVersion)
	cfg.LoadRunID = strings.TrimSpace(cfg.LoadRunID)
	if cfg.ReleaseCandidate == "" || cfg.ServiceVersion == "" || cfg.LoadRunID == "" {
		return errors.New("release-candidate, service-version, and load-run-id are required for deployment evidence")
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
	var err error
	if cfg.ProbeTerraform {
		cfg.TerraformInitURL, err = normalizeArtifactURL(cfg.TerraformInitURL, "terraform-init-url")
		if err != nil {
			return err
		}
		cfg.TerraformPlanURL, err = normalizeArtifactURL(cfg.TerraformPlanURL, "terraform-plan-url")
		if err != nil {
			return err
		}
		cfg.TerraformApplyURL, err = normalizeArtifactURL(cfg.TerraformApplyURL, "terraform-apply-url")
		if err != nil {
			return err
		}
		if err := requireDistinctArtifactURLs([]artifactTarget{
			{name: "terraform-init-url", target: cfg.TerraformInitURL},
			{name: "terraform-plan-url", target: cfg.TerraformPlanURL},
			{name: "terraform-apply-url", target: cfg.TerraformApplyURL},
		}); err != nil {
			return err
		}
	}
	if cfg.ProbeKubernetes {
		cfg.K8SRolloutURL, err = normalizeArtifactURL(cfg.K8SRolloutURL, "k8s-rollout-url")
		if err != nil {
			return err
		}
		cfg.K8SResourcesURL, err = normalizeArtifactURL(cfg.K8SResourcesURL, "k8s-resources-url")
		if err != nil {
			return err
		}
		if err := requireDistinctArtifactURLs([]artifactTarget{
			{name: "k8s-rollout-url", target: cfg.K8SRolloutURL},
			{name: "k8s-resources-url", target: cfg.K8SResourcesURL},
		}); err != nil {
			return err
		}
	}
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}

	probes := []probeResult{}
	evidenceItems := []string{}
	releaseMarkers := []string{
		"release_candidate=" + cfg.ReleaseCandidate,
		"service_version=" + cfg.ServiceVersion,
		"load_run_id=" + cfg.LoadRunID,
	}
	if cfg.ProbeTerraform {
		probes = append(probes,
			probeArtifact(client, "terraform-remote-backend-init", cfg.TerraformInitURL, append([]string{"terraform", "s3", "backend", "bucket", "key", "encrypt=true", "kms_key_id=", "versioning=enabled", "dynamodb_table", "successfully initialized"}, releaseMarkers...), []string{"-backend=false", "local backend"}),
			probeArtifact(client, "terraform-staging-plan", cfg.TerraformPlanURL, append([]string{"Terraform", "Plan:", "aws_eks_cluster", "aws_eks_node_group", "aws_rds_cluster", "aws_elasticache_replication_group", "aws_ecr_repository", "kubernetes_deployment", "kubernetes_ingress_v1", "kubernetes_horizontal_pod_autoscaler_v2", "kubernetes_pod_disruption_budget_v1", "kubernetes_manifest", "aws_iam_role", "kms_key_id", "database_kms_key_arn", "redis_kms_key_arn"}, releaseMarkers...), nil),
			probeArtifactAny(client, "terraform-staging-apply-or-approval", cfg.TerraformApplyURL, [][]string{
				append([]string{"Apply complete", "Resources:", "0 destroyed"}, releaseMarkers...),
				append([]string{"deployment approval", "approved", "DEPLOY-TF-001", "change_ticket="}, releaseMarkers...),
			}, []string{"Error:", "failed"}, []string{"distinct_terraform_artifacts=true"}),
		)
		evidenceItems = append(evidenceItems, "DEPLOY-TF-001")
	}
	if cfg.ProbeKubernetes {
		probes = append(probes,
			probeArtifact(client, "kubernetes-rollout-status", cfg.K8SRolloutURL, append([]string{"namespace", "staging", "deployment", "scriptureforge-api", "scriptureforge-web", "scriptureforge-rust-engine", "successfully rolled out", "ready", "available"}, releaseMarkers...), nil),
			probeArtifact(client, "kubernetes-workload-resources", cfg.K8SResourcesURL, append([]string{"namespace", "staging", "deployment", "service", "ingress", "hpa", "pdb", "ready", "available", "targets", "minavailable", "readinessProbe", "livenessProbe", "rollingUpdate", "maxUnavailable=0", "minReplicas", "maxReplicas", "tls", "SecretProviderClass", "image", "sha256:"}, append(releaseMarkers, "scriptureforge-api", "scriptureforge-web", "scriptureforge-rust-engine")...), nil),
		)
		evidenceItems = append(evidenceItems, "DEPLOY-K8S-001")
	}

	result := report{
		ObservedAt:       time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		ThresholdPass:    true,
		ReleaseCandidate: cfg.ReleaseCandidate,
		ServiceVersion:   cfg.ServiceVersion,
		LoadRunID:        cfg.LoadRunID,
		Probes:           probes,
		EvidenceItems:    evidenceItems,
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
	return probeArtifactAny(client, name, target, [][]string{required}, forbidden, nil)
}

func probeArtifactAny(client *http.Client, name, target string, acceptableRequiredSets [][]string, forbidden []string, extraVerifiedMarkers []string) probeResult {
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
	allForbidden := append([]string{}, forbidden...)
	allForbidden = append(allForbidden, forbiddenArtifactMarkers()...)
	matchedRequiredSet := matchingRequiredSet(text, acceptableRequiredSets)
	passed := resp.StatusCode >= 200 && resp.StatusCode < 300 && len(matchedRequiredSet) > 0 && evidenceSpecificMarkersValid(name, text) && containsNoneFold(text, allForbidden)
	summary := fmt.Sprintf("got HTTP %d in %dms", resp.StatusCode, latency)
	if passed {
		changeTicket := approvalTicket(name, text)
		matchedRequiredSet = appendApprovalTicketMarker(changeTicket, matchedRequiredSet)
		matchedRequiredSet = appendKubernetesDigestMarker(name, text, matchedRequiredSet)
		matchedRequiredSet = append(matchedRequiredSet, extraVerifiedMarkers...)
		summary = fmt.Sprintf("%s; staging artifact; verified markers: %s", summary, strings.Join(matchedRequiredSet, ", "))
		result := probeResult{Name: name, Target: target, Passed: passed, StatusCode: resp.StatusCode, LatencyMS: latency, ChangeTicket: changeTicket, ResultSummary: summary}
		applyKubernetesDigestFields(&result, text)
		return result
	} else {
		summary += "; artifact missing required markers or contains forbidden local/mock/failure markers"
	}
	return probeResult{Name: name, Target: target, Passed: passed, StatusCode: resp.StatusCode, LatencyMS: latency, ResultSummary: summary}
}

func evidenceSpecificMarkersValid(name, text string) bool {
	if name == "kubernetes-workload-resources" {
		return concreteImageDigestCount(text) >= 3 && len(kubernetesWorkloadDigestMarkers(text)) == len(kubernetesWorkloadImageDigests)
	}
	if name != "terraform-staging-apply-or-approval" || !containsAllFold(text, []string{"deployment approval", "approved", "DEPLOY-TF-001"}) {
		return true
	}
	return terraformApprovalTicketPattern.MatchString(text)
}

func appendKubernetesDigestMarker(name, text string, markers []string) []string {
	if name != "kubernetes-workload-resources" {
		return markers
	}
	digestMarkers := kubernetesWorkloadDigestMarkers(text)
	markers = append(markers, digestMarkers...)
	return append(markers,
		fmt.Sprintf("concrete_image_digests=%d", concreteImageDigestCount(text)),
		fmt.Sprintf("workload_image_digests=%d", len(digestMarkers)),
		"distinct_kubernetes_artifacts=true",
	)
}

func applyKubernetesDigestFields(result *probeResult, text string) {
	if result.Name != "kubernetes-workload-resources" {
		return
	}
	digests := kubernetesWorkloadDigestMap(text)
	result.ConcreteImageDigests = concreteImageDigestCount(text)
	result.WorkloadImageDigests = len(digests)
	result.ImageDigests = digests
}

func concreteImageDigestCount(text string) int {
	matches := immutableImageDigestPattern.FindAllString(strings.ToLower(text), -1)
	unique := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		unique[match] = struct{}{}
	}
	return len(unique)
}

func kubernetesWorkloadDigestMarkers(text string) []string {
	workloads := []string{"scriptureforge-api", "scriptureforge-web", "scriptureforge-rust-engine"}
	markers := make([]string, 0, len(workloads))
	for _, workload := range workloads {
		if digest := kubernetesWorkloadDigest(text, workload); digest != "" {
			markers = append(markers, workload+"@"+digest)
		}
	}
	return markers
}

func kubernetesWorkloadDigestMap(text string) map[string]string {
	workloads := []string{"scriptureforge-api", "scriptureforge-web", "scriptureforge-rust-engine"}
	digests := make(map[string]string, len(workloads))
	for _, workload := range workloads {
		if digest := kubernetesWorkloadDigest(text, workload); digest != "" {
			digests[workload] = digest
		}
	}
	return digests
}

func kubernetesWorkloadDigest(text, workload string) string {
	match := kubernetesWorkloadImageDigests[workload].FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return strings.ToLower(match[1])
}

func approvalTicket(name, text string) string {
	if name != "terraform-staging-apply-or-approval" || !containsAllFold(text, []string{"deployment approval", "approved", "DEPLOY-TF-001"}) {
		return ""
	}
	match := terraformApprovalTicketPattern.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func appendApprovalTicketMarker(changeTicket string, markers []string) []string {
	if changeTicket == "" {
		return markers
	}
	normalized := "change_ticket=" + changeTicket
	lowerNormalized := strings.ToLower(normalized)
	for _, marker := range markers {
		if strings.ToLower(marker) == lowerNormalized {
			return markers
		}
	}
	return append(markers, normalized)
}

func matchingRequiredSet(text string, sets [][]string) []string {
	for _, set := range sets {
		if containsAllFold(text, set) {
			return set
		}
	}
	return nil
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

func normalizeArtifactURL(raw, field string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("-%s must use https", field)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("-%s must include a host", field)
	}
	if isLocalOrPrivateHost(parsed.Hostname()) {
		return "", fmt.Errorf("-%s must use a non-local, non-private staging artifact host", field)
	}
	if isReservedPlaceholderHost(parsed.Hostname()) {
		return "", fmt.Errorf("-%s must not use a reserved placeholder artifact host", field)
	}
	parsed.Fragment = ""
	return parsed.String(), nil
}

func isReservedPlaceholderHost(host string) bool {
	normalized := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if normalized == "" {
		return false
	}
	if normalized == "example.com" || strings.HasSuffix(normalized, ".example.com") {
		return true
	}
	for _, suffix := range []string{".example", ".test", ".invalid"} {
		if strings.HasSuffix(normalized, suffix) {
			return true
		}
	}
	return false
}

type artifactTarget struct {
	name   string
	target string
}

func requireDistinctArtifactURLs(artifacts []artifactTarget) error {
	seen := make(map[string]string, len(artifacts))
	for _, artifact := range artifacts {
		normalized, err := canonicalArtifactURL(artifact.target)
		if err != nil {
			return fmt.Errorf("-%s artifact URL: %w", artifact.name, err)
		}
		if normalized == "" {
			continue
		}
		if previousName, ok := seen[normalized]; ok {
			return fmt.Errorf("-%s must be a distinct artifact URL from -%s", artifact.name, previousName)
		}
		seen[normalized] = artifact.name
	}
	return nil
}

func canonicalArtifactURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if host == "" {
		return "", errors.New("missing host")
	}
	if scheme == "https" && port == "443" {
		port = ""
	}
	if port != "" {
		parsed.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		parsed.Host = "[" + host + "]"
	} else {
		parsed.Host = host
	}
	parsed.Scheme = scheme
	parsed.Fragment = ""
	parsed.RawQuery = parsed.Query().Encode()
	return parsed.String(), nil
}

func isLocalOrPrivateHost(host string) bool {
	normalized := strings.Trim(strings.ToLower(host), "[]")
	if normalized == "localhost" {
		return true
	}
	ip := net.ParseIP(normalized)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast())
}

func forbiddenArtifactMarkers() []string {
	return []string{
		"terraform init failed",
		"terraform plan failed",
		"terraform apply failed",
		"apply failed",
		"plan failed",
		"rollout failed",
		"rollout status failed",
		"not rolled out",
		"availableReplicas: 0",
		"available replicas: 0",
		"readyReplicas: 0",
		"ready replicas: 0",
		"CrashLoopBackOff",
		"ImagePullBackOff",
		"mock",
		"mocked",
		"placeholder",
		"sample artifact",
		"synthetic",
		"stubbed",
		"test-only",
		"dry-run",
		"local-only",
		"localhost",
		"127.0.0.1",
	}
}

func failedProbe(name, target, summary string) probeResult {
	return probeResult{Name: name, Target: target, Passed: false, ResultSummary: summary}
}
