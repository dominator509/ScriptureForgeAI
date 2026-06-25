package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type config struct {
	ProbeSecrets      bool
	ProbeDBUser       bool
	ServiceAccountURL string
	SecretProviderURL string
	SyncedSecretURL   string
	IAMPolicyURL      string
	AccessTestURL     string
	DatabaseURL       string
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
	flag.BoolVar(&cfg.ProbeSecrets, "probe-secrets", false, "probe staged IRSA, Secrets Store CSI, and synced-secret metadata artifacts")
	flag.BoolVar(&cfg.ProbeDBUser, "probe-db-user", false, "connect with the staged DATABASE_URL and prove it is a scoped non-admin database principal")
	flag.StringVar(&cfg.ServiceAccountURL, "service-account-url", os.Getenv("STAGING_SERVICE_ACCOUNT_URL"), "URL for kubectl/get serviceaccount artifact")
	flag.StringVar(&cfg.SecretProviderURL, "secret-provider-url", os.Getenv("STAGING_SECRET_PROVIDER_URL"), "URL for SecretProviderClass artifact")
	flag.StringVar(&cfg.SyncedSecretURL, "synced-secret-url", os.Getenv("STAGING_SYNCED_SECRET_URL"), "URL for redacted Kubernetes synced-secret metadata artifact")
	flag.StringVar(&cfg.IAMPolicyURL, "iam-policy-url", os.Getenv("STAGING_IAM_POLICY_URL"), "URL for app workload IAM policy or access-analyzer artifact")
	flag.StringVar(&cfg.AccessTestURL, "access-test-url", os.Getenv("STAGING_SECRETS_ACCESS_TEST_URL"), "URL for scoped Secrets Manager allow/deny access test artifact")
	flag.StringVar(&cfg.DatabaseURL, "database-url", os.Getenv("STAGING_DATABASE_URL"), "staging application DATABASE_URL; never emitted in the report")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "per-probe timeout")
	flag.Parse()
	return cfg
}

func run(cfg config, output io.Writer) error {
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if !cfg.ProbeSecrets && !cfg.ProbeDBUser {
		return errors.New("at least one of -probe-secrets or -probe-db-user is required")
	}
	if cfg.ProbeSecrets {
		if cfg.ServiceAccountURL == "" || cfg.SecretProviderURL == "" || cfg.SyncedSecretURL == "" || cfg.IAMPolicyURL == "" || cfg.AccessTestURL == "" {
			return errors.New("-probe-secrets requires service account, SecretProviderClass, synced-secret, IAM policy, and scoped access-test artifact URLs")
		}
	}
	if cfg.ProbeDBUser && cfg.DatabaseURL == "" {
		return errors.New("-database-url or STAGING_DATABASE_URL is required for -probe-db-user")
	}

	client := &http.Client{Timeout: cfg.Timeout}
	probes := []probeResult{}
	evidenceItems := []string{}
	if cfg.ProbeSecrets {
		probes = append(probes,
			probeArtifact(client, "irsa-service-account", cfg.ServiceAccountURL, []string{"eks.amazonaws.com/role-arn", "scriptureforge"}, nil),
			probeArtifact(client, "secret-provider-class", cfg.SecretProviderURL, []string{"SecretProviderClass", "secrets-store.csi.k8s.io", "DATABASE_URL", "JWT_SECRET_KEY", "OPENAI_API_KEY", "ZOOM_WEBHOOK_SECRET_TOKEN"}, highConfidenceSecretValueMarkers()),
			probeArtifact(client, "synced-secret-metadata-redacted", cfg.SyncedSecretURL, []string{"scriptureforge-runtime-secrets", "DATABASE_URL", "JWT_SECRET_KEY"}, forbiddenSecretMarkers()),
			probeArtifact(client, "iam-secrets-policy", cfg.IAMPolicyURL, []string{"secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret", "arn:aws:secretsmanager:"}, nil),
			probeArtifact(client, "scoped-secrets-access-test", cfg.AccessTestURL, []string{"allowed", "configured secret", "denied", "unscoped secret", "AccessDenied"}, forbiddenSecretMarkers()),
		)
		evidenceItems = append(evidenceItems, "SEC-SECRETS-001")
	}
	if cfg.ProbeDBUser {
		probes = append(probes, probeDatabaseUser(cfg.DatabaseURL, cfg.Timeout))
		evidenceItems = append(evidenceItems, "SEC-DBUSER-001")
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
		return errors.New("one or more security probes failed")
	}
	return nil
}

func probeArtifact(client *http.Client, name, target string, required []string, forbidden []string) probeResult {
	start := time.Now()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	req.Header.Set("User-Agent", "scriptureforge-securityprobe/1.0")
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	text := string(body)
	passed := resp.StatusCode >= 200 && resp.StatusCode < 300 && containsAllFold(text, required) && containsNoneFold(text, forbidden)
	summary := fmt.Sprintf("got HTTP %d in %dms", resp.StatusCode, latency)
	if !passed {
		summary = fmt.Sprintf("%s; artifact did not satisfy required markers or redaction checks", summary)
	}
	return probeResult{Name: name, Target: target, Passed: passed, StatusCode: resp.StatusCode, LatencyMS: latency, ResultSummary: summary}
}

func probeDatabaseUser(databaseURL string, timeout time.Duration) probeResult {
	principal, err := databasePrincipal(databaseURL)
	if err != nil {
		return failedProbe("database-scoped-user", "redacted-database-url", err.Error())
	}
	if isPrivilegedPrincipal(principal) {
		return failedProbe("database-scoped-user", "redacted-database-url", fmt.Sprintf("database principal %q is privileged or reserved", principal))
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	pool, err := pgxpool.New(ctx, databaseURL)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe("database-scoped-user", "redacted-database-url", err.Error())
	}
	defer pool.Close()

	var currentUser string
	var isSuperuser, canCreateRole, canCreateDB bool
	err = pool.QueryRow(ctx, `
		SELECT current_user, rolsuper, rolcreaterole, rolcreatedb
		FROM pg_roles
		WHERE rolname = current_user
	`).Scan(&currentUser, &isSuperuser, &canCreateRole, &canCreateDB)
	latency = time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe("database-scoped-user", "redacted-database-url", err.Error())
	}
	passed := currentUser == principal && !isPrivilegedPrincipal(currentUser) && !isSuperuser && !canCreateRole && !canCreateDB
	summary := fmt.Sprintf("connected as %q in %dms; superuser=%t createrole=%t createdb=%t", currentUser, latency, isSuperuser, canCreateRole, canCreateDB)
	return probeResult{Name: "database-scoped-user", Target: "redacted-database-url", Passed: passed, LatencyMS: latency, ResultSummary: summary}
}

func databasePrincipal(databaseURL string) (string, error) {
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		return "", err
	}
	user := parsed.User.Username()
	if strings.TrimSpace(user) == "" {
		return "", errors.New("database URL did not include a username")
	}
	return user, nil
}

func isPrivilegedPrincipal(user string) bool {
	normalized := strings.ToLower(strings.TrimSpace(user))
	if normalized == "" {
		return true
	}
	privileged := []string{"postgres", "rdsadmin", "root", "admin", "aurora", "master"}
	for _, marker := range privileged {
		if normalized == marker || strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func forbiddenSecretMarkers() []string {
	return []string{
		"postgres://",
		"postgresql://",
		"sk-",
		"client_secret",
		"webhook_secret",
		"password:",
		"-----BEGIN",
	}
}

func highConfidenceSecretValueMarkers() []string {
	return []string{
		"postgres://",
		"postgresql://",
		"sk-",
		"-----BEGIN",
	}
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
