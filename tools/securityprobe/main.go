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
	ReleaseCandidate  string
	ServiceVersion    string
	LoadRunID         string
	Timeout           time.Duration
}

var concreteIAMRoleARNPattern = regexp.MustCompile(`\brole_arn=(arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+)\b`)

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
	Name                      string   `json:"name"`
	Target                    string   `json:"target"`
	Passed                    bool     `json:"passed"`
	StatusCode                int      `json:"status_code,omitempty"`
	LatencyMS                 int64    `json:"latency_ms,omitempty"`
	RoleARN                   string   `json:"role_arn,omitempty"`
	CurrentUser               string   `json:"current_user,omitempty"`
	Superuser                 *bool    `json:"superuser,omitempty"`
	BypassRLS                 *bool    `json:"bypassrls,omitempty"`
	CreateRole                *bool    `json:"createrole,omitempty"`
	CreateDB                  *bool    `json:"createdb,omitempty"`
	PrivilegedOperationDenied *bool    `json:"privileged_operation_denied,omitempty"`
	AppGrantsVerified         *bool    `json:"app_grants_verified,omitempty"`
	AppGrantTables            int      `json:"app_grant_tables,omitempty"`
	AppGrantTableNames        []string `json:"app_grant_table_names,omitempty"`
	AppGrants                 []string `json:"app_grants,omitempty"`
	ResultSummary             string   `json:"result_summary"`
}

var requiredApplicationGrantTables = []string{
	"organizations",
	"users",
	"scripture_texts",
	"refresh_tokens",
	"journal_entries",
	"live_rooms",
	"room_participants",
	"ai_request_logs",
	"citation_trails",
}

var requiredApplicationGrantPrivileges = []string{"SELECT", "INSERT", "UPDATE", "DELETE"}

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
	flag.StringVar(&cfg.ReleaseCandidate, "release-candidate", os.Getenv("STAGING_RELEASE_CANDIDATE"), "exact git SHA or release candidate represented by this security evidence")
	flag.StringVar(&cfg.ServiceVersion, "service-version", os.Getenv("STAGING_SECURITY_SERVICE_VERSION"), "exact API/service version represented by this security evidence")
	flag.StringVar(&cfg.LoadRunID, "load-run-id", os.Getenv("STAGING_LOAD_RUN_ID"), "staging evidence run identifier shared by security artifact and database-user proof")
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
	cfg.ReleaseCandidate = strings.TrimSpace(cfg.ReleaseCandidate)
	cfg.ServiceVersion = strings.TrimSpace(cfg.ServiceVersion)
	cfg.LoadRunID = strings.TrimSpace(cfg.LoadRunID)
	if cfg.ReleaseCandidate == "" || cfg.ServiceVersion == "" || cfg.LoadRunID == "" {
		return errors.New("security proof requires release-candidate, service-version, and load-run-id")
	}
	var err error
	if cfg.ProbeSecrets {
		cfg.ServiceAccountURL, err = normalizeArtifactURL(cfg.ServiceAccountURL, "service-account-url")
		if err != nil {
			return err
		}
		cfg.SecretProviderURL, err = normalizeArtifactURL(cfg.SecretProviderURL, "secret-provider-url")
		if err != nil {
			return err
		}
		cfg.SyncedSecretURL, err = normalizeArtifactURL(cfg.SyncedSecretURL, "synced-secret-url")
		if err != nil {
			return err
		}
		cfg.IAMPolicyURL, err = normalizeArtifactURL(cfg.IAMPolicyURL, "iam-policy-url")
		if err != nil {
			return err
		}
		cfg.AccessTestURL, err = normalizeArtifactURL(cfg.AccessTestURL, "access-test-url")
		if err != nil {
			return err
		}
		if err := requireDistinctArtifactURLs([]artifactTarget{
			{name: "service-account-url", target: cfg.ServiceAccountURL},
			{name: "secret-provider-url", target: cfg.SecretProviderURL},
			{name: "synced-secret-url", target: cfg.SyncedSecretURL},
			{name: "iam-policy-url", target: cfg.IAMPolicyURL},
			{name: "access-test-url", target: cfg.AccessTestURL},
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
	if cfg.ProbeSecrets {
		probes = append(probes,
			probeArtifact(client, "irsa-service-account", cfg.ServiceAccountURL, append([]string{"staging artifact", "namespace=staging", "service_account=scriptureforge-api", "role_arn=arn:aws:iam::", "eks.amazonaws.com/role-arn", "scriptureforge", "trust policy", "sts:AssumeRoleWithWebIdentity"}, releaseMarkers...), nil, true),
			probeArtifact(client, "secret-provider-class", cfg.SecretProviderURL, append([]string{"staging artifact", "namespace=staging", "service_account=scriptureforge-api", "role_arn=arn:aws:iam::", "SecretProviderClass", "secrets-store.csi.k8s.io", "provider", "aws", "objects", "objectName", "objectType", "secretsmanager", "objectAlias", "jmesPath", "secretObjects", "type", "Opaque", "DATABASE_URL", "JWT_SECRET_KEY", "OPENAI_API_KEY", "ZOOM_WEBHOOK_SECRET_TOKEN"}, releaseMarkers...), highConfidenceSecretValueMarkers(), true),
			probeArtifact(client, "synced-secret-metadata-redacted", cfg.SyncedSecretURL, append([]string{"staging artifact", "namespace=staging", "scriptureforge-runtime-secrets", "type", "Opaque", "DATABASE_URL", "JWT_SECRET_KEY", "OPENAI_API_KEY", "ZOOM_WEBHOOK_SECRET_TOKEN", "redacted", "stringData absent", "managed by secrets-store.csi.k8s.io", "ownerReferences", "secrets-store.csi.k8s.io/managed=true"}, releaseMarkers...), forbiddenSecretMarkers(), false),
			probeArtifact(client, "iam-secrets-policy", cfg.IAMPolicyURL, append([]string{"staging artifact", "role_arn=arn:aws:iam::", "secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret", "arn:aws:secretsmanager:", "scoped resource", "no wildcard resources"}, releaseMarkers...), forbiddenIAMPolicyMarkers(), true),
			probeArtifact(client, "scoped-secrets-access-test", cfg.AccessTestURL, append([]string{"staging artifact", "namespace=staging", "service_account=scriptureforge-api", "role_arn=arn:aws:iam::", "allowed", "configured secret", "denied", "unscoped secret", "AccessDenied", "distinct_secret_artifacts=true"}, releaseMarkers...), forbiddenSecretMarkers(), true),
		)
		enforceConsistentSecretRoleARNs(probes)
		evidenceItems = append(evidenceItems, "SEC-SECRETS-001")
	}
	if cfg.ProbeDBUser {
		probes = append(probes, probeDatabaseUser(cfg.DatabaseURL, cfg.Timeout, releaseMarkers))
		evidenceItems = append(evidenceItems, "SEC-DBUSER-001")
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
		return errors.New("one or more security probes failed")
	}
	return nil
}

func probeArtifact(client *http.Client, name, target string, required []string, forbidden []string, requireConcreteRoleARN bool) probeResult {
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
	roleARN := ""
	if passed && requireConcreteRoleARN {
		roleARN = concreteIAMRoleARN(text)
		if roleARN == "" {
			passed = false
		} else {
			required = append(required, "role_arn="+roleARN)
		}
	}
	summary := fmt.Sprintf("got HTTP %d in %dms", resp.StatusCode, latency)
	if passed {
		summary = fmt.Sprintf("%s; verified markers: %s", summary, strings.Join(required, ", "))
	} else {
		summary = fmt.Sprintf("%s; artifact did not satisfy required markers or redaction checks", summary)
	}
	return probeResult{Name: name, Target: target, Passed: passed, StatusCode: resp.StatusCode, LatencyMS: latency, RoleARN: roleARN, ResultSummary: summary}
}

func concreteIAMRoleARN(text string) string {
	matches := concreteIAMRoleARNPattern.FindStringSubmatch(text)
	if len(matches) != 2 {
		return ""
	}
	return matches[1]
}

func enforceConsistentSecretRoleARNs(probes []probeResult) {
	expected := ""
	mismatch := false
	for _, probe := range probes {
		if probe.RoleARN == "" {
			continue
		}
		if expected == "" {
			expected = probe.RoleARN
			continue
		}
		if probe.RoleARN != expected {
			mismatch = true
			break
		}
	}
	if !mismatch {
		return
	}
	for i := range probes {
		if probes[i].RoleARN == "" {
			continue
		}
		probes[i].Passed = false
		probes[i].ResultSummary = probes[i].ResultSummary + "; role_arn_mismatch=true"
	}
}

func probeDatabaseUser(databaseURL string, timeout time.Duration, releaseMarkers []string) probeResult {
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
	var isSuperuser, canBypassRLS, canCreateRole, canCreateDB bool
	err = pool.QueryRow(ctx, `
		SELECT current_user, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb
		FROM pg_roles
		WHERE rolname = current_user
	`).Scan(&currentUser, &isSuperuser, &canBypassRLS, &canCreateRole, &canCreateDB)
	latency = time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe("database-scoped-user", "redacted-database-url", err.Error())
	}
	privilegedOperationDenied, privilegeErr := privilegedOperationIsDenied(ctx, pool)
	latency = time.Since(start).Milliseconds()
	if privilegeErr != nil {
		return failedProbe("database-scoped-user", "redacted-database-url", privilegeErr.Error())
	}
	appGrantsVerified, grantErr := applicationGrantsArePresent(ctx, pool)
	latency = time.Since(start).Milliseconds()
	if grantErr != nil {
		return failedProbe("database-scoped-user", "redacted-database-url", grantErr.Error())
	}
	passed := currentUser == principal && !isPrivilegedPrincipal(currentUser) && !isSuperuser && !canBypassRLS && !canCreateRole && !canCreateDB && privilegedOperationDenied && appGrantsVerified
	summary := fmt.Sprintf("connected as %q in %dms; current_user=%s superuser=%t bypassrls=%t createrole=%t createdb=%t privileged_operation_denied=%t app_grants_verified=%t app_grant_tables=%d app_grant_table_names=%s app_grants=%s; verified markers: staging artifact, %s", currentUser, latency, currentUser, isSuperuser, canBypassRLS, canCreateRole, canCreateDB, privilegedOperationDenied, appGrantsVerified, len(requiredApplicationGrantTables), strings.Join(requiredApplicationGrantTables, ","), strings.Join(requiredApplicationGrantPrivileges, ","), strings.Join(releaseMarkers, ", "))
	return probeResult{
		Name:                      "database-scoped-user",
		Target:                    "redacted-database-url",
		Passed:                    passed,
		LatencyMS:                 latency,
		CurrentUser:               currentUser,
		Superuser:                 boolPtr(isSuperuser),
		BypassRLS:                 boolPtr(canBypassRLS),
		CreateRole:                boolPtr(canCreateRole),
		CreateDB:                  boolPtr(canCreateDB),
		PrivilegedOperationDenied: boolPtr(privilegedOperationDenied),
		AppGrantsVerified:         boolPtr(appGrantsVerified),
		AppGrantTables:            len(requiredApplicationGrantTables),
		AppGrantTableNames:        requiredApplicationGrantTables,
		AppGrants:                 requiredApplicationGrantPrivileges,
		ResultSummary:             summary,
	}
}

func boolPtr(value bool) *bool {
	return &value
}

func applicationGrantsArePresent(ctx context.Context, pool *pgxpool.Pool) (bool, error) {
	var schemaUsage bool
	if err := pool.QueryRow(ctx, `SELECT has_schema_privilege(current_user, 'public', 'USAGE')`).Scan(&schemaUsage); err != nil {
		return false, err
	}
	if !schemaUsage {
		return false, nil
	}
	for _, table := range requiredApplicationGrantTables {
		for _, privilege := range requiredApplicationGrantPrivileges {
			var granted bool
			if err := pool.QueryRow(ctx, `SELECT has_table_privilege(current_user, $1, $2)`, "public."+table, privilege).Scan(&granted); err != nil {
				return false, err
			}
			if !granted {
				return false, nil
			}
		}
	}
	return true, nil
}

func privilegedOperationIsDenied(ctx context.Context, pool *pgxpool.Pool) (bool, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)

	roleName := fmt.Sprintf("scriptureforge_privilege_probe_%d", time.Now().UnixNano())
	_, err = tx.Exec(ctx, `CREATE ROLE `+roleName)
	if err == nil {
		return false, nil
	}
	denialText := strings.ToLower(err.Error())
	if strings.Contains(denialText, "permission denied") ||
		strings.Contains(denialText, "must be superuser") ||
		strings.Contains(denialText, "insufficient privilege") ||
		strings.Contains(denialText, "sqlstate 42501") {
		return true, nil
	}
	return false, err
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

func isReservedPlaceholderHost(host string) bool {
	normalized := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if normalized == "" {
		return false
	}
	return strings.HasSuffix(normalized, ".example") ||
		normalized == "example.com" ||
		strings.HasSuffix(normalized, ".example.com") ||
		normalized == "example.org" ||
		strings.HasSuffix(normalized, ".example.org") ||
		normalized == "example.net" ||
		strings.HasSuffix(normalized, ".example.net") ||
		strings.HasSuffix(normalized, ".test") ||
		strings.HasSuffix(normalized, ".invalid")
}

func forbiddenSecretMarkers() []string {
	return []string{
		"local-only",
		"postgres://",
		"postgresql://",
		"cg9zdgdyzxm6ly8",
		"cg9zdgdyzxnxbcdovlw",
		"sk-",
		"c2st",
		"client_secret=",
		"client_secret:",
		"webhook_secret=",
		"webhook_secret:",
		"password:",
		"stringdata:",
		"-----BEGIN",
	}
}

func highConfidenceSecretValueMarkers() []string {
	return []string{
		"postgres://",
		"postgresql://",
		"cg9zdgdyzxm6ly8",
		"cg9zdgdyzxnxbcdovlw",
		"sk-",
		"c2st",
		"stringdata:",
		"-----BEGIN",
	}
}

func forbiddenIAMPolicyMarkers() []string {
	markers := forbiddenSecretMarkers()
	return append(markers,
		`"Resource":"*"`,
		`"Resource": "*"`,
		`Resource=*`,
		`resource=*`,
		`Action=*`,
		`action=*`,
	)
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
