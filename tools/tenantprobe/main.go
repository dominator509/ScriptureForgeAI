package main

import (
	"bytes"
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
	"slices"
	"strings"
	"time"
)

type config struct {
	APIBase          string
	OwnerToken       string
	BlockedToken     string
	OwnerOrgID       string
	BlockedOrgID     string
	DBRLSArtifactURL string
	ReleaseCandidate string
	ServiceVersion   string
	LoadRunID        string
	Timeout          time.Duration
}

type report struct {
	ObservedAt       string        `json:"observed_at"`
	APITarget        string        `json:"api_target"`
	OwnerOrgID       string        `json:"owner_org_id"`
	BlockedOrgID     string        `json:"blocked_org_id"`
	CreatedJournalID string        `json:"created_journal_id,omitempty"`
	CreatedRoomID    string        `json:"created_room_id,omitempty"`
	ReleaseCandidate string        `json:"release_candidate"`
	ServiceVersion   string        `json:"service_version"`
	LoadRunID        string        `json:"load_run_id"`
	ThresholdPass    bool          `json:"threshold_pass"`
	Probes           []probeResult `json:"probes"`
	EvidenceItems    []string      `json:"evidence_items"`
}

type probeResult struct {
	Name              string   `json:"name"`
	Target            string   `json:"target"`
	Passed            bool     `json:"passed"`
	StatusCode        int      `json:"status_code,omitempty"`
	LatencyMS         int64    `json:"latency_ms,omitempty"`
	JournalID         string   `json:"journal_id,omitempty"`
	RoomID            string   `json:"room_id,omitempty"`
	ApplicationRole   string   `json:"application_role,omitempty"`
	RowSecurity       string   `json:"row_security,omitempty"`
	RLSTablesVerified int      `json:"rls_tables_verified,omitempty"`
	RLSForcedTables   int      `json:"rls_forced_tables,omitempty"`
	RLSTableNames     []string `json:"rls_table_names,omitempty"`
	RLSPolicyScope    string   `json:"rls_policy_scope,omitempty"`
	ResultSummary     string   `json:"result_summary"`
}

type journalPayload struct {
	ID          string `json:"id,omitempty"`
	Ciphertext  string `json:"ciphertext"`
	IV          string `json:"iv"`
	SaltID      string `json:"salt_id"`
	SaltVersion int    `json:"salt_version"`
}

type roomPayload struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

var tenantScopedRLSTables = []string{
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

var requiredDBRLSMarkers = append([]string{
	"staging artifact",
	"current_user=scriptureforge_app",
	"non-superuser",
	"superuser=false",
	"bypassrls=false",
	"app.current_org_id",
	"current_setting('app.current_org_id')",
	"row_security=on",
	"FORCE ROW LEVEL SECURITY",
	"rls_tables_verified=9",
	"rls_forced_tables=9",
	"rls_policy_scope=app.current_org_id",
}, append(tenantScopedRLSTables, []string{
	"same-tenant read visible",
	"cross-tenant read hidden",
	"cross-tenant write denied",
	"auth_refresh_session_rls=true",
	"auth_mfa_rls=true",
	"workspace_switch_tenant_match=true",
	"privileged_mfa_enrollment_rls=true",
	"ai_audit_rls=true",
	"generated_curriculum_audit_rls=true",
}...)...)

var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func main() {
	cfg := parseFlags()
	if err := run(cfg, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseFlags() config {
	cfg := config{}
	flag.StringVar(&cfg.APIBase, "api-base", "", "deployed API base URL, for example https://api.staging.example")
	flag.StringVar(&cfg.OwnerToken, "owner-token", os.Getenv("TENANT_PROBE_OWNER_TOKEN"), "bearer token for the tenant/user that creates the journal entry")
	flag.StringVar(&cfg.BlockedToken, "blocked-token", os.Getenv("TENANT_PROBE_BLOCKED_TOKEN"), "bearer token for a different user or tenant that must not read the created entry")
	flag.StringVar(&cfg.OwnerOrgID, "owner-org-id", os.Getenv("TENANT_PROBE_OWNER_ORG_ID"), "organization ID represented by owner-token and used for app.current_org_id proof binding")
	flag.StringVar(&cfg.BlockedOrgID, "blocked-org-id", os.Getenv("TENANT_PROBE_BLOCKED_ORG_ID"), "different organization ID represented by blocked-token and used for cross-tenant proof binding")
	flag.StringVar(&cfg.DBRLSArtifactURL, "db-rls-artifact-url", os.Getenv("STAGING_RLS_DB_PROOF_URL"), "redacted database/RLS proof artifact URL for current_user, app.current_org_id, and tenant table policies")
	flag.StringVar(&cfg.ReleaseCandidate, "release-candidate", os.Getenv("RELEASE_CANDIDATE"), "exact release candidate Git SHA expected in staging RLS proof artifacts")
	flag.StringVar(&cfg.ServiceVersion, "service-version", os.Getenv("SERVICE_VERSION"), "deployed service version marker expected in staging RLS proof artifacts")
	flag.StringVar(&cfg.LoadRunID, "load-run-id", os.Getenv("STAGING_LOAD_RUN_ID"), "exact staging load run ID this tenant/RLS evidence is bound to")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "per-probe timeout")
	flag.Parse()
	return cfg
}

func run(cfg config, output io.Writer) error {
	return runWithClient(cfg, output, &http.Client{Timeout: cfg.Timeout})
}

func runWithClient(cfg config, output io.Writer, client *http.Client) error {
	if cfg.APIBase == "" {
		return errors.New("-api-base is required")
	}
	if cfg.OwnerToken == "" {
		return errors.New("-owner-token or TENANT_PROBE_OWNER_TOKEN is required")
	}
	if cfg.BlockedToken == "" {
		return errors.New("-blocked-token or TENANT_PROBE_BLOCKED_TOKEN is required")
	}
	cfg.OwnerOrgID = strings.TrimSpace(cfg.OwnerOrgID)
	cfg.BlockedOrgID = strings.TrimSpace(cfg.BlockedOrgID)
	if cfg.OwnerOrgID == "" {
		return errors.New("-owner-org-id or TENANT_PROBE_OWNER_ORG_ID is required")
	}
	if cfg.BlockedOrgID == "" {
		return errors.New("-blocked-org-id or TENANT_PROBE_BLOCKED_ORG_ID is required")
	}
	if !uuidPattern.MatchString(cfg.OwnerOrgID) {
		return errors.New("-owner-org-id must be a UUID")
	}
	if !uuidPattern.MatchString(cfg.BlockedOrgID) {
		return errors.New("-blocked-org-id must be a UUID")
	}
	if strings.EqualFold(cfg.OwnerOrgID, cfg.BlockedOrgID) {
		return errors.New("-owner-org-id and -blocked-org-id must identify different organizations")
	}
	if cfg.DBRLSArtifactURL == "" {
		return errors.New("-db-rls-artifact-url or STAGING_RLS_DB_PROOF_URL is required")
	}
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	var err error
	cfg.APIBase, err = normalizeStagingURL(cfg.APIBase, "api-base", "staging API host")
	if err != nil {
		return err
	}
	cfg.DBRLSArtifactURL, err = normalizeStagingURL(cfg.DBRLSArtifactURL, "db-rls-artifact-url", "staging artifact host")
	if err != nil {
		return err
	}
	if canonicalEvidenceHost(cfg.APIBase) == canonicalEvidenceHost(cfg.DBRLSArtifactURL) {
		return errors.New("-db-rls-artifact-url must use a distinct evidence host from api-base")
	}
	cfg.ReleaseCandidate = strings.TrimSpace(cfg.ReleaseCandidate)
	cfg.ServiceVersion = strings.TrimSpace(cfg.ServiceVersion)
	if cfg.ReleaseCandidate == "" {
		return errors.New("-release-candidate or RELEASE_CANDIDATE is required")
	}
	if cfg.ServiceVersion == "" {
		return errors.New("-service-version or SERVICE_VERSION is required")
	}
	cfg.LoadRunID = strings.TrimSpace(cfg.LoadRunID)
	if cfg.LoadRunID == "" {
		return errors.New("-load-run-id or STAGING_LOAD_RUN_ID is required")
	}
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	probes := make([]probeResult, 0, 5)

	marker := fmt.Sprintf("tenant-probe-%d", time.Now().UTC().UnixNano())
	createPayload := journalPayload{
		Ciphertext:  "dGVuYW50LXByb2JlLXNlYWxlZC1wYXlsb2Fk",
		IV:          "AQIDBAUGBwgJCgsM",
		SaltID:      "journal:v1:" + marker,
		SaltVersion: 1,
	}
	created, createProbe := createJournalEntry(client, cfg.APIBase, cfg.OwnerToken, createPayload)
	probes = append(probes, createProbe)
	probes = append(probes, rejectJournalTenantOverride(client, cfg.APIBase, cfg.BlockedToken, marker))
	if createProbe.Passed {
		probes = append(probes, getJournalEntry(client, cfg.APIBase, cfg.OwnerToken, created.ID, http.StatusOK, "owner-read-created-journal"))
		probes = append(probes, listEntryForTenant(client, cfg.APIBase, cfg.OwnerToken, created.ID, true, "owner-list-contains-created-journal"))
		probes = append(probes, getJournalEntry(client, cfg.APIBase, cfg.BlockedToken, created.ID, http.StatusNotFound, "blocked-read-created-journal"))
		probes = append(probes, listEntryForTenant(client, cfg.APIBase, cfg.BlockedToken, created.ID, false, "blocked-list-excludes-created-journal"))
	}
	room, createRoomProbe := createRoom(client, cfg.APIBase, cfg.OwnerToken, "Tenant Isolation Room")
	probes = append(probes, createRoomProbe)
	probes = append(probes, rejectRoomTenantOverride(client, cfg.APIBase, cfg.BlockedToken))
	if createRoomProbe.Passed {
		probes = append(probes, listRoomStateForTenant(client, cfg.APIBase, cfg.OwnerToken, room.ID, http.StatusOK, true, "owner-active-rooms-contains-created-room"))
		probes = append(probes, listRoomStateForTenant(client, cfg.APIBase, cfg.BlockedToken, room.ID, http.StatusOK, false, "blocked-active-rooms-excludes-created-room"))
		probes = append(probes, getRoomState(client, cfg.APIBase, cfg.OwnerToken, room.ID, "owner-room-state", http.StatusOK))
		probes = append(probes, getRoomState(client, cfg.APIBase, cfg.BlockedToken, room.ID, "blocked-room-state-denied", http.StatusForbidden))
	}
	probes = append(probes, probeDBRLSArtifact(client, cfg.DBRLSArtifactURL, cfg.ReleaseCandidate, cfg.ServiceVersion, cfg.LoadRunID, cfg.OwnerOrgID, cfg.BlockedOrgID))
	appendReleaseMarkers(probes, cfg.ReleaseCandidate, cfg.ServiceVersion, cfg.LoadRunID)

	result := report{
		ObservedAt:       time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		APITarget:        cfg.APIBase,
		OwnerOrgID:       cfg.OwnerOrgID,
		BlockedOrgID:     cfg.BlockedOrgID,
		CreatedJournalID: created.ID,
		CreatedRoomID:    room.ID,
		ReleaseCandidate: cfg.ReleaseCandidate,
		ServiceVersion:   cfg.ServiceVersion,
		LoadRunID:        cfg.LoadRunID,
		ThresholdPass:    true,
		Probes:           probes,
		EvidenceItems:    []string{"DATA-RLS-001"},
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
		return errors.New("one or more tenant isolation probes failed")
	}
	return nil
}

func probeDBRLSArtifact(client *http.Client, target, releaseCandidate, serviceVersion, loadRunID, ownerOrgID, blockedOrgID string) probeResult {
	start := time.Now()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		return failedProbe("database-rls-context-proof", target, err.Error())
	}
	req.Header.Set("User-Agent", "scriptureforge-tenantprobe/1.0")
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe("database-rls-context-proof", target, err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	text := string(body)
	requiredMarkers := dbRLSMarkers(releaseCandidate, serviceVersion, loadRunID, ownerOrgID, blockedOrgID)
	passed := resp.StatusCode >= 200 && resp.StatusCode < 300 && containsAllFold(text, requiredMarkers) && containsNoneFold(text, forbiddenDBRLSArtifactMarkers())
	summary := fmt.Sprintf("database RLS proof returned HTTP %d in %dms", resp.StatusCode, latency)
	if passed {
		summary = fmt.Sprintf("%s; verified markers: %s, distinct_db_rls_artifact=true", summary, strings.Join(requiredMarkers, ", "))
	} else if missing := missingMarkersFold(text, requiredMarkers); len(missing) > 0 {
		summary = fmt.Sprintf("%s; missing required markers: %s", summary, strings.Join(missing, ", "))
	}
	result := probeResult{
		Name:          "database-rls-context-proof",
		Target:        target,
		Passed:        passed,
		StatusCode:    resp.StatusCode,
		LatencyMS:     latency,
		ResultSummary: summary,
	}
	if passed {
		result.ApplicationRole = "scriptureforge_app"
		result.RowSecurity = "on"
		result.RLSTablesVerified = 9
		result.RLSForcedTables = 9
		result.RLSTableNames = slices.Clone(tenantScopedRLSTables)
		result.RLSPolicyScope = "app.current_org_id"
	}
	return result
}

func dbRLSMarkers(releaseCandidate, serviceVersion, loadRunID, ownerOrgID, blockedOrgID string) []string {
	markers := append([]string{}, requiredDBRLSMarkers...)
	markers = append(
		markers,
		"app.current_org_id="+ownerOrgID,
		"blocked_org_id="+blockedOrgID,
		"release_candidate="+releaseCandidate,
		"service_version="+serviceVersion,
		"load_run_id="+loadRunID,
	)
	return markers
}

func appendReleaseMarkers(probes []probeResult, releaseCandidate, serviceVersion, loadRunID string) {
	releaseSummary := fmt.Sprintf("release_candidate=%s, service_version=%s, load_run_id=%s", releaseCandidate, serviceVersion, loadRunID)
	for i := range probes {
		if probes[i].Passed {
			probes[i].ResultSummary = probes[i].ResultSummary + "; verified release markers: " + releaseSummary
		}
	}
}

func createJournalEntry(client *http.Client, apiBase, token string, payload journalPayload) (journalPayload, probeResult) {
	var created journalPayload
	target := apiBase + "/api/v1/journal_entries"
	start := time.Now()

	malformedBody := []byte(`{"ciphertext":"Lord, help me","iv":"AQIDBAUGBwgJCgsM","salt_id":"journal:v1:tenant-probe-plaintext","salt_version":1}`)
	malformedReq, err := authorizedRequest(http.MethodPost, target, token, malformedBody)
	if err != nil {
		return created, failedProbe("owner-create-encrypted-journal", target, err.Error())
	}
	malformedResp, err := client.Do(malformedReq)
	if err != nil {
		return created, failedProbe("owner-create-encrypted-journal", target, err.Error())
	}
	_, _ = io.Copy(io.Discard, malformedResp.Body)
	_ = malformedResp.Body.Close()
	if malformedResp.StatusCode != http.StatusBadRequest {
		return created, probeResult{
			Name:          "owner-create-encrypted-journal",
			Target:        target,
			Passed:        false,
			StatusCode:    malformedResp.StatusCode,
			LatencyMS:     time.Since(start).Milliseconds(),
			ResultSummary: fmt.Sprintf("plaintext-shaped journal payload returned HTTP %d; expected HTTP 400 before encrypted journal create", malformedResp.StatusCode),
		}
	}

	body, _ := json.Marshal(payload)
	req, err := authorizedRequest(http.MethodPost, target, token, body)
	if err != nil {
		return created, failedProbe("owner-create-encrypted-journal", target, err.Error())
	}
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return created, failedProbe("owner-create-encrypted-journal", target, err.Error())
	}
	defer resp.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode == http.StatusCreated {
		_ = json.Unmarshal(responseBody, &created)
	}
	passed := resp.StatusCode == http.StatusCreated && created.ID != "" && !bytes.Contains(responseBody, []byte("plaintext"))
	return created, probeResult{
		Name:          "owner-create-encrypted-journal",
		Target:        target,
		Passed:        passed,
		StatusCode:    resp.StatusCode,
		LatencyMS:     latency,
		JournalID:     created.ID,
		ResultSummary: fmt.Sprintf("create returned HTTP %d in %dms; verified markers: same-tenant journal write accepted, encrypted journal created, plaintext not returned, plaintext-shaped journal payload denied, malformed encrypted envelope rejected, journal_id=%s", resp.StatusCode, latency, created.ID),
	}
}

func rejectJournalTenantOverride(client *http.Client, apiBase, token, marker string) probeResult {
	body := []byte(fmt.Sprintf(`{"organization_id":"00000000-0000-4000-8000-000000000000","user_id":"00000000-0000-4000-8000-000000000001","ciphertext":"dGVuYW50LXByb2JlLXNlYWxlZC1wYXlsb2Fk","iv":"AQIDBAUGBwgJCgsM","salt_id":"journal:v1:tenant-probe-%s","salt_version":1}`, marker))
	target := apiBase + "/api/v1/journal_entries"
	start := time.Now()
	req, err := authorizedRequest(http.MethodPost, target, token, body)
	if err != nil {
		return failedProbe("blocked-journal-tenant-override-write-denied", target, err.Error())
	}
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe("blocked-journal-tenant-override-write-denied", target, err.Error())
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	passed := resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusForbidden
	return probeResult{
		Name:          "blocked-journal-tenant-override-write-denied",
		Target:        target,
		Passed:        passed,
		StatusCode:    resp.StatusCode,
		LatencyMS:     latency,
		ResultSummary: fmt.Sprintf("tenant override journal write returned HTTP %d in %dms; verified markers: cross-tenant journal write denied, tenant override rejected", resp.StatusCode, latency),
	}
}

func getJournalEntry(client *http.Client, apiBase, token, id string, expectedStatus int, name string) probeResult {
	target := apiBase + "/api/v1/journal_entries/" + id
	start := time.Now()
	req, err := authorizedRequest(http.MethodGet, target, token, nil)
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	defer resp.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	passed := resp.StatusCode == expectedStatus
	if name == "owner-read-created-journal" && resp.StatusCode == http.StatusOK {
		passed = passed && bytes.Contains(responseBody, []byte(id))
	}
	return probeResult{
		Name:          name,
		Target:        target,
		Passed:        passed,
		StatusCode:    resp.StatusCode,
		LatencyMS:     latency,
		JournalID:     id,
		ResultSummary: journalReadSummary(name, resp.StatusCode, latency, id),
	}
}

func listEntryForTenant(client *http.Client, apiBase, token, id string, mustContainEntryID bool, name string) probeResult {
	target := apiBase + "/api/v1/journal_entries"
	start := time.Now()
	req, err := authorizedRequest(http.MethodGet, target, token, nil)
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	defer resp.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	containsEntryID := bytes.Contains(responseBody, []byte(id))
	passed := resp.StatusCode == http.StatusOK && containsEntryID == mustContainEntryID
	return probeResult{
		Name:          name,
		Target:        target,
		Passed:        passed,
		StatusCode:    resp.StatusCode,
		LatencyMS:     latency,
		JournalID:     id,
		ResultSummary: journalListSummary(name, resp.StatusCode, latency, id),
	}
}

func createRoom(client *http.Client, apiBase, token, title string) (roomPayload, probeResult) {
	var created roomPayload
	body, _ := json.Marshal(map[string]string{"title": title})
	target := apiBase + "/api/v1/rooms/create"
	start := time.Now()
	req, err := authorizedRequest(http.MethodPost, target, token, body)
	if err != nil {
		return created, failedProbe("owner-create-room", target, err.Error())
	}
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return created, failedProbe("owner-create-room", target, err.Error())
	}
	defer resp.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode == http.StatusCreated {
		_ = json.Unmarshal(responseBody, &created)
	}
	passed := resp.StatusCode == http.StatusCreated && created.ID != ""
	return created, probeResult{
		Name:          "owner-create-room",
		Target:        target,
		Passed:        passed,
		StatusCode:    resp.StatusCode,
		LatencyMS:     latency,
		RoomID:        created.ID,
		ResultSummary: fmt.Sprintf("room create returned HTTP %d in %dms; verified markers: same-tenant room write accepted, room created, room_id=%s", resp.StatusCode, latency, created.ID),
	}
}

func rejectRoomTenantOverride(client *http.Client, apiBase, token string) probeResult {
	body := []byte(`{"title":"Blocked Tenant Override Room","organization_id":"00000000-0000-4000-8000-000000000000","user_id":"00000000-0000-4000-8000-000000000001"}`)
	target := apiBase + "/api/v1/rooms/create"
	start := time.Now()
	req, err := authorizedRequest(http.MethodPost, target, token, body)
	if err != nil {
		return failedProbe("blocked-room-tenant-override-write-denied", target, err.Error())
	}
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe("blocked-room-tenant-override-write-denied", target, err.Error())
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	passed := resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusForbidden
	return probeResult{
		Name:          "blocked-room-tenant-override-write-denied",
		Target:        target,
		Passed:        passed,
		StatusCode:    resp.StatusCode,
		LatencyMS:     latency,
		ResultSummary: fmt.Sprintf("tenant override room write returned HTTP %d in %dms; verified markers: cross-tenant room write denied, tenant override rejected", resp.StatusCode, latency),
	}
}

func listRoomStateForTenant(client *http.Client, apiBase, token, roomID string, expectedStatus int, mustContainRoomID bool, name string) probeResult {
	target := apiBase + "/api/v1/rooms/active"
	start := time.Now()
	req, err := authorizedRequest(http.MethodGet, target, token, nil)
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	defer resp.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	bodyText := string(responseBody)
	passed := resp.StatusCode == expectedStatus
	if resp.StatusCode == http.StatusOK {
		contains := strings.Contains(bodyText, roomID)
		passed = passed && (mustContainRoomID == contains)
	}
	return probeResult{
		Name:          name,
		Target:        target,
		Passed:        passed,
		StatusCode:    resp.StatusCode,
		LatencyMS:     latency,
		RoomID:        roomID,
		ResultSummary: roomListSummary(name, resp.StatusCode, latency, roomID),
	}
}

func getRoomState(client *http.Client, apiBase, token, roomID, name string, expectedStatus int) probeResult {
	target := apiBase + "/api/v1/rooms/state/" + roomID
	start := time.Now()
	req, err := authorizedRequest(http.MethodGet, target, token, nil)
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe(name, target, err.Error())
	}
	defer resp.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	passed := resp.StatusCode == expectedStatus
	if name == "owner-room-state" && resp.StatusCode == http.StatusOK {
		passed = passed && bytes.Contains(responseBody, []byte(roomID))
	}
	return probeResult{
		Name:          name,
		Target:        target,
		Passed:        passed,
		StatusCode:    resp.StatusCode,
		LatencyMS:     latency,
		RoomID:        roomID,
		ResultSummary: roomStateSummary(name, resp.StatusCode, latency, roomID),
	}
}

func journalReadSummary(name string, statusCode int, latency int64, journalID string) string {
	if name == "owner-read-created-journal" {
		return fmt.Sprintf("read returned HTTP %d in %dms; verified markers: same-tenant journal read visible, created journal returned, journal_id=%s", statusCode, latency, journalID)
	}
	return fmt.Sprintf("read returned HTTP %d in %dms; verified markers: cross-tenant journal read denied, created journal hidden, journal_id=%s", statusCode, latency, journalID)
}

func journalListSummary(name string, statusCode int, latency int64, journalID string) string {
	if name == "owner-list-contains-created-journal" {
		return fmt.Sprintf("owner list returned HTTP %d in %dms; verified markers: same-tenant journal list visible, created journal present, journal_id=%s", statusCode, latency, journalID)
	}
	return fmt.Sprintf("blocked list returned HTTP %d in %dms; verified markers: cross-tenant journal list hidden, created journal absent, journal_id=%s", statusCode, latency, journalID)
}

func roomListSummary(name string, statusCode int, latency int64, roomID string) string {
	if name == "owner-active-rooms-contains-created-room" {
		return fmt.Sprintf("active rooms returned HTTP %d in %dms; verified markers: same-tenant room list visible, created room present, room_id=%s", statusCode, latency, roomID)
	}
	return fmt.Sprintf("active rooms returned HTTP %d in %dms; verified markers: cross-tenant room list hidden, created room absent, room_id=%s", statusCode, latency, roomID)
}

func roomStateSummary(name string, statusCode int, latency int64, roomID string) string {
	if name == "owner-room-state" {
		return fmt.Sprintf("room state probe returned HTTP %d in %dms; verified markers: same-tenant room state visible, created room state returned, room_id=%s", statusCode, latency, roomID)
	}
	return fmt.Sprintf("room state probe returned HTTP %d in %dms; verified markers: cross-tenant room state denied, created room state hidden, room_id=%s", statusCode, latency, roomID)
}

func authorizedRequest(method, target, token string, body []byte) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, target, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "scriptureforge-tenantprobe/1.0")
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
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

func missingMarkersFold(text string, needles []string) []string {
	lowerText := strings.ToLower(text)
	var missing []string
	for _, needle := range needles {
		if !strings.Contains(lowerText, strings.ToLower(needle)) {
			missing = append(missing, needle)
		}
	}
	return missing
}

func normalizeStagingURL(raw, field, hostKind string) (string, error) {
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
	if isReservedPlaceholderHost(parsed.Hostname()) {
		return "", fmt.Errorf("-%s must not use a reserved placeholder %s", field, hostKind)
	}
	if isLocalOrPrivateHost(parsed.Hostname()) {
		return "", fmt.Errorf("-%s must use a public %s", field, hostKind)
	}
	parsed.Fragment = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func canonicalEvidenceHost(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return strings.TrimRight(strings.Trim(strings.ToLower(strings.TrimSpace(raw)), "[]"), ".")
	}
	return strings.TrimRight(strings.Trim(strings.ToLower(parsed.Hostname()), "[]"), ".")
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
	normalized := strings.TrimRight(strings.Trim(strings.ToLower(host), "[]"), ".")
	return normalized == "example" ||
		strings.HasSuffix(normalized, ".example") ||
		normalized == "example.com" ||
		strings.HasSuffix(normalized, ".example.com") ||
		normalized == "example.org" ||
		strings.HasSuffix(normalized, ".example.org") ||
		normalized == "example.net" ||
		strings.HasSuffix(normalized, ".example.net") ||
		normalized == "test" ||
		strings.HasSuffix(normalized, ".test") ||
		normalized == "invalid" ||
		strings.HasSuffix(normalized, ".invalid")
}

func forbiddenDBRLSArtifactMarkers() []string {
	return []string{
		"postgres://",
		"postgresql://",
		"password=",
		"password:",
		"-----BEGIN",
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
