package main

import (
	"bytes"
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
	APIBase          string
	OwnerToken       string
	BlockedToken     string
	DBRLSArtifactURL string
	Timeout          time.Duration
}

type report struct {
	ObservedAt    string        `json:"observed_at"`
	APITarget     string        `json:"api_target"`
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
	flag.StringVar(&cfg.DBRLSArtifactURL, "db-rls-artifact-url", os.Getenv("STAGING_RLS_DB_PROOF_URL"), "redacted database/RLS proof artifact URL for current_user, app.current_org_id, and tenant table policies")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "per-probe timeout")
	flag.Parse()
	return cfg
}

func run(cfg config, output io.Writer) error {
	if cfg.APIBase == "" {
		return errors.New("-api-base is required")
	}
	if cfg.OwnerToken == "" {
		return errors.New("-owner-token or TENANT_PROBE_OWNER_TOKEN is required")
	}
	if cfg.BlockedToken == "" {
		return errors.New("-blocked-token or TENANT_PROBE_BLOCKED_TOKEN is required")
	}
	if cfg.DBRLSArtifactURL == "" {
		return errors.New("-db-rls-artifact-url or STAGING_RLS_DB_PROOF_URL is required")
	}
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	cfg.APIBase = strings.TrimRight(cfg.APIBase, "/")
	client := &http.Client{Timeout: cfg.Timeout}
	probes := make([]probeResult, 0, 5)

	marker := fmt.Sprintf("tenant-probe-%d", time.Now().UTC().UnixNano())
	createPayload := journalPayload{
		Ciphertext:  "ciphertext:" + marker,
		IV:          "iv:" + marker,
		SaltID:      "tenant-probe-salt:" + marker,
		SaltVersion: 1,
	}
	created, createProbe := createJournalEntry(client, cfg.APIBase, cfg.OwnerToken, createPayload)
	probes = append(probes, createProbe)
	if createProbe.Passed {
		probes = append(probes, getJournalEntry(client, cfg.APIBase, cfg.OwnerToken, created.ID, http.StatusOK, "owner-read-created-journal"))
		probes = append(probes, getJournalEntry(client, cfg.APIBase, cfg.BlockedToken, created.ID, http.StatusNotFound, "blocked-read-created-journal"))
		probes = append(probes, listDoesNotContainEntry(client, cfg.APIBase, cfg.BlockedToken, created.ID))
	}
	room, createRoomProbe := createRoom(client, cfg.APIBase, cfg.OwnerToken, "Tenant Isolation Room")
	probes = append(probes, createRoomProbe)
	if createRoomProbe.Passed {
		probes = append(probes, listRoomStateForTenant(client, cfg.APIBase, cfg.OwnerToken, room.ID, http.StatusOK, true, "owner-active-rooms-contains-created-room"))
		probes = append(probes, listRoomStateForTenant(client, cfg.APIBase, cfg.BlockedToken, room.ID, http.StatusOK, false, "blocked-active-rooms-excludes-created-room"))
		probes = append(probes, getRoomState(client, cfg.APIBase, cfg.OwnerToken, room.ID, "owner-room-state", http.StatusOK))
		probes = append(probes, getRoomState(client, cfg.APIBase, cfg.BlockedToken, room.ID, "blocked-room-state-denied", http.StatusForbidden))
	}
	probes = append(probes, probeDBRLSArtifact(client, cfg.DBRLSArtifactURL))

	result := report{
		ObservedAt:    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		APITarget:     cfg.APIBase,
		ThresholdPass: true,
		Probes:        probes,
		EvidenceItems: []string{"DATA-RLS-001"},
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

func probeDBRLSArtifact(client *http.Client, target string) probeResult {
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
	required := []string{
		"current_user",
		"non-superuser",
		"app.current_org_id",
		"row_security",
		"FORCE ROW LEVEL SECURITY",
		"journal_entries",
		"live_rooms",
		"ai_request_logs",
		"citation_trails",
		"cross-tenant write denied",
	}
	passed := resp.StatusCode >= 200 && resp.StatusCode < 300 && containsAllFold(text, required) && containsNoneFold(text, forbiddenSecretMarkers())
	return probeResult{
		Name:          "database-rls-context-proof",
		Target:        target,
		Passed:        passed,
		StatusCode:    resp.StatusCode,
		LatencyMS:     latency,
		ResultSummary: fmt.Sprintf("database RLS proof returned HTTP %d in %dms", resp.StatusCode, latency),
	}
}

func createJournalEntry(client *http.Client, apiBase, token string, payload journalPayload) (journalPayload, probeResult) {
	var created journalPayload
	body, _ := json.Marshal(payload)
	target := apiBase + "/api/v1/journal_entries"
	start := time.Now()
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
		ResultSummary: fmt.Sprintf("create returned HTTP %d in %dms", resp.StatusCode, latency),
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
	_, err = io.Copy(io.Discard, resp.Body)
	passed := resp.StatusCode == expectedStatus
	return probeResult{
		Name:          name,
		Target:        target,
		Passed:        passed,
		StatusCode:    resp.StatusCode,
		LatencyMS:     latency,
		ResultSummary: fmt.Sprintf("read returned HTTP %d in %dms", resp.StatusCode, latency),
	}
}

func listDoesNotContainEntry(client *http.Client, apiBase, token, id string) probeResult {
	target := apiBase + "/api/v1/journal_entries"
	start := time.Now()
	req, err := authorizedRequest(http.MethodGet, target, token, nil)
	if err != nil {
		return failedProbe("blocked-list-excludes-created-journal", target, err.Error())
	}
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return failedProbe("blocked-list-excludes-created-journal", target, err.Error())
	}
	defer resp.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	passed := resp.StatusCode == http.StatusOK && !bytes.Contains(responseBody, []byte(id))
	return probeResult{
		Name:          "blocked-list-excludes-created-journal",
		Target:        target,
		Passed:        passed,
		StatusCode:    resp.StatusCode,
		LatencyMS:     latency,
		ResultSummary: fmt.Sprintf("blocked list returned HTTP %d in %dms", resp.StatusCode, latency),
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
		ResultSummary: fmt.Sprintf("room create returned HTTP %d in %dms", resp.StatusCode, latency),
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
		ResultSummary: fmt.Sprintf("active rooms returned HTTP %d in %dms", resp.StatusCode, latency),
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
	_, _ = io.Copy(io.Discard, resp.Body)
	passed := resp.StatusCode == expectedStatus
	return probeResult{
		Name:          name,
		Target:        target,
		Passed:        passed,
		StatusCode:    resp.StatusCode,
		LatencyMS:     latency,
		ResultSummary: fmt.Sprintf("room state probe returned HTTP %d in %dms", resp.StatusCode, latency),
	}
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

func forbiddenSecretMarkers() []string {
	return []string{
		"postgres://",
		"postgresql://",
		"password=",
		"password:",
		"-----BEGIN",
	}
}

func failedProbe(name, target, summary string) probeResult {
	return probeResult{Name: name, Target: target, Passed: false, ResultSummary: summary}
}
