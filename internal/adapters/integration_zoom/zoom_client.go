package integration_zoom

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"scriptureforge/internal/domain/observability"
	"scriptureforge/internal/domain/room"
)

type ZoomClient struct {
	AccountID        string
	ClientID         string
	ClientSecret     string
	HTTPClient       *http.Client
	MaxRetries       int
	mu               sync.Mutex
	failures         int
	circuitOpenUntil time.Time
}

const (
	defaultZoomHTTPTimeout   = 3500 * time.Millisecond
	maxZoomHTTPTimeout       = 30 * time.Second
	defaultZoomMaxRetries    = 2
	maxZoomMaxRetries        = 3
	maxZoomResponseBodyBytes = 1 << 20
)

var (
	errZoomResponseBodyTooLarge = errors.New("zoom response body exceeds the maximum size")
	errZoomResponseBodyMissing  = errors.New("zoom response body is missing")
)

func newZoomIdempotencyKey() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func validateZoomMeetingID(meetingID string) (string, error) {
	meetingID = strings.TrimSpace(meetingID)
	if meetingID == "" || len(meetingID) > 64 {
		return "", errors.New("zoom meeting id is invalid")
	}
	for _, character := range meetingID {
		if character < '0' || character > '9' {
			return "", errors.New("zoom meeting id is invalid")
		}
	}
	return meetingID, nil
}

func validateZoomMeetingURL(raw string) error {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Path == "" {
		return errors.New("zoom meeting URL is invalid")
	}
	host := strings.ToLower(parsed.Hostname())
	if host != "zoom.us" && !strings.HasSuffix(host, ".zoom.us") {
		return errors.New("zoom meeting URL host is invalid")
	}
	return nil
}

func NewZoomClient() *ZoomClient {
	return &ZoomClient{
		AccountID:    strings.TrimSpace(os.Getenv("ZOOM_ACCOUNT_ID")),
		ClientID:     strings.TrimSpace(os.Getenv("ZOOM_CLIENT_ID")),
		ClientSecret: strings.TrimSpace(os.Getenv("ZOOM_CLIENT_SECRET")),
		HTTPClient:   newZoomHTTPClient(zoomHTTPTimeout()),
		MaxRetries:   zoomMaxRetries(),
	}
}

func newZoomHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 || timeout > maxZoomHTTPTimeout {
		timeout = defaultZoomHTTPTimeout
	}
	return &http.Client{
		Timeout: timeout,
		// Zoom requests carry OAuth bearer credentials. Never follow a redirect
		// that could move those credentials to an unexpected origin.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func zoomHTTPTimeout() time.Duration {
	value := strings.TrimSpace(os.Getenv("ZOOM_HTTP_TIMEOUT_MS"))
	if value == "" {
		return defaultZoomHTTPTimeout
	}
	millis, err := strconv.Atoi(value)
	if err != nil || millis <= 0 {
		return defaultZoomHTTPTimeout
	}
	timeout := time.Duration(millis) * time.Millisecond
	if timeout > maxZoomHTTPTimeout {
		return maxZoomHTTPTimeout
	}
	return timeout
}

func zoomMaxRetries() int {
	value := strings.TrimSpace(os.Getenv("ZOOM_MAX_RETRIES"))
	if value == "" {
		return defaultZoomMaxRetries
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return defaultZoomMaxRetries
	}
	if parsed > maxZoomMaxRetries {
		return maxZoomMaxRetries
	}
	return parsed
}

func (c *ZoomClient) httpClient() *http.Client {
	if c != nil && c.HTTPClient != nil {
		return c.HTTPClient
	}
	return newZoomHTTPClient(defaultZoomHTTPTimeout)
}

func (c *ZoomClient) circuitOpen() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Before(c.circuitOpenUntil)
}

func (c *ZoomClient) recordResult(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.failures = 0
		c.circuitOpenUntil = time.Time{}
		return
	}
	c.failures++
	if c.failures >= 3 {
		c.circuitOpenUntil = time.Now().Add(60 * time.Second)
	}
}

func offlineMeetingDetails(config room.MeetingConfig) *room.MeetingDetails {
	return &room.MeetingDetails{
		ID:       fmt.Sprintf("offline-%d", time.Now().UnixNano()),
		JoinURL:  "offline://in-person",
		StartURL: "offline://host/" + config.HostID,
	}
}

func observeZoom(ctx context.Context, operation, status string, start time.Time) {
	observability.ObserveDependencyFromContext(ctx, "zoom", operation, status, time.Since(start))
}

func readZoomResponseBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errZoomResponseBodyMissing
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxZoomResponseBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxZoomResponseBodyBytes {
		return nil, errZoomResponseBodyTooLarge
	}
	return body, nil
}

func (c *ZoomClient) doWithRetry(buildRequest func() (*http.Request, error)) (*http.Response, error) {
	maxRetries := 0
	if c != nil {
		maxRetries = c.MaxRetries
	}
	if maxRetries < 0 {
		maxRetries = 0
	}
	if maxRetries > maxZoomMaxRetries {
		maxRetries = maxZoomMaxRetries
	}
	attempts := maxRetries + 1
	client := c.httpClient()
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		req, err := buildRequest()
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
		} else if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
			lastErr = fmt.Errorf("transient zoom status: %d", resp.StatusCode)
			if attempt == attempts-1 {
				return resp, nil
			}
			if resp.Body != nil {
				_ = resp.Body.Close()
			}
		} else {
			return resp, nil
		}
	}
	return nil, lastErr
}

// getAccessToken executes the Server-to-Server OAuth flow.
func (c *ZoomClient) getAccessToken(ctx context.Context) (string, error) {
	accountID := strings.TrimSpace(c.AccountID)
	clientID := strings.TrimSpace(c.ClientID)
	clientSecret := strings.TrimSpace(c.ClientSecret)
	if accountID == "" || clientID == "" || clientSecret == "" {
		return "", fmt.Errorf("zoom credentials are not fully configured")
	}

	tokenURL := fmt.Sprintf("https://zoom.us/oauth/token?grant_type=account_credentials&account_id=%s", url.QueryEscape(accountID))
	resp, err := c.doWithRetry(func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, nil)
		if err != nil {
			return nil, err
		}
		req.SetBasicAuth(clientID, clientSecret)
		return req, nil
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to retrieve zoom access token, status: %d", resp.StatusCode)
	}

	responseBody, err := readZoomResponseBody(resp)
	if err != nil {
		return "", err
	}
	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(responseBody, &tokenResp); err != nil {
		return "", err
	}
	if strings.TrimSpace(tokenResp.AccessToken) == "" {
		return "", errors.New("zoom access token is missing")
	}
	return tokenResp.AccessToken, nil
}

func (c *ZoomClient) CreateMeeting(ctx context.Context, config room.MeetingConfig) (*room.MeetingDetails, error) {
	start := time.Now()
	if c.circuitOpen() {
		observeZoom(ctx, "create_meeting", "circuit_open_fallback", start)
		return offlineMeetingDetails(config), nil
	}
	token, err := c.getAccessToken(ctx)
	if err != nil {
		c.recordResult(err)
		observeZoom(ctx, "create_meeting", "credential_or_token_fallback", start)
		return offlineMeetingDetails(config), nil
	}
	type zoomMeetingSettings struct {
		HostVideo        bool `json:"host_video"`
		ParticipantVideo bool `json:"participant_video"`
		JoinBeforeHost   bool `json:"join_before_host"`
	}

	type zoomMeetingPayload struct {
		Topic    string              `json:"topic"`
		Type     int                 `json:"type"`
		Duration int                 `json:"duration"`
		Password string              `json:"password"`
		Settings zoomMeetingSettings `json:"settings"`
	}

	payload := zoomMeetingPayload{
		Topic:    config.Topic,
		Type:     2, // Scheduled meeting
		Duration: config.Duration,
		Password: config.Password,
		Settings: zoomMeetingSettings{
			HostVideo:        true,
			ParticipantVideo: false,
			JoinBeforeHost:   false,
		},
	}
	body, _ := json.Marshal(payload)
	idempotencyKey, err := newZoomIdempotencyKey()
	if err != nil {
		c.recordResult(err)
		observeZoom(ctx, "create_meeting", "idempotency_key_error", start)
		return offlineMeetingDetails(config), nil
	}

	resp, err := c.doWithRetry(func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.zoom.us/v2/users/me/meetings", bytes.NewBuffer(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", idempotencyKey)
		return req, nil
	})
	if err != nil {
		c.recordResult(err)
		observeZoom(ctx, "create_meeting", "provider_error_fallback", start)
		return offlineMeetingDetails(config), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		if _, err := readZoomResponseBody(resp); err != nil {
			c.recordResult(err)
			observeZoom(ctx, "create_meeting", "response_body_error", start)
		} else {
			err := fmt.Errorf("zoom API error on creation: %d", resp.StatusCode)
			c.recordResult(err)
			observeZoom(ctx, "create_meeting", strconv.Itoa(resp.StatusCode), start)
		}
		return offlineMeetingDetails(config), nil
	}

	responseBody, err := readZoomResponseBody(resp)
	if err != nil {
		c.recordResult(err)
		observeZoom(ctx, "create_meeting", "response_body_error", start)
		return offlineMeetingDetails(config), nil
	}
	var meetingResp struct {
		Id       int64  `json:"id"`
		JoinUrl  string `json:"join_url"`
		StartUrl string `json:"start_url"`
	}
	if err := json.Unmarshal(responseBody, &meetingResp); err != nil {
		c.recordResult(err)
		observeZoom(ctx, "create_meeting", "response_decode_error", start)
		return offlineMeetingDetails(config), nil
	}
	if meetingResp.Id <= 0 || strings.TrimSpace(meetingResp.JoinUrl) == "" || strings.TrimSpace(meetingResp.StartUrl) == "" {
		err := errors.New("zoom meeting response is missing required fields")
		c.recordResult(err)
		observeZoom(ctx, "create_meeting", "response_validation_error", start)
		return offlineMeetingDetails(config), nil
	}
	if err := validateZoomMeetingURL(meetingResp.JoinUrl); err != nil {
		c.recordResult(err)
		observeZoom(ctx, "create_meeting", "response_validation_error", start)
		return offlineMeetingDetails(config), nil
	}
	if err := validateZoomMeetingURL(meetingResp.StartUrl); err != nil {
		c.recordResult(err)
		observeZoom(ctx, "create_meeting", "response_validation_error", start)
		return offlineMeetingDetails(config), nil
	}
	c.recordResult(nil)
	observeZoom(ctx, "create_meeting", "success", start)

	return &room.MeetingDetails{
		ID:       fmt.Sprintf("%d", meetingResp.Id),
		JoinURL:  meetingResp.JoinUrl,
		StartURL: meetingResp.StartUrl,
	}, nil
}

func (c *ZoomClient) TerminateMeeting(ctx context.Context, meetingID string) error {
	start := time.Now()
	if c.circuitOpen() {
		observeZoom(ctx, "terminate_meeting", "circuit_open", start)
		return nil
	}
	meetingID, err := validateZoomMeetingID(meetingID)
	if err != nil {
		return err
	}
	token, err := c.getAccessToken(ctx)
	if err != nil {
		c.recordResult(err)
		observeZoom(ctx, "terminate_meeting", "credential_or_token_error", start)
		return err
	}
	type zoomActionPayload struct {
		Action string `json:"action"`
	}
	payload := zoomActionPayload{Action: "end"}
	body, _ := json.Marshal(payload)

	requestURL := fmt.Sprintf("https://api.zoom.us/v2/meetings/%s/status", url.PathEscape(meetingID))
	resp, err := c.doWithRetry(func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, requestURL, bytes.NewBuffer(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	})
	if err != nil {
		c.recordResult(err)
		observeZoom(ctx, "terminate_meeting", "provider_error", start)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		err := fmt.Errorf("zoom API error on termination: %d", resp.StatusCode)
		c.recordResult(err)
		observeZoom(ctx, "terminate_meeting", strconv.Itoa(resp.StatusCode), start)
		return err
	}
	c.recordResult(nil)
	observeZoom(ctx, "terminate_meeting", "success", start)

	return nil
}

func (c *ZoomClient) GetMeetingStatus(ctx context.Context, meetingID string) (string, error) {
	start := time.Now()
	if c.circuitOpen() {
		observeZoom(ctx, "get_meeting_status", "circuit_open", start)
		return "offline", nil
	}
	meetingID, err := validateZoomMeetingID(meetingID)
	if err != nil {
		return "", err
	}
	token, err := c.getAccessToken(ctx)
	if err != nil {
		c.recordResult(err)
		observeZoom(ctx, "get_meeting_status", "credential_or_token_error", start)
		return "", err
	}
	requestURL := fmt.Sprintf("https://api.zoom.us/v2/meetings/%s", url.PathEscape(meetingID))
	resp, err := c.doWithRetry(func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		return req, nil
	})
	if err != nil {
		c.recordResult(err)
		observeZoom(ctx, "get_meeting_status", "provider_error", start)
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		err := fmt.Errorf("zoom API error on fetching status: %d", resp.StatusCode)
		c.recordResult(err)
		observeZoom(ctx, "get_meeting_status", strconv.Itoa(resp.StatusCode), start)
		return "", err
	}

	responseBody, err := readZoomResponseBody(resp)
	if err != nil {
		c.recordResult(err)
		observeZoom(ctx, "get_meeting_status", "response_body_error", start)
		return "", err
	}
	var meetingResp struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(responseBody, &meetingResp); err != nil {
		c.recordResult(err)
		observeZoom(ctx, "get_meeting_status", "response_decode_error", start)
		return "", err
	}
	if strings.TrimSpace(meetingResp.Status) == "" {
		err := errors.New("zoom meeting status is missing")
		c.recordResult(err)
		observeZoom(ctx, "get_meeting_status", "response_validation_error", start)
		return "", err
	}
	c.recordResult(nil)
	observeZoom(ctx, "get_meeting_status", "success", start)

	return meetingResp.Status, nil
}

// Ensure ZoomClient implements room.MeetingAdapter at compile time.
var _ room.MeetingAdapter = (*ZoomClient)(nil)
