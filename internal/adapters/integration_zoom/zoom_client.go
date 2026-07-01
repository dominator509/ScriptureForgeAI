package integration_zoom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

func NewZoomClient() *ZoomClient {
	return &ZoomClient{
		AccountID:    os.Getenv("ZOOM_ACCOUNT_ID"),
		ClientID:     os.Getenv("ZOOM_CLIENT_ID"),
		ClientSecret: os.Getenv("ZOOM_CLIENT_SECRET"),
		HTTPClient:   &http.Client{Timeout: 3500 * time.Millisecond},
		MaxRetries:   zoomMaxRetries(),
	}
}

func zoomMaxRetries() int {
	value := strings.TrimSpace(os.Getenv("ZOOM_MAX_RETRIES"))
	if value == "" {
		return 2
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return 2
	}
	return parsed
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

func (c *ZoomClient) doWithRetry(buildRequest func() (*http.Request, error)) (*http.Response, error) {
	attempts := c.MaxRetries + 1
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		req, err := buildRequest()
		if err != nil {
			return nil, err
		}
		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = err
		} else if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
			lastErr = fmt.Errorf("transient zoom status: %d", resp.StatusCode)
			if attempt == attempts-1 {
				return resp, nil
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		} else {
			return resp, nil
		}
	}
	return nil, lastErr
}

// getAccessToken executes the Server-to-Server OAuth flow.
func (c *ZoomClient) getAccessToken(ctx context.Context) (string, error) {
	if c.AccountID == "" || c.ClientID == "" || c.ClientSecret == "" {
		return "", fmt.Errorf("zoom credentials are not fully configured")
	}

	tokenURL := fmt.Sprintf("https://zoom.us/oauth/token?grant_type=account_credentials&account_id=%s", c.AccountID)
	resp, err := c.doWithRetry(func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, nil)
		if err != nil {
			return nil, err
		}
		req.SetBasicAuth(c.ClientID, c.ClientSecret)
		return req, nil
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to retrieve zoom access token, status: %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
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

	resp, err := c.doWithRetry(func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.zoom.us/v2/users/me/meetings", bytes.NewBuffer(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	})
	if err != nil {
		c.recordResult(err)
		observeZoom(ctx, "create_meeting", "provider_error_fallback", start)
		return offlineMeetingDetails(config), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("zoom API error on creation: %d %s", resp.StatusCode, string(respBody))
		c.recordResult(err)
		observeZoom(ctx, "create_meeting", strconv.Itoa(resp.StatusCode), start)
		return offlineMeetingDetails(config), nil
	}

	var meetingResp struct {
		Id       int64  `json:"id"`
		JoinUrl  string `json:"join_url"`
		StartUrl string `json:"start_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meetingResp); err != nil {
		c.recordResult(err)
		observeZoom(ctx, "create_meeting", "response_decode_error", start)
		return nil, err
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

	url := fmt.Sprintf("https://api.zoom.us/v2/meetings/%s/status", meetingID)
	resp, err := c.doWithRetry(func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(body))
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
	token, err := c.getAccessToken(ctx)
	if err != nil {
		c.recordResult(err)
		observeZoom(ctx, "get_meeting_status", "credential_or_token_error", start)
		return "", err
	}

	url := fmt.Sprintf("https://api.zoom.us/v2/meetings/%s", meetingID)
	resp, err := c.doWithRetry(func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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

	var meetingResp struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meetingResp); err != nil {
		c.recordResult(err)
		observeZoom(ctx, "get_meeting_status", "response_decode_error", start)
		return "", err
	}
	c.recordResult(nil)
	observeZoom(ctx, "get_meeting_status", "success", start)

	return meetingResp.Status, nil
}

// Ensure ZoomClient implements room.MeetingAdapter at compile time.
var _ room.MeetingAdapter = (*ZoomClient)(nil)
