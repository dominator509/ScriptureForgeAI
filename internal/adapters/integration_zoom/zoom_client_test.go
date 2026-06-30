package integration_zoom

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"scriptureforge/internal/domain/observability"
	"scriptureforge/internal/domain/room"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestCreateMeetingFallsBackAndOpensCircuitAfterTimeouts(t *testing.T) {
	t.Setenv("GO_ENV", "")
	client := &ZoomClient{
		AccountID:    "account",
		ClientID:     "client",
		ClientSecret: "secret",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return nil, context.DeadlineExceeded
		})},
	}

	config := room.MeetingConfig{Topic: "Study", Duration: 45, HostID: "host-1"}
	observer := observability.NewObserver(observability.Options{})
	ctx := observability.WithObserver(context.Background(), observer)
	for i := 0; i < 3; i++ {
		meeting, err := client.CreateMeeting(ctx, config)
		if err != nil {
			t.Fatalf("fallback create meeting returned error: %v", err)
		}
		if meeting.JoinURL != "offline://in-person" {
			t.Fatalf("fallback join url = %q, want offline://in-person", meeting.JoinURL)
		}
	}

	var calledAfterCircuit bool
	client.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calledAfterCircuit = true
		return nil, errors.New("transport should not be called while circuit is open")
	})}

	meeting, err := client.CreateMeeting(ctx, config)
	if err != nil {
		t.Fatalf("circuit-open fallback returned error: %v", err)
	}
	if calledAfterCircuit {
		t.Fatal("HTTP transport was called while Zoom circuit was open")
	}
	if meeting.JoinURL != "offline://in-person" || meeting.StartURL != "offline://host/host-1" {
		t.Fatalf("circuit fallback meeting = %#v", meeting)
	}
	metrics := observer.Snapshot()
	if !strings.Contains(metrics, `scriptureforge_dependency_operations_total{dependency="zoom",operation="create_meeting",status="credential_or_token_fallback"} 3`) {
		t.Fatalf("Zoom fallback dependency metric missing:\n%s", metrics)
	}
	if !strings.Contains(metrics, `scriptureforge_dependency_operations_total{dependency="zoom",operation="create_meeting",status="circuit_open_fallback"} 1`) {
		t.Fatalf("Zoom circuit-open dependency metric missing:\n%s", metrics)
	}
}

func TestCreateMeetingRetriesTransientZoomFailure(t *testing.T) {
	t.Setenv("GO_ENV", "")
	var tokenAttempts int
	var meetingAttempts int
	client := &ZoomClient{
		AccountID:    "account",
		ClientID:     "client",
		ClientSecret: "secret",
		MaxRetries:   1,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			switch {
			case strings.Contains(r.URL.String(), "zoom.us/oauth/token"):
				tokenAttempts++
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"access_token":"token-1"}`)),
					Header:     http.Header{},
				}, nil
			case strings.Contains(r.URL.String(), "/v2/users/me/meetings"):
				meetingAttempts++
				if meetingAttempts == 1 {
					return &http.Response{
						StatusCode: http.StatusServiceUnavailable,
						Body:       io.NopCloser(strings.NewReader(`{"message":"temporary"}`)),
						Header:     http.Header{},
					}, nil
				}
				return &http.Response{
					StatusCode: http.StatusCreated,
					Body:       io.NopCloser(strings.NewReader(`{"id":12345,"join_url":"https://zoom.us/j/12345","start_url":"https://zoom.us/s/12345"}`)),
					Header:     http.Header{},
				}, nil
			default:
				t.Fatalf("unexpected Zoom request URL: %s", r.URL.String())
				return nil, nil
			}
		})},
	}

	observer := observability.NewObserver(observability.Options{})
	ctx := observability.WithObserver(context.Background(), observer)
	meeting, err := client.CreateMeeting(ctx, room.MeetingConfig{Topic: "Study", Duration: 45, HostID: "host-1"})
	if err != nil {
		t.Fatalf("retrying create meeting returned error: %v", err)
	}
	if meeting.ID != "12345" || meeting.JoinURL != "https://zoom.us/j/12345" {
		t.Fatalf("meeting after retry = %#v", meeting)
	}
	if tokenAttempts != 1 || meetingAttempts != 2 {
		t.Fatalf("attempts token=%d meeting=%d, want token=1 meeting=2", tokenAttempts, meetingAttempts)
	}
	if client.circuitOpen() {
		t.Fatal("successful retry should not leave Zoom circuit open")
	}
	metrics := observer.Snapshot()
	if !strings.Contains(metrics, `scriptureforge_dependency_operations_total{dependency="zoom",operation="create_meeting",status="success"} 1`) {
		t.Fatalf("Zoom success dependency metric missing:\n%s", metrics)
	}
}

func TestCreateMeetingFallsBackAndOpensCircuitAfterMeetingTimeouts(t *testing.T) {
	t.Setenv("GO_ENV", "")
	var tokenAttempts int
	var meetingAttempts int
	client := &ZoomClient{
		AccountID:    "account",
		ClientID:     "client",
		ClientSecret: "secret",
		MaxRetries:   0,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			switch {
			case strings.Contains(r.URL.String(), "zoom.us/oauth/token"):
				tokenAttempts++
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"access_token":"token-1"}`)),
					Header:     http.Header{},
				}, nil
			case strings.Contains(r.URL.String(), "/v2/users/me/meetings"):
				meetingAttempts++
				return nil, context.DeadlineExceeded
			default:
				t.Fatalf("unexpected Zoom request URL: %s", r.URL.String())
				return nil, nil
			}
		})},
	}

	config := room.MeetingConfig{Topic: "Study", Duration: 45, HostID: "host-timeout"}
	observer := observability.NewObserver(observability.Options{})
	ctx := observability.WithObserver(context.Background(), observer)
	for i := 0; i < 3; i++ {
		meeting, err := client.CreateMeeting(ctx, config)
		if err != nil {
			t.Fatalf("provider-timeout fallback returned error: %v", err)
		}
		if meeting.JoinURL != "offline://in-person" || meeting.StartURL != "offline://host/host-timeout" {
			t.Fatalf("provider-timeout fallback meeting = %#v", meeting)
		}
	}
	if tokenAttempts != 3 || meetingAttempts != 3 {
		t.Fatalf("attempts token=%d meeting=%d, want 3/3 before circuit opens", tokenAttempts, meetingAttempts)
	}

	client.HTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatal("transport should not be called after provider timeouts open the circuit")
		return nil, nil
	})}
	meeting, err := client.CreateMeeting(ctx, config)
	if err != nil {
		t.Fatalf("circuit-open fallback after provider timeout returned error: %v", err)
	}
	if meeting.JoinURL != "offline://in-person" {
		t.Fatalf("circuit-open fallback join URL = %q, want offline fallback", meeting.JoinURL)
	}

	metrics := observer.Snapshot()
	if !strings.Contains(metrics, `scriptureforge_dependency_operations_total{dependency="zoom",operation="create_meeting",status="provider_error_fallback"} 3`) {
		t.Fatalf("Zoom provider timeout fallback metric missing:\n%s", metrics)
	}
	if !strings.Contains(metrics, `scriptureforge_dependency_operations_total{dependency="zoom",operation="create_meeting",status="circuit_open_fallback"} 1`) {
		t.Fatalf("Zoom circuit-open fallback metric missing after provider timeout:\n%s", metrics)
	}
}

func TestCreateMeetingUsesOfflineFallbackWhenCredentialsMissing(t *testing.T) {
	t.Setenv("GO_ENV", "")
	for _, name := range []string{"ZOOM_ACCOUNT_ID", "ZOOM_CLIENT_ID", "ZOOM_CLIENT_SECRET"} {
		t.Setenv(name, "")
	}
	client := NewZoomClient()
	client.HTTPClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatal("HTTP transport should not be called without credentials")
		return nil, nil
	})

	meeting, err := client.CreateMeeting(context.Background(), room.MeetingConfig{HostID: "host-2"})
	if err != nil {
		t.Fatalf("missing-credential fallback returned error: %v", err)
	}
	if meeting.JoinURL != "offline://in-person" {
		t.Fatalf("meeting join url = %q, want offline fallback", meeting.JoinURL)
	}
}

func TestGetMeetingStatusEmitsZoomDependencyMetric(t *testing.T) {
	t.Setenv("GO_ENV", "")
	client := &ZoomClient{
		AccountID:    "account",
		ClientID:     "client",
		ClientSecret: "secret",
		MaxRetries:   0,
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			switch {
			case strings.Contains(r.URL.String(), "zoom.us/oauth/token"):
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"access_token":"token-1"}`)),
					Header:     http.Header{},
				}, nil
			case strings.Contains(r.URL.String(), "/v2/meetings/meeting-1"):
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"status":"started"}`)),
					Header:     http.Header{},
				}, nil
			default:
				t.Fatalf("unexpected Zoom request URL: %s", r.URL.String())
				return nil, nil
			}
		})},
	}

	observer := observability.NewObserver(observability.Options{})
	ctx := observability.WithObserver(context.Background(), observer)
	status, err := client.GetMeetingStatus(ctx, "meeting-1")
	if err != nil {
		t.Fatalf("get meeting status returned error: %v", err)
	}
	if status != "started" {
		t.Fatalf("meeting status = %q, want started", status)
	}
	metrics := observer.Snapshot()
	if !strings.Contains(metrics, `scriptureforge_dependency_operations_total{dependency="zoom",operation="get_meeting_status",status="success"} 1`) {
		t.Fatalf("Zoom status dependency metric missing:\n%s", metrics)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
