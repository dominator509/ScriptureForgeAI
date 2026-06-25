package integration_zoom

import (
	"context"
	"errors"
	"net/http"
	"os"
	"testing"

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
	for i := 0; i < 3; i++ {
		meeting, err := client.CreateMeeting(context.Background(), config)
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

	meeting, err := client.CreateMeeting(context.Background(), config)
	if err != nil {
		t.Fatalf("circuit-open fallback returned error: %v", err)
	}
	if calledAfterCircuit {
		t.Fatal("HTTP transport was called while Zoom circuit was open")
	}
	if meeting.JoinURL != "offline://in-person" || meeting.StartURL != "offline://host/host-1" {
		t.Fatalf("circuit fallback meeting = %#v", meeting)
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

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
