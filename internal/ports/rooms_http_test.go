package ports

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"scriptureforge/internal/domain/auth"
	"scriptureforge/internal/domain/room"
)

type testMeetingAdapter struct {
	details       *room.MeetingDetails
	createdConfig room.MeetingConfig
	terminatedID  string
}

func (a *testMeetingAdapter) CreateMeeting(_ context.Context, config room.MeetingConfig) (*room.MeetingDetails, error) {
	a.createdConfig = config
	return a.details, nil
}

func (a *testMeetingAdapter) TerminateMeeting(_ context.Context, meetingID string) error {
	a.terminatedID = meetingID
	return nil
}

func (a *testMeetingAdapter) GetMeetingStatus(context.Context, string) (string, error) {
	return "started", nil
}

func TestPersistedMeetingDetailsExposeOnlySafeJoinMetadata(t *testing.T) {
	provider, meetingID, metadata, err := persistedMeetingDetails(&room.MeetingDetails{
		ID:       "123456789",
		JoinURL:  "https://zoom.us/j/123456789",
		StartURL: "https://zoom.us/s/host-secret",
	}, "zoom")
	if err != nil {
		t.Fatalf("persistedMeetingDetails returned error: %v", err)
	}
	if provider != "zoom" || meetingID != "123456789" {
		t.Fatalf("meeting persistence identity = %q/%q, want zoom/123456789", provider, meetingID)
	}
	if strings.Contains(string(metadata), "host-secret") || strings.Contains(string(metadata), "start_url") {
		t.Fatalf("meeting metadata exposed host start URL: %s", metadata)
	}
	if !strings.Contains(string(metadata), "https://zoom.us/j/123456789") {
		t.Fatalf("meeting metadata omitted safe join URL: %s", metadata)
	}
}

func TestPersistedOfflineMeetingDetailsDoNotCreateExternalMapping(t *testing.T) {
	provider, meetingID, metadata, err := persistedMeetingDetails(offlineMeetingDetails("host-1"), "zoom")
	if err != nil {
		t.Fatalf("persistedMeetingDetails returned error: %v", err)
	}
	if provider != "offline" || meetingID != "" {
		t.Fatalf("offline meeting persistence identity = %q/%q, want offline/empty", provider, meetingID)
	}
	if !strings.Contains(string(metadata), "offline://in-person") {
		t.Fatalf("offline meeting metadata = %s, want fallback URL", metadata)
	}
}

func TestCreateRoomRejectsTenantOverrideFieldsBeforePersistence(t *testing.T) {
	handler := &RoomHandler{}
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/rooms/create",
		strings.NewReader(`{"title":"Override Attempt","organization_id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","user_id":"22222222-2222-4222-8222-222222222222"}`),
	)
	req = req.WithContext(context.WithValue(req.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         "11111111-1111-4111-8111-111111111111",
		OrganizationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		Role:           "member",
	}))

	rec := httptest.NewRecorder()
	handler.CreateRoomHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("room create with tenant override fields status = %d body = %s, want 400", rec.Code, rec.Body.String())
	}
}

func TestCreateRoomFailsClosedWhenStateManagerMissing(t *testing.T) {
	handler := &RoomHandler{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rooms/create", strings.NewReader(`{"title":"State Required"}`))
	req = req.WithContext(context.WithValue(req.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         "11111111-1111-4111-8111-111111111111",
		OrganizationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		Role:           "member",
	}))

	rec := httptest.NewRecorder()
	handler.CreateRoomHandler(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("room create without state manager status = %d body = %s, want 503", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Room state manager is not configured") {
		t.Fatalf("room create without state manager body = %s", rec.Body.String())
	}
}

func TestCreateRoomRejectsOversizedBodyBeforePersistence(t *testing.T) {
	handler := &RoomHandler{}
	body := `{"title":"` + strings.Repeat("x", maxRoomRequestBodyBytes) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rooms/create", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         "11111111-1111-4111-8111-111111111111",
		OrganizationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		Role:           "member",
	}))

	rec := httptest.NewRecorder()
	handler.CreateRoomHandler(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized room body status = %d body = %s, want 413", rec.Code, rec.Body.String())
	}
}

func TestCreateRoomRejectsConcatenatedJSONBeforePersistence(t *testing.T) {
	handler := &RoomHandler{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rooms/create", strings.NewReader(`{"title":"first"}{"title":"second"}`))
	req = req.WithContext(context.WithValue(req.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         "11111111-1111-4111-8111-111111111111",
		OrganizationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		Role:           "member",
	}))

	rec := httptest.NewRecorder()
	handler.CreateRoomHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("concatenated room JSON status = %d body = %s, want 400", rec.Code, rec.Body.String())
	}
}

func TestCreateRoomRejectsOverlongTitleBeforePersistence(t *testing.T) {
	handler := &RoomHandler{}
	body := `{"title":"` + strings.Repeat("x", maxRoomTitleBytes+1) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rooms/create", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), auth.ContextKeyUser, &auth.TokenClaims{
		UserID:         "11111111-1111-4111-8111-111111111111",
		OrganizationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		Role:           "member",
	}))

	rec := httptest.NewRecorder()
	handler.CreateRoomHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("overlong room title status = %d body = %s, want 400", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Room title is too long") {
		t.Fatalf("overlong room title body = %s, want explicit length error", rec.Body.String())
	}
}
