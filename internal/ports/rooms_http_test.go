package ports

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"scriptureforge/internal/domain/auth"
)

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
