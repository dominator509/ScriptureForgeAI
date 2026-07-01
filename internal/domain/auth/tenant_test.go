package auth

import (
	"context"
	"testing"
)

func TestSetTenantContextRejectsMalformedOrganizationIDBeforeDatabaseUse(t *testing.T) {
	err := SetTenantContext(context.Background(), nil, " not-a-uuid ")
	if err == nil {
		t.Fatal("SetTenantContext accepted a malformed organization id")
	}

	platformErr, ok := err.(*PlatformException)
	if !ok {
		t.Fatalf("SetTenantContext error type = %T, want *PlatformException", err)
	}
	if platformErr.Category != AuthorizationFault {
		t.Fatalf("SetTenantContext category = %s, want %s", platformErr.Category, AuthorizationFault)
	}
	if platformErr.Code != 400 {
		t.Fatalf("SetTenantContext code = %d, want 400", platformErr.Code)
	}
}
