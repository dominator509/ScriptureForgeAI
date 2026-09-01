package auth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type failingTenantTx struct {
	pgx.Tx
}

func (failingTenantTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("database host and credential details")
}

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

func TestSetTenantContextDoesNotExposeDatabaseFailureDetails(t *testing.T) {
	err := SetTenantContext(context.Background(), failingTenantTx{}, "11111111-1111-4111-8111-111111111111")
	if err == nil {
		t.Fatal("SetTenantContext accepted a database failure")
	}

	platformErr, ok := err.(*PlatformException)
	if !ok {
		t.Fatalf("SetTenantContext error type = %T, want *PlatformException", err)
	}
	if platformErr.Code != 500 {
		t.Fatalf("SetTenantContext error code = %d, want 500", platformErr.Code)
	}
	if platformErr.Message != "failed to establish tenant isolation boundary" {
		t.Fatalf("SetTenantContext message = %q, want generic client-safe message", platformErr.Message)
	}
	if strings.Contains(platformErr.Message, "database host") {
		t.Fatal("SetTenantContext leaked database failure details")
	}
}
