package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SetTenantContext safely injects the organization ID into the local Postgres transaction
// to enforce Row-Level Security (RLS) policies.
func SetTenantContext(ctx context.Context, tx pgx.Tx, orgID string) error {
	tenantID := strings.TrimSpace(orgID)
	if _, err := uuid.Parse(tenantID); err != nil {
		return &PlatformException{
			Category: AuthorizationFault,
			Message:  "invalid tenant isolation organization id",
			Code:     http.StatusBadRequest,
		}
	}
	// Prevents SQL injection by using the built-in set_config function rather than string concatenation
	_, err := tx.Exec(ctx, "SELECT set_config('app.current_org_id', $1, true)", tenantID)
	if err != nil {
		return &PlatformException{
			Category: AuthorizationFault,
			Message:  "failed to establish tenant isolation boundary",
			Code:     500,
		}
	}
	return nil
}
