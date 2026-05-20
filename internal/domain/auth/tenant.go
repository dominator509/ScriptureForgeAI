package auth

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// SetTenantContext safely injects the organization ID into the local Postgres transaction
// to enforce Row-Level Security (RLS) policies.
func SetTenantContext(ctx context.Context, tx pgx.Tx, orgID string) error {
	// Prevents SQL injection by using the built-in set_config function rather than string concatenation
	_, err := tx.Exec(ctx, "SELECT set_config('app.current_org_id', $1, true)", orgID)
	if err != nil {
		return &PlatformException{
			Category: AuthorizationFault,
			Message:  fmt.Sprintf("failed to establish tenant isolation boundary: %v", err),
			Code:     500,
		}
	}
	return nil
}
