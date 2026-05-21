package database_postgres

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInitPoolConfig(t *testing.T) {
	// Use an invalid config to force an error. The structure of pgxpool
	// will lazy load the connection on NewWithConfig, so if the config
	// string is well formed, it won't error out during pool creation even
	// if the DB doesn't exist until it actually pings.
	// To test our logic, we just pass an invalid connection string format
	connString := "invalid-connection-string"

	ctx := context.Background()
	pool, err := InitPool(ctx, connString)

	assert.Error(t, err)
	assert.Nil(t, pool)
}
