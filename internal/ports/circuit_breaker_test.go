package ports

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestExecuteWithBreaker_Success(t *testing.T) {
	cb := NewCircuitBreaker("test-success")
	ctx := context.Background()

	res, err := ExecuteWithBreaker(ctx, cb, func(ctx context.Context) (interface{}, error) {
		return "success", nil
	})

	assert.NoError(t, err)
	assert.Equal(t, "success", res)
}

func TestExecuteWithBreaker_Timeout(t *testing.T) {
	cb := NewCircuitBreaker("test-timeout")
	ctx := context.Background()

	res, err := ExecuteWithBreaker(ctx, cb, func(ctx context.Context) (interface{}, error) {
		// Simulate a long running process that exceeds the 2-second timeout
		select {
		case <-time.After(3 * time.Second):
			return "late", nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})

	assert.Error(t, err)
	assert.Nil(t, res)
	var pErr *PlatformException
	assert.True(t, errors.As(err, &pErr))
	assert.Equal(t, ServiceUnavailableFault, pErr.Category)
}
