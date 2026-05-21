package ports

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/sony/gobreaker"
)

type ErrorCategory string

const (
	AIOrchestrationEngineFault ErrorCategory = "AI_ORCHESTRATION_ENGINE_FAULT"
	ServiceUnavailableFault    ErrorCategory = "SERVICE_UNAVAILABLE_FAULT"
)

type PlatformException struct {
	Category ErrorCategory `json:"category"`
	Message  string        `json:"message"`
	Code     int           `json:"code"`
	TraceID  string        `json:"trace_id"`
}

func (e *PlatformException) Error() string {
	return e.Message
}

// NewCircuitBreaker creates a circuit breaker tailored for >2s latency faults.
func NewCircuitBreaker(name string) *gobreaker.CircuitBreaker {
	settings := gobreaker.Settings{
		Name:        name,
		MaxRequests: 5,
		Interval:    10 * time.Second,
		Timeout:     5 * time.Second,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
			return counts.Requests >= 5 && failureRatio >= 0.5
		},
	}
	return gobreaker.NewCircuitBreaker(settings)
}

// ExecuteWithBreaker enforces a 2-second timeout and wraps the call with circuit breaking logic.
func ExecuteWithBreaker(ctx context.Context, cb *gobreaker.CircuitBreaker, reqFunc func(ctx context.Context) (interface{}, error)) (interface{}, error) {
	// Fast-fail requests exceeding 2 seconds
	timeoutCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	res, err := cb.Execute(func() (interface{}, error) {
		// Run the request function, passing the timeout context so the underlying operation (e.g. pgx or grpc) can cancel early.

		ch := make(chan struct {
			res interface{}
			err error
		}, 1)

		go func() {
			r, e := reqFunc(timeoutCtx)
			ch <- struct {
				res interface{}
				err error
			}{r, e}
		}()

		select {
		case <-timeoutCtx.Done():
			return nil, timeoutCtx.Err()
		case result := <-ch:
			return result.res, result.err
		}
	})

	if err != nil {
		if errors.Is(err, gobreaker.ErrOpenState) || errors.Is(err, gobreaker.ErrTooManyRequests) || errors.Is(err, context.DeadlineExceeded) {
			return nil, &PlatformException{
				Category: ServiceUnavailableFault,
				Message:  "Service temporarily unavailable due to high latency or faults",
				Code:     http.StatusServiceUnavailable,
				TraceID:  "generate_or_propagate_trace_id_here",
			}
		}
		return nil, err
	}
	return res, nil
}
