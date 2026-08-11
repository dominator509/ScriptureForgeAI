package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAPIRequestDeadlineMiddlewareCancelsOrdinaryAPIWork(t *testing.T) {
	deadlineObserved := make(chan bool, 1)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		deadlineObserved <- errors.Is(r.Context().Err(), context.DeadlineExceeded)
	})

	apiRequestDeadlineMiddleware(next, 10*time.Millisecond).ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/api/v1/rooms/active", nil),
	)

	select {
	case expired := <-deadlineObserved:
		if !expired {
			t.Fatal("ordinary API request did not end with a deadline exceeded error")
		}
	case <-time.After(time.Second):
		t.Fatal("ordinary API request deadline was not observed")
	}
}

func TestAPIRequestDeadlineMiddlewarePreservesLongLivedRoomStreams(t *testing.T) {
	called := make(chan struct{}, 1)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Context().Deadline(); ok {
			t.Error("room stream received an ordinary API deadline")
		}
		called <- struct{}{}
	})

	apiRequestDeadlineMiddleware(next, time.Millisecond).ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/api/v1/rooms/stream/room-1", nil),
	)

	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("room stream handler was not invoked")
	}
}

func TestAPIRequestDeadlineMiddlewarePreservesEarlierCancellation(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	deadlineObserved := make(chan bool, 1)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deadline, ok := r.Context().Deadline()
		deadlineObserved <- ok && time.Until(deadline) <= 20*time.Millisecond
	})

	request := httptest.NewRequest(http.MethodGet, "/api/v1/rooms/active", nil).WithContext(parent)
	apiRequestDeadlineMiddleware(next, time.Second).ServeHTTP(httptest.NewRecorder(), request)

	if !<-deadlineObserved {
		t.Fatal("middleware replaced an earlier request deadline")
	}
}
