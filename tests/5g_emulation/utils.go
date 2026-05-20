package main

import (
	"crypto/rand"
	"time"
)

// NanoTimer provides high-resolution timing for microsecond/nanosecond profiling
type NanoTimer struct {
	start time.Time
}

func NewNanoTimer() *NanoTimer {
	return &NanoTimer{start: time.Now()}
}

func (t *NanoTimer) ElapsedMicro() int64 {
	return time.Since(t.start).Microseconds()
}

func (t *NanoTimer) ElapsedNano() int64 {
	return time.Since(t.start).Nanoseconds()
}

func generateRandomPayload(size int) []byte {
	b := make([]byte, size)
	rand.Read(b)
	return b
}
