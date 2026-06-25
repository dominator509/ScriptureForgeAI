package room

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestAppendRoomEventAssignsContiguousSequencesUnderConcurrency(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	defer client.Close()

	manager := NewRoomStateManager(client)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const writers = 64
	results := make(chan int64, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			event := fmt.Sprintf(`{"type":"cursor","room_id":"room-concurrent","sequence":0,"payload":{"writer":%d},"sent_at":"2026-06-25T00:00:00Z"}`, i)
			seq, err := manager.AppendRoomEvent(ctx, "room-concurrent", event)
			if err != nil {
				t.Errorf("append event %d: %v", i, err)
				return
			}
			results <- seq
		}(i)
	}
	wg.Wait()
	close(results)

	seen := make(map[int64]bool, writers)
	for seq := range results {
		if seq < 1 || seq > writers {
			t.Fatalf("sequence %d out of range 1..%d", seq, writers)
		}
		if seen[seq] {
			t.Fatalf("duplicate sequence %d", seq)
		}
		seen[seq] = true
	}
	if len(seen) != writers {
		t.Fatalf("observed %d sequences, want %d", len(seen), writers)
	}
	for seq := int64(1); seq <= writers; seq++ {
		if !seen[seq] {
			t.Fatalf("missing sequence %d", seq)
		}
	}

	latest, err := manager.GetLatestRoomEvent(ctx, "room-concurrent")
	if err != nil {
		t.Fatalf("get latest event: %v", err)
	}
	var latestEvent struct {
		Sequence int64 `json:"sequence"`
	}
	if err := json.Unmarshal([]byte(latest), &latestEvent); err != nil {
		t.Fatalf("decode latest event %q: %v", latest, err)
	}
	if latestEvent.Sequence < 1 || latestEvent.Sequence > writers {
		t.Fatalf("latest sequence = %d, want within 1..%d", latestEvent.Sequence, writers)
	}
}
