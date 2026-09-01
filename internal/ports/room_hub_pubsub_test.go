package ports

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"scriptureforge/internal/domain/room"
)

func TestRedisRoomHubsDeliverPublishedEventsAcrossReplicas(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	defer client.Close()

	originHub := NewRedisRoomHub(client)
	remoteHub := NewRedisRoomHub(client)
	originEvents, unsubscribeOrigin := originHub.Subscribe("room-replica")
	defer unsubscribeOrigin()
	remoteEvents, unsubscribeRemote := remoteHub.Subscribe("room-replica")
	defer unsubscribeRemote()

	// Give both subscriptions time to complete their Redis handshake before
	// publishing; this mirrors the short upgrade window before a client sends.
	time.Sleep(50 * time.Millisecond)
	manager := room.NewRoomStateManager(client)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	seq, err := manager.AppendRoomEventAndPublish(ctx, "room-replica", `{"type":"cursor","room_id":"room-replica","sequence":0,"payload":{"verse":"Romans 8:1"},"sent_at":"2026-08-16T00:00:00Z"}`, originHub.InstanceID())
	if err != nil {
		t.Fatalf("append and publish room event: %v", err)
	}

	select {
	case event := <-remoteEvents:
		if event.Sequence != seq || event.RoomID != "room-replica" {
			t.Fatalf("remote event = %+v, want room-replica sequence %d", event, seq)
		}
	case <-ctx.Done():
		t.Fatal("remote replica did not receive published room event")
	}

	select {
	case event := <-originEvents:
		t.Fatalf("origin replica received its own pubsub event without local broadcast: %+v", event)
	case <-time.After(100 * time.Millisecond):
	}

	originHub.Broadcast("room-replica", RoomEvent{RoomID: "room-replica", Sequence: seq, Type: "cursor", Payload: []byte(`{"verse":"Romans 8:1"}`)})
	select {
	case event := <-originEvents:
		if event.Sequence != seq {
			t.Fatalf("local event sequence = %d, want %d", event.Sequence, seq)
		}
	case <-ctx.Done():
		t.Fatal("origin replica did not receive local broadcast")
	}
}

func TestRedisRoomHubCloseStopsSubscriptions(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	defer client.Close()

	hub := NewRedisRoomHub(client)
	_, unsubscribe := hub.Subscribe("room-close")
	unsubscribe()
	hub.Close()
	if hub.subscriberCount("room-close") != 0 {
		t.Fatalf("room subscribers = %d, want 0 after close", hub.subscriberCount("room-close"))
	}
}

func TestRedisRoomHubRetriesUnavailableSubscription(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	addr := server.Addr()
	server.Close()

	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		DialTimeout:  100 * time.Millisecond,
		ReadTimeout:  100 * time.Millisecond,
		WriteTimeout: 100 * time.Millisecond,
		MaxRetries:   0,
	})
	hub := NewRedisRoomHub(client)
	events, unsubscribe := hub.Subscribe("room-reconnect")
	defer unsubscribe()
	defer hub.Close()
	defer client.Close()

	time.Sleep(250 * time.Millisecond)
	recoveredServer := miniredis.NewMiniRedis()
	if err := recoveredServer.StartAddr(addr); err != nil {
		t.Fatalf("restart miniredis: %v", err)
	}
	defer recoveredServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	payload := `{"source_id":"reconnect-source","event":{"type":"cursor","room_id":"room-reconnect","sequence":1,"payload":{"verse":"Romans 8:1"},"sent_at":"2026-08-16T00:00:00Z"}}`
	for {
		publishCtx, publishCancel := context.WithTimeout(ctx, 250*time.Millisecond)
		err := client.Publish(publishCtx, roomEventChannel("room-reconnect"), payload).Err()
		publishCancel()
		if err == nil {
			select {
			case event := <-events:
				if event.Sequence != 1 || event.RoomID != "room-reconnect" {
					t.Fatalf("reconnected event = %+v, want room-reconnect sequence 1", event)
				}
				return
			default:
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("room hub did not recover its Redis subscription; last publish error: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
	}
}
