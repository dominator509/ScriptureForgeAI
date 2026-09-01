package ports

import (
	"encoding/json"
	"testing"
)

func TestRoomHubEvictsLaggingSubscriberAndReportsDrop(t *testing.T) {
	hub := NewRoomHub()
	events, unsubscribe := hub.Subscribe("room-1")
	defer unsubscribe()

	for i := 0; i < 16; i++ {
		result := hub.Broadcast("room-1", RoomEvent{Type: "cursor", RoomID: "room-1"})
		if result.Delivered != 1 || result.Dropped != 0 {
			t.Fatalf("fill broadcast %d result = %+v, want delivered=1 dropped=0", i+1, result)
		}
	}

	result := hub.Broadcast("room-1", RoomEvent{Type: "cursor", RoomID: "room-1"})
	if result.Delivered != 0 || result.Dropped != 1 {
		t.Fatalf("lagging broadcast result = %+v, want delivered=0 dropped=1", result)
	}

	received := 0
	for range events {
		received++
	}
	if received != 16 {
		t.Fatalf("lagging subscriber received %d buffered events before eviction, want 16", received)
	}

	afterEviction := hub.Broadcast("room-1", RoomEvent{Type: "cursor", RoomID: "room-1"})
	if afterEviction.Delivered != 0 || afterEviction.Dropped != 0 {
		t.Fatalf("post-eviction broadcast result = %+v, want no subscribers", afterEviction)
	}
}

func TestValidPublishedRoomEventRejectsNullPayload(t *testing.T) {
	event := RoomEvent{
		Type:     "cursor",
		RoomID:   "room-1",
		Sequence: 1,
		Payload:  json.RawMessage("null"),
	}
	if validPublishedRoomEvent(event, "room-1") {
		t.Fatal("validPublishedRoomEvent accepted a null payload")
	}
}
