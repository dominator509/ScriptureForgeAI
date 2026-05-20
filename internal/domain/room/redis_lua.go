package room

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// Define custom Error Category for Room operations
type ErrorCategory string

const (
	RoomStateFault ErrorCategory = "ROOM_STATE_FAULT"
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

// RoomStateManager handles atomic Redis operations
type RoomStateManager struct {
	client *redis.Client
}

func NewRoomStateManager(rdb *redis.Client) *RoomStateManager {
	return &RoomStateManager{client: rdb}
}

// UpdateParticipantDuration safely increments a user's duration in a room using a Lua script
// to avoid data race conditions under high concurrent WebSocket loads.
func (rsm *RoomStateManager) UpdateParticipantDuration(ctx context.Context, roomID, userID string, durationSeconds int) error {
	// Replacing Lua script with direct atomic HINCRBY
	roomKey := fmt.Sprintf("room:%s:participants", roomID)

	err := rsm.client.HIncrBy(ctx, roomKey, userID, int64(durationSeconds)).Err()
	if err != nil {
		return &PlatformException{
			Category: RoomStateFault,
			Message:  fmt.Sprintf("Failed to update participant duration: %v", err),
			Code:     500,
		}
	}
	return nil
}

// SetRoomActiveState atomically updates the active status of a room
func (rsm *RoomStateManager) SetRoomActiveState(ctx context.Context, roomID string, active bool) error {
	roomKey := fmt.Sprintf("room:%s:meta", roomID)
	activeStr := "false"
	if active {
		activeStr = "true"
	}

	err := rsm.client.HSet(ctx, roomKey, "active", activeStr).Err()
	if err != nil {
		return &PlatformException{
			Category: RoomStateFault,
			Message:  fmt.Sprintf("Failed to update room active state: %v", err),
			Code:     500,
		}
	}
	return nil
}
