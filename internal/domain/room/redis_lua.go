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
	// Lua script: Increment duration safely.
	// KEYS[1] = room key
	// ARGV[1] = user ID
	// ARGV[2] = duration to add
	script := redis.NewScript(`
		local current = redis.call("HGET", KEYS[1], ARGV[1])
		if current then
			redis.call("HINCRBY", KEYS[1], ARGV[1], ARGV[2])
		else
			redis.call("HSET", KEYS[1], ARGV[1], ARGV[2])
		end
		return 1
	`)

	roomKey := fmt.Sprintf("room:%s:participants", roomID)

	err := script.Run(ctx, rsm.client, []string{roomKey}, userID, durationSeconds).Err()
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
	script := redis.NewScript(`
		redis.call("HSET", KEYS[1], "active", ARGV[1])
		return 1
	`)

	roomKey := fmt.Sprintf("room:%s:meta", roomID)
	activeStr := "false"
	if active {
		activeStr = "true"
	}

	err := script.Run(ctx, rsm.client, []string{roomKey}, activeStr).Err()
	if err != nil {
		return &PlatformException{
			Category: RoomStateFault,
			Message:  fmt.Sprintf("Failed to update room active state: %v", err),
			Code:     500,
		}
	}
	return nil
}
