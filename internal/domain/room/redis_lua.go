package room

import (
	"context"
	"fmt"
	"time"

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

// AppendRoomEvent stores the latest room event atomically and returns the new sequence number.
func (rsm *RoomStateManager) AppendRoomEvent(ctx context.Context, roomID, eventJSON string) (int64, error) {
	script := redis.NewScript(`
		local seq = redis.call("INCR", KEYS[1])
		redis.call("SET", KEYS[2], ARGV[1])
		redis.call("EXPIRE", KEYS[1], ARGV[2])
		redis.call("EXPIRE", KEYS[2], ARGV[2])
		return seq
	`)

	seqKey := fmt.Sprintf("room:%s:sequence", roomID)
	stateKey := fmt.Sprintf("room:%s:latest", roomID)
	ttlSeconds := int((24 * time.Hour).Seconds())
	seq, err := script.Run(ctx, rsm.client, []string{seqKey, stateKey}, eventJSON, ttlSeconds).Int64()
	if err != nil {
		return 0, &PlatformException{
			Category: RoomStateFault,
			Message:  fmt.Sprintf("Failed to append room event: %v", err),
			Code:     500,
		}
	}
	return seq, nil
}

// GetLatestRoomEvent retrieves the last accepted event for HTTP polling fallback.
func (rsm *RoomStateManager) GetLatestRoomEvent(ctx context.Context, roomID string) (string, error) {
	stateKey := fmt.Sprintf("room:%s:latest", roomID)
	value, err := rsm.client.Get(ctx, stateKey).Result()
	if err == redis.Nil {
		return "{}", nil
	}
	if err != nil {
		return "", &PlatformException{
			Category: RoomStateFault,
			Message:  fmt.Sprintf("Failed to load room state: %v", err),
			Code:     500,
		}
	}
	return value, nil
}
