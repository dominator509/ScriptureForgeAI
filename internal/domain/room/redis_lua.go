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

// roomKey keeps all per-room keys in one Redis Cluster hash slot while
// preserving clear key suffixes for state, sequencing, and pub/sub.
func roomKey(roomID, suffix string) string {
	return fmt.Sprintf("room:{%s}:%s", roomID, suffix)
}

func NewRoomStateManager(rdb *redis.Client) *RoomStateManager {
	return &RoomStateManager{client: rdb}
}

func (rsm *RoomStateManager) requireClient() (*redis.Client, error) {
	if rsm == nil || rsm.client == nil {
		return nil, &PlatformException{
			Category: RoomStateFault,
			Message:  "room state backend is not configured",
			Code:     503,
		}
	}
	return rsm.client, nil
}

// UpdateParticipantDuration safely increments a user's duration in a room using a Lua script
// to avoid data race conditions under high concurrent WebSocket loads.
func (rsm *RoomStateManager) UpdateParticipantDuration(ctx context.Context, roomID, userID string, durationSeconds int) error {
	client, err := rsm.requireClient()
	if err != nil {
		return err
	}

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

	participantsKey := roomKey(roomID, "participants")

	err = script.Run(ctx, client, []string{participantsKey}, userID, durationSeconds).Err()
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
	client, err := rsm.requireClient()
	if err != nil {
		return err
	}

	script := redis.NewScript(`
		redis.call("HSET", KEYS[1], "active", ARGV[1])
		return 1
	`)

	metaKey := roomKey(roomID, "meta")
	activeStr := "false"
	if active {
		activeStr = "true"
	}

	err = script.Run(ctx, client, []string{metaKey}, activeStr).Err()
	if err != nil {
		return &PlatformException{
			Category: RoomStateFault,
			Message:  fmt.Sprintf("Failed to update room active state: %v", err),
			Code:     500,
		}
	}
	return nil
}

// AppendRoomEvent stores the latest sequenced room event atomically and returns the new sequence number.
func (rsm *RoomStateManager) AppendRoomEvent(ctx context.Context, roomID, eventJSON string) (int64, error) {
	return rsm.appendRoomEvent(ctx, roomID, eventJSON, "")
}

// AppendRoomEventAndPublish persists the accepted event and publishes the
// same sequenced envelope atomically so every API replica can fan it out.
func (rsm *RoomStateManager) AppendRoomEventAndPublish(ctx context.Context, roomID, eventJSON, sourceID string) (int64, error) {
	return rsm.appendRoomEvent(ctx, roomID, eventJSON, sourceID)
}

func (rsm *RoomStateManager) appendRoomEvent(ctx context.Context, roomID, eventJSON, sourceID string) (int64, error) {
	client, err := rsm.requireClient()
	if err != nil {
		return 0, err
	}

	script := redis.NewScript(`
		local seq = redis.call("INCR", KEYS[1])
		local event = cjson.decode(ARGV[1])
		event["sequence"] = seq
		local encoded = cjson.encode(event)
		redis.call("SET", KEYS[2], encoded)
		redis.call("EXPIRE", KEYS[1], ARGV[2])
		redis.call("EXPIRE", KEYS[2], ARGV[2])
		if ARGV[3] ~= "" then
			redis.call("PUBLISH", KEYS[3], cjson.encode({source_id = ARGV[3], event = event}))
		end
		return seq
	`)

	seqKey := roomKey(roomID, "sequence")
	stateKey := roomKey(roomID, "latest")
	eventChannel := roomKey(roomID, "events")
	ttlSeconds := int((24 * time.Hour).Seconds())
	seq, err := script.Run(ctx, client, []string{seqKey, stateKey, eventChannel}, eventJSON, ttlSeconds, sourceID).Int64()
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
	client, err := rsm.requireClient()
	if err != nil {
		return "", err
	}

	stateKey := roomKey(roomID, "latest")
	value, err := client.Get(ctx, stateKey).Result()
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

// ClaimWebhookDelivery provides a short-lived, cross-replica idempotency key
// for signed provider callbacks. The caller releases the key when processing
// fails so the provider can safely retry the delivery.
func (rsm *RoomStateManager) ClaimWebhookDelivery(ctx context.Context, deliveryID string, ttl time.Duration) (bool, error) {
	client, err := rsm.requireClient()
	if err != nil {
		return false, err
	}
	return client.SetNX(ctx, "room:webhook:"+deliveryID, "1", ttl).Result()
}

func (rsm *RoomStateManager) ReleaseWebhookDelivery(ctx context.Context, deliveryID string) error {
	client, err := rsm.requireClient()
	if err != nil {
		return err
	}
	return client.Del(ctx, "room:webhook:"+deliveryID).Err()
}
