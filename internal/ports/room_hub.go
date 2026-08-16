package ports

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"scriptureforge/internal/domain/observability"
)

type RoomHub struct {
	mu            sync.RWMutex
	rooms         map[string]map[*roomSubscriber]struct{}
	redisClient   *redis.Client
	instanceID    string
	subscriptions map[string]*roomSubscription
}

type roomSubscription struct {
	cancel context.CancelFunc
	pubsub *redis.PubSub
}

type publishedRoomEvent struct {
	SourceID string    `json:"source_id"`
	Event    RoomEvent `json:"event"`
}

type BroadcastResult struct {
	Delivered int
	Dropped   int
}

type roomSubscriber struct {
	mu     sync.Mutex
	ch     chan RoomEvent
	closed bool
}

func newRoomSubscriber() *roomSubscriber {
	return &roomSubscriber{ch: make(chan RoomEvent, 16)}
}

func (s *roomSubscriber) send(event RoomEvent) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	select {
	case s.ch <- event:
		return true
	default:
		return false
	}
}

func (s *roomSubscriber) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.ch)
	}
}

func NewRoomHub() *RoomHub {
	return newRoomHub(nil)
}

// NewRedisRoomHub enables replica-wide fan-out while retaining the same local
// hub behavior for tests and development configurations without Redis.
func NewRedisRoomHub(client *redis.Client) *RoomHub {
	return newRoomHub(client)
}

func newRoomHub(client *redis.Client) *RoomHub {
	return &RoomHub{
		rooms:         map[string]map[*roomSubscriber]struct{}{},
		redisClient:   client,
		instanceID:    newRoomHubInstanceID(),
		subscriptions: map[string]*roomSubscription{},
	}
}

func newRoomHubInstanceID() string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err == nil {
		return hex.EncodeToString(bytes[:])
	}
	return "room-hub-fallback"
}

func (h *RoomHub) InstanceID() string {
	if h == nil {
		return ""
	}
	return h.instanceID
}

func (h *RoomHub) Subscribe(roomID string) (<-chan RoomEvent, func()) {
	if h == nil {
		ch := make(chan RoomEvent)
		close(ch)
		return ch, func() {}
	}
	subscriber := newRoomSubscriber()
	h.mu.Lock()
	if h.rooms[roomID] == nil {
		h.rooms[roomID] = map[*roomSubscriber]struct{}{}
	}
	h.rooms[roomID][subscriber] = struct{}{}
	if len(h.rooms[roomID]) == 1 {
		h.startSubscriptionLocked(roomID)
	}
	h.mu.Unlock()

	return subscriber.ch, func() {
		h.unsubscribe(roomID, subscriber)
	}
}

func (h *RoomHub) startSubscriptionLocked(roomID string) {
	if h.redisClient == nil || h.subscriptions[roomID] != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	pubsub := h.redisClient.Subscribe(ctx, roomEventChannel(roomID))
	h.subscriptions[roomID] = &roomSubscription{cancel: cancel, pubsub: pubsub}
	go h.consumeSubscription(ctx, roomID, pubsub)
}

func roomEventChannel(roomID string) string {
	return "room:{" + roomID + "}:events"
}

func (h *RoomHub) consumeSubscription(ctx context.Context, roomID string, pubsub *redis.PubSub) {
	if _, err := pubsub.Receive(ctx); err != nil {
		if ctx.Err() == nil {
			log.Printf("room pubsub subscription unavailable room=%s: %v", roomID, err)
		}
		return
	}
	for {
		select {
		case message, ok := <-pubsub.Channel():
			if !ok {
				return
			}
			var published publishedRoomEvent
			if err := json.Unmarshal([]byte(message.Payload), &published); err != nil || !validPublishedRoomEvent(published.Event, roomID) {
				log.Printf("room pubsub event rejected room=%s", roomID)
				continue
			}
			if published.SourceID == h.instanceID {
				continue
			}
			started := time.Now()
			status := "success"
			if result := h.Broadcast(roomID, published.Event); result.Dropped > 0 {
				status = "dropped"
			}
			observability.ObserveDependencyFromContext(ctx, "websocket", "room_broadcast", status, time.Since(started))
		case <-ctx.Done():
			return
		}
	}
}

func validPublishedRoomEvent(event RoomEvent, roomID string) bool {
	return event.RoomID == roomID && event.Sequence > 0 && validRoomEventType(event.Type) &&
		len(event.Payload) > 0 && json.Valid(event.Payload)
}

// Close stops all Redis subscriptions owned by this process.
func (h *RoomHub) Close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	subscriptions := make([]*roomSubscription, 0, len(h.subscriptions))
	for roomID, subscription := range h.subscriptions {
		delete(h.subscriptions, roomID)
		subscriptions = append(subscriptions, subscription)
	}
	h.mu.Unlock()
	for _, subscription := range subscriptions {
		subscription.cancel()
		_ = subscription.pubsub.Close()
	}
}

func (h *RoomHub) Broadcast(roomID string, event RoomEvent) BroadcastResult {
	if h == nil {
		return BroadcastResult{}
	}
	h.mu.RLock()
	subscribers := make([]*roomSubscriber, 0, len(h.rooms[roomID]))
	for subscriber := range h.rooms[roomID] {
		subscribers = append(subscribers, subscriber)
	}
	h.mu.RUnlock()

	result := BroadcastResult{}
	lagging := make([]*roomSubscriber, 0)
	for _, subscriber := range subscribers {
		if subscriber.send(event) {
			result.Delivered++
			continue
		}
		result.Dropped++
		lagging = append(lagging, subscriber)
	}
	for _, subscriber := range lagging {
		h.unsubscribe(roomID, subscriber)
	}
	return result
}

func (h *RoomHub) subscriberCount(roomID string) int {
	if h == nil {
		return 0
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.rooms[roomID])
}

func (h *RoomHub) unsubscribe(roomID string, subscriber *roomSubscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	subscribers, ok := h.rooms[roomID]
	if !ok {
		subscriber.close()
		return
	}
	if _, exists := subscribers[subscriber]; exists {
		delete(subscribers, subscriber)
		subscriber.close()
	}
	if len(subscribers) == 0 {
		delete(h.rooms, roomID)
		if subscription, subscribed := h.subscriptions[roomID]; subscribed {
			delete(h.subscriptions, roomID)
			subscription.cancel()
			_ = subscription.pubsub.Close()
		}
	}
}
