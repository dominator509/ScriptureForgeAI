package ports

import "sync"

type RoomHub struct {
	mu    sync.RWMutex
	rooms map[string]map[*roomSubscriber]struct{}
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
	return &RoomHub{rooms: map[string]map[*roomSubscriber]struct{}{}}
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
	h.mu.Unlock()

	return subscriber.ch, func() {
		h.unsubscribe(roomID, subscriber)
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
	}
}
