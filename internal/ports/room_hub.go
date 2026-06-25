package ports

import "sync"

type RoomHub struct {
	mu    sync.RWMutex
	rooms map[string]map[chan RoomEvent]struct{}
}

func NewRoomHub() *RoomHub {
	return &RoomHub{rooms: map[string]map[chan RoomEvent]struct{}{}}
}

func (h *RoomHub) Subscribe(roomID string) (<-chan RoomEvent, func()) {
	if h == nil {
		ch := make(chan RoomEvent)
		close(ch)
		return ch, func() {}
	}
	ch := make(chan RoomEvent, 16)
	h.mu.Lock()
	if h.rooms[roomID] == nil {
		h.rooms[roomID] = map[chan RoomEvent]struct{}{}
	}
	h.rooms[roomID][ch] = struct{}{}
	h.mu.Unlock()

	return ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if subscribers, ok := h.rooms[roomID]; ok {
			delete(subscribers, ch)
			close(ch)
			if len(subscribers) == 0 {
				delete(h.rooms, roomID)
			}
		}
	}
}

func (h *RoomHub) Broadcast(roomID string, event RoomEvent) {
	if h == nil {
		return
	}
	h.mu.RLock()
	subscribers := make([]chan RoomEvent, 0, len(h.rooms[roomID]))
	for ch := range h.rooms[roomID] {
		subscribers = append(subscribers, ch)
	}
	h.mu.RUnlock()

	for _, ch := range subscribers {
		select {
		case ch <- event:
		default:
		}
	}
}
