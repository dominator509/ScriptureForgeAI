package room

import "context"

// MeetingConfig specifies the parameters for creating a new synchronized meeting room.
type MeetingConfig struct {
	Topic    string
	Duration int // in minutes
	Password string
	HostID   string
}

// MeetingDetails provides the connection identifiers returned by the external adapter.
type MeetingDetails struct {
	ID       string
	JoinURL  string
	StartURL string
}

// MeetingAdapter dictates the required external conference orchestration contract.
// This interface decouples the application core from the specific external provider (e.g., Zoom, Teams).
type MeetingAdapter interface {
	// CreateMeeting provisions a new active environment on the external system.
	CreateMeeting(ctx context.Context, config MeetingConfig) (*MeetingDetails, error)

	// TerminateMeeting safely concludes the active environment, forcing client disconnects.
	TerminateMeeting(ctx context.Context, meetingID string) error

	// GetMeetingStatus retrieves the current lifecycle state from the external system.
	GetMeetingStatus(ctx context.Context, meetingID string) (string, error)
}
