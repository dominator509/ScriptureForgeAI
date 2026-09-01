package ports

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type scriptedRows struct {
	values  [][]any
	current int
	err     error
}

var _ pgx.Rows = (*scriptedRows)(nil)

func (r *scriptedRows) Close() {}

func (r *scriptedRows) Err() error { return r.err }

func (r *scriptedRows) CommandTag() pgconn.CommandTag { return pgconn.NewCommandTag("SELECT") }

func (r *scriptedRows) FieldDescriptions() []pgconn.FieldDescription { return nil }

func (r *scriptedRows) Next() bool {
	if r.current >= len(r.values) {
		return false
	}
	r.current++
	return true
}

func (r *scriptedRows) Scan(dest ...any) error {
	values := r.values[r.current-1]
	if len(dest) != len(values) {
		return fmt.Errorf("scan destination count %d, values count %d", len(dest), len(values))
	}
	for index, target := range dest {
		switch destination := target.(type) {
		case *string:
			value, ok := values[index].(string)
			if !ok {
				return fmt.Errorf("value %d is not a string", index)
			}
			*destination = value
		case *bool:
			value, ok := values[index].(bool)
			if !ok {
				return fmt.Errorf("value %d is not a bool", index)
			}
			*destination = value
		case *int:
			value, ok := values[index].(int)
			if !ok {
				return fmt.Errorf("value %d is not an int", index)
			}
			*destination = value
		default:
			return fmt.Errorf("unsupported scan destination %T", target)
		}
	}
	return nil
}

func (r *scriptedRows) Values() ([]any, error) {
	if r.current == 0 || r.current > len(r.values) {
		return nil, errors.New("no current row")
	}
	return r.values[r.current-1], nil
}

func (r *scriptedRows) RawValues() [][]byte { return nil }

func (r *scriptedRows) Conn() *pgx.Conn { return nil }

func TestScanActiveRoomRowsRejectsCursorErrors(t *testing.T) {
	rooms, err := scanActiveRoomRows(&scriptedRows{
		values: [][]any{{"room-1", "Study", true, "2026-08-16T00:00:00Z", "offline", "", `{"mode":"offline","join_url":"offline://in-person"}`}},
		err:    errors.New("cursor failed after first room"),
	})
	if err == nil {
		t.Fatal("scanActiveRoomRows returned nil error for a failed cursor")
	}
	if rooms != nil {
		t.Fatalf("scanActiveRoomRows returned partial rooms %#v", rooms)
	}
}

func TestScanJournalRowsRejectsCursorErrors(t *testing.T) {
	entries, err := scanJournalRows(&scriptedRows{
		values: [][]any{{"entry-1", "ciphertext", "iv", "salt-v1", 1, "2026-08-16T00:00:00Z"}},
		err:    errors.New("cursor failed after first entry"),
	})
	if err == nil {
		t.Fatal("scanJournalRows returned nil error for a failed cursor")
	}
	if entries != nil {
		t.Fatalf("scanJournalRows returned partial entries %#v", entries)
	}
}
