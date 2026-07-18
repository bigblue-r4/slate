// Package query provides the shared filter logic used by both the CLI
// (`slate audit query`, `slate batch`) and the REST API (`/api/events`,
// `/api/items`). There is exactly one implementation so the dashboard and the
// command line can never diverge on what a filter means.
package query

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/bigblue-r4/slate/internal/evidence"
	"github.com/bigblue-r4/slate/internal/store"
)

// Filter is the union of every field the CLI and dashboard can filter on.
// Zero-valued fields are ignored. MatchEvent and MatchItem each honor the
// subset of fields that make sense for their target (documented per method).
type Filter struct {
	// Event-oriented fields (honored by MatchEvent).
	Role      string    // actor role (recorded on events from v1.1 onward)
	EventType string    // intake, transfer, access, hold_set, hold_release, export, destroyed
	Actor     string    // actor name (substring, case-insensitive)
	DateFrom  time.Time // inclusive lower bound on timestamp (UTC)
	DateTo    time.Time // inclusive upper bound on timestamp (UTC)

	// Item-oriented fields (honored by MatchItem).
	Category  string // narcotics, firearms, digital_media, documents, other
	Status    string // active, transferred, destroyed
	HoldState string // "held" or "released"

	// Shared fields (honored by both).
	Case   string // exact case number
	ItemID string // exact item ID
	Text   string // free-text substring across notes/description (case-insensitive)
}

// MatchEvent reports whether a custody event passes the filter. It honors:
// Role, EventType, Actor, DateFrom, DateTo, Case, ItemID, Text. Item-only
// fields (Category, Status) are ignored here; HoldState is expressed on events
// via EventType (hold_set / hold_release).
func (f Filter) MatchEvent(e evidence.CustodyEvent) bool {
	if f.Case != "" && e.CaseNumber != f.Case {
		return false
	}
	if f.ItemID != "" && e.ItemID != f.ItemID {
		return false
	}
	if f.EventType != "" && e.EventType != f.EventType {
		return false
	}
	if f.Role != "" && !strings.EqualFold(e.ActorRole, f.Role) {
		return false
	}
	if f.Actor != "" && !containsFold(e.Actor, f.Actor) {
		return false
	}
	if !f.DateFrom.IsZero() && e.Timestamp.Before(f.DateFrom) {
		return false
	}
	if !f.DateTo.IsZero() && e.Timestamp.After(f.DateTo) {
		return false
	}
	if f.Text != "" && !containsFold(e.Notes, f.Text) {
		return false
	}
	return true
}

// MatchItem reports whether an evidence item passes the filter. It honors:
// Case, ItemID, Category, Status, HoldState, Text (across description). Event-only
// fields (Role, EventType, Actor, dates) are ignored here.
func (f Filter) MatchItem(it *evidence.Item) bool {
	if f.Case != "" && it.CaseNumber != f.Case {
		return false
	}
	if f.ItemID != "" && it.ID != f.ItemID {
		return false
	}
	if f.Category != "" && it.Category != f.Category {
		return false
	}
	if f.Status != "" && it.Status != f.Status {
		return false
	}
	switch strings.ToLower(f.HoldState) {
	case "held", "hold", "on_hold":
		if !it.LegalHold {
			return false
		}
	case "released", "off", "none":
		if it.LegalHold {
			return false
		}
	case "":
		// no hold filter
	}
	if f.Text != "" && !containsFold(it.Description, f.Text) &&
		!containsFold(it.CaseNumber, f.Text) && !containsFold(it.ID, f.Text) {
		return false
	}
	return true
}

// MatchStoreEntry decodes a raw log entry's Data as a CustodyEvent and applies
// MatchEvent. If the decoded event has no timestamp (e.g. a system event), the
// log entry's own timestamp is used for date filtering. This is the predicate
// shared by `slate audit query` and the /api/events REST handler.
func (f Filter) MatchStoreEntry(e store.Entry) bool {
	var ce evidence.CustodyEvent
	if len(e.Data) > 0 {
		_ = json.Unmarshal(e.Data, &ce)
	}
	if ce.Timestamp.IsZero() {
		ce.Timestamp = e.Timestamp
	}
	return f.MatchEvent(ce)
}

// FilterEntries returns the subset of entries that pass the filter, preserving
// order. The original store.Entry values are returned unchanged so downstream
// consumers keep seq/prev_hash for audit and court export.
func (f Filter) FilterEntries(entries []store.Entry) []store.Entry {
	out := make([]store.Entry, 0, len(entries))
	for _, e := range entries {
		if f.MatchStoreEntry(e) {
			out = append(out, e)
		}
	}
	return out
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

// FilterFromFunc builds a Filter by reading named parameters through get. The
// same parameter names are used by CLI flags and REST query strings so the two
// surfaces stay identical:
//
//	case, item, type, role, actor, category, status, hold, from, to, text
//
// "from"/"to" are YYYY-MM-DD; "to" is treated as inclusive (end of day).
func FilterFromFunc(get func(string) string) (Filter, error) {
	f := Filter{
		Case:      get("case"),
		ItemID:    get("item"),
		EventType: get("type"),
		Role:      get("role"),
		Actor:     get("actor"),
		Category:  get("category"),
		Status:    get("status"),
		HoldState: get("hold"),
		Text:      get("text"),
	}
	from, err := ParseDate(get("from"))
	if err != nil {
		return f, err
	}
	to, err := EndOfDay(get("to"))
	if err != nil {
		return f, err
	}
	f.DateFrom, f.DateTo = from, to
	return f, nil
}

// ParseDate parses a YYYY-MM-DD string into a UTC time at start of day.
// An empty string returns the zero time (meaning "no bound").
func ParseDate(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse("2006-01-02", s)
}

// EndOfDay converts a YYYY-MM-DD lower-bound date into an inclusive upper bound
// (23:59:59.999999999 UTC of that day). An empty string returns the zero time.
func EndOfDay(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, err
	}
	return t.Add(24*time.Hour - time.Nanosecond), nil
}
