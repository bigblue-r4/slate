package query

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/bigblue-r4/slate/internal/evidence"
	"github.com/bigblue-r4/slate/internal/store"
)

func mkEntry(seq uint64, ce evidence.CustodyEvent) store.Entry {
	data, _ := json.Marshal(ce)
	return store.Entry{Seq: seq, Timestamp: ce.Timestamp, Event: "slate/" + ce.EventType, Data: data}
}

func sampleEntries() []store.Entry {
	base := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	return []store.Entry{
		mkEntry(1, evidence.CustodyEvent{ItemID: "EV-1", CaseNumber: "C-1", EventType: "intake", Actor: "Rivera", ActorRole: "evidence_clerk", Timestamp: base}),
		mkEntry(2, evidence.CustodyEvent{ItemID: "EV-1", CaseNumber: "C-1", EventType: "transfer", Actor: "Chen", ActorRole: "chief", Timestamp: base.AddDate(0, 0, 2), Notes: "to lab"}),
		mkEntry(3, evidence.CustodyEvent{ItemID: "EV-2", CaseNumber: "C-2", EventType: "hold_set", Actor: "Chen", ActorRole: "chief", Timestamp: base.AddDate(0, 0, 5)}),
	}
}

func TestFilterByCaseAndType(t *testing.T) {
	e := sampleEntries()
	got := Filter{Case: "C-1"}.FilterEntries(e)
	if len(got) != 2 {
		t.Fatalf("case filter: want 2, got %d", len(got))
	}
	got = Filter{EventType: "hold_set"}.FilterEntries(e)
	if len(got) != 1 || got[0].Seq != 3 {
		t.Fatalf("type filter failed: %+v", got)
	}
}

func TestFilterByRoleAndActor(t *testing.T) {
	e := sampleEntries()
	if got := (Filter{Role: "chief"}).FilterEntries(e); len(got) != 2 {
		t.Fatalf("role filter: want 2, got %d", len(got))
	}
	// Actor is a case-insensitive substring match.
	if got := (Filter{Actor: "riv"}).FilterEntries(e); len(got) != 1 {
		t.Fatalf("actor filter: want 1, got %d", len(got))
	}
}

func TestFilterByDateRange(t *testing.T) {
	e := sampleEntries()
	from, _ := ParseDate("2026-05-02")
	to, _ := EndOfDay("2026-05-03")
	got := Filter{DateFrom: from, DateTo: to}.FilterEntries(e)
	if len(got) != 1 || got[0].Seq != 2 {
		t.Fatalf("date filter failed: %+v", got)
	}
}

func TestMatchItem(t *testing.T) {
	items := []*evidence.Item{
		{ID: "EV-1", CaseNumber: "C-1", Category: "firearms", Status: "active", LegalHold: false, Description: "Glock 19"},
		{ID: "EV-2", CaseNumber: "C-2", Category: "narcotics", Status: "active", LegalHold: true, Description: "baggie"},
	}
	count := func(f Filter) int {
		n := 0
		for _, it := range items {
			if f.MatchItem(it) {
				n++
			}
		}
		return n
	}
	if count(Filter{Category: "firearms"}) != 1 {
		t.Fatal("category filter failed")
	}
	if count(Filter{HoldState: "held"}) != 1 {
		t.Fatal("hold filter failed")
	}
	if count(Filter{HoldState: "released"}) != 1 {
		t.Fatal("released filter failed")
	}
	if count(Filter{Text: "glock"}) != 1 {
		t.Fatal("text filter failed")
	}
}

func TestFilterFromFunc(t *testing.T) {
	m := map[string]string{"case": "C-1", "type": "intake", "from": "2026-01-01", "to": "2026-12-31"}
	f, err := FilterFromFunc(func(k string) string { return m[k] })
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f.Case != "C-1" || f.EventType != "intake" {
		t.Fatalf("unexpected filter: %+v", f)
	}
	if f.DateFrom.IsZero() || f.DateTo.IsZero() {
		t.Fatal("dates not parsed")
	}
}

func TestFilterFromFuncBadDate(t *testing.T) {
	if _, err := FilterFromFunc(func(k string) string {
		if k == "from" {
			return "not-a-date"
		}
		return ""
	}); err == nil {
		t.Fatal("expected error on bad date")
	}
}
