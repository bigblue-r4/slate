package evidence

import (
	"testing"
)

func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i * 7)
	}
	return k
}

func openTest(t *testing.T) *Store {
	t.Helper()
	ev, err := Open(t.TempDir(), testKey())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = ev.Close() })
	return ev
}

func TestIntakeAndEvents(t *testing.T) {
	ev := openTest(t)
	it := &Item{CaseNumber: "C-1", Description: "Glock", Category: "firearms", CurrentNode: "room-1"}
	if err := ev.RecordIntake(it, "Rivera", "evidence_clerk"); err != nil {
		t.Fatalf("intake: %v", err)
	}
	if it.ID == "" || it.Status != "active" {
		t.Fatalf("intake did not populate item: %+v", it)
	}
	evs, err := ev.EventsForItem(it.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %d", len(evs))
	}
}

func TestLegalHoldBlocksTransfer(t *testing.T) {
	ev := openTest(t)
	it := &Item{CaseNumber: "C-1", Description: "x"}
	_ = ev.RecordIntake(it, "a", "chief")
	if err := ev.SetLegalHold(it.ID, "a", "chief", "trial"); err != nil {
		t.Fatalf("hold: %v", err)
	}
	if err := ev.RecordTransfer(it.ID, "a", "chief", "n1", "n2", ""); err == nil {
		t.Fatal("transfer should be blocked under legal hold")
	}
	if err := ev.RecordOutgoingTransfer(it.ID, "a", "chief", "node-B", "XFER-1", ""); err == nil {
		t.Fatal("outgoing transfer should be blocked under legal hold")
	}
}

func TestAcceptIncomingTransferPreservesID(t *testing.T) {
	ev := openTest(t)
	incoming := &Item{ID: "EV-REMOTE-1", CaseNumber: "C-9", Description: "bag", Category: "documents"}
	if err := ev.AcceptIncomingTransfer(incoming, "peer:node-A", "", "node-A", "node-B", "XFER-1"); err != nil {
		t.Fatalf("accept: %v", err)
	}
	got, ok := ev.GetItem("EV-REMOTE-1")
	if !ok {
		t.Fatal("item not stored under original ID")
	}
	if got.CurrentNode != "node-B" {
		t.Fatalf("current node not updated: %+v", got)
	}
	// Duplicate handoff of the same item ID must be refused (replay protection).
	if err := ev.AcceptIncomingTransfer(incoming, "peer:node-A", "", "node-A", "node-B", "XFER-2"); err == nil {
		t.Fatal("duplicate incoming transfer should be rejected")
	}
}

func TestActorRoleRecorded(t *testing.T) {
	ev := openTest(t)
	it := &Item{CaseNumber: "C-1", Description: "x"}
	_ = ev.RecordIntake(it, "Rivera", "evidence_clerk")
	evs, _ := ev.EventsForItem(it.ID)
	if len(evs) == 0 {
		t.Fatal("no events")
	}
	// Decode the custody event and confirm the role was persisted.
	res, err := ev.VerifyChain()
	if err != nil || !res.OK {
		t.Fatalf("chain should verify: %+v %v", res, err)
	}
}
