// Package evidence manages the SLATE evidence catalog and tamper-evident audit log.
package evidence

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bigblue-r4/slate/internal/store"
)

// Item is a tracked evidence item.
type Item struct {
	ID          string    `json:"id"`
	CaseNumber  string    `json:"case_number"`
	Description string    `json:"description"`
	Category    string    `json:"category"` // narcotics, firearms, digital_media, documents, other
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"` // actor name at intake
	LegalHold   bool      `json:"legal_hold"`
	HoldReason  string    `json:"hold_reason,omitempty"`
	Status      string    `json:"status"` // active, transferred, destroyed
	CurrentNode string    `json:"current_node"`
}

// CustodyEvent is one step in the chain of custody, written to the tamper-evident log.
type CustodyEvent struct {
	ItemID     string    `json:"item_id"`
	CaseNumber string    `json:"case_number"`
	EventType  string    `json:"event_type"` // intake, transfer, access, hold_set, hold_release, export, destroyed
	Timestamp  time.Time `json:"timestamp"`
	Actor      string    `json:"actor"`                // always from the authenticated token name
	ActorRole  string    `json:"actor_role,omitempty"` // role bound to the token (v1.1+; empty on pre-v1.1 events)
	FromNode   string    `json:"from_node,omitempty"`
	ToNode     string    `json:"to_node,omitempty"`
	Notes      string    `json:"notes,omitempty"`
	ExportRef  string    `json:"export_ref,omitempty"`
	BundleRef  string    `json:"bundle_ref,omitempty"` // inter-node transfer bundle ID (v1.1+)
}

const catalogFile = "items.json"

// Store manages the evidence catalog and the encrypted, hash-chained audit log.
type Store struct {
	log   *store.Store
	key   []byte
	dir   string
	mu    sync.RWMutex
	items map[string]*Item
}

// Open opens or creates the evidence store at dir.
func Open(dir string, key []byte) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	s, err := store.Open(dir, key)
	if err != nil {
		return nil, err
	}
	ev := &Store{
		log:   s,
		key:   key,
		dir:   dir,
		items: make(map[string]*Item),
	}
	if err := ev.loadCatalog(); err != nil {
		return nil, err
	}
	return ev, nil
}

// Close flushes and closes the underlying log.
func (ev *Store) Close() error {
	return ev.log.Close()
}

// RecordIntake creates a new evidence item and logs the intake event.
func (ev *Store) RecordIntake(item *Item, actor, actorRole string) error {
	ev.mu.Lock()
	defer ev.mu.Unlock()

	id, err := newItemID()
	if err != nil {
		return err
	}
	item.ID = id
	item.CreatedAt = time.Now().UTC()
	item.CreatedBy = actor
	item.Status = "active"
	ev.items[id] = item

	if err := ev.saveCatalog(); err != nil {
		return err
	}
	return ev.log.Append("INFO", "slate/intake", "slate", CustodyEvent{
		ItemID:     id,
		CaseNumber: item.CaseNumber,
		EventType:  "intake",
		Timestamp:  item.CreatedAt,
		Actor:      actor,
		ActorRole:  actorRole,
		ToNode:     item.CurrentNode,
		Notes:      item.Description,
	})
}

// RecordTransfer transfers an item to a new node. Blocked if item is under legal hold.
func (ev *Store) RecordTransfer(itemID, actor, actorRole, fromNode, toNode, notes string) error {
	ev.mu.Lock()
	defer ev.mu.Unlock()

	item, ok := ev.items[itemID]
	if !ok {
		return fmt.Errorf("item not found: %s", itemID)
	}
	if item.LegalHold {
		return fmt.Errorf("item %s is under legal hold — release hold before transfer", itemID)
	}
	caseNum := item.CaseNumber
	item.CurrentNode = toNode
	if err := ev.saveCatalog(); err != nil {
		return err
	}
	return ev.log.Append("INFO", "slate/transfer", "slate", CustodyEvent{
		ItemID:     itemID,
		CaseNumber: caseNum,
		EventType:  "transfer",
		Timestamp:  time.Now().UTC(),
		Actor:      actor,
		ActorRole:  actorRole,
		FromNode:   fromNode,
		ToNode:     toNode,
		Notes:      notes,
	})
}

// RecordAccess logs that an item was examined.
func (ev *Store) RecordAccess(itemID, actor, actorRole, notes string) error {
	ev.mu.RLock()
	caseNum := ev.caseNumberFor(itemID)
	ev.mu.RUnlock()

	return ev.log.Append("INFO", "slate/access", "slate", CustodyEvent{
		ItemID:     itemID,
		CaseNumber: caseNum,
		EventType:  "access",
		Timestamp:  time.Now().UTC(),
		Actor:      actor,
		ActorRole:  actorRole,
		Notes:      notes,
	})
}

// SetLegalHold places a legal hold on an item.
func (ev *Store) SetLegalHold(itemID, actor, actorRole, reason string) error {
	ev.mu.Lock()
	defer ev.mu.Unlock()

	item, ok := ev.items[itemID]
	if !ok {
		return fmt.Errorf("item not found: %s", itemID)
	}
	item.LegalHold = true
	item.HoldReason = reason
	caseNum := item.CaseNumber
	if err := ev.saveCatalog(); err != nil {
		return err
	}
	return ev.log.Append("WARN", "slate/hold_set", "slate", CustodyEvent{
		ItemID:     itemID,
		CaseNumber: caseNum,
		EventType:  "hold_set",
		Timestamp:  time.Now().UTC(),
		Actor:      actor,
		ActorRole:  actorRole,
		Notes:      reason,
	})
}

// ReleaseLegalHold removes a legal hold from an item.
func (ev *Store) ReleaseLegalHold(itemID, actor, actorRole, notes string) error {
	ev.mu.Lock()
	defer ev.mu.Unlock()

	item, ok := ev.items[itemID]
	if !ok {
		return fmt.Errorf("item not found: %s", itemID)
	}
	item.LegalHold = false
	item.HoldReason = ""
	caseNum := item.CaseNumber
	if err := ev.saveCatalog(); err != nil {
		return err
	}
	return ev.log.Append("INFO", "slate/hold_release", "slate", CustodyEvent{
		ItemID:     itemID,
		CaseNumber: caseNum,
		EventType:  "hold_release",
		Timestamp:  time.Now().UTC(),
		Actor:      actor,
		ActorRole:  actorRole,
		Notes:      notes,
	})
}

// RecordExport logs that a court export bundle was generated.
func (ev *Store) RecordExport(itemID, actor, actorRole, exportRef string) error {
	ev.mu.RLock()
	caseNum := ev.caseNumberFor(itemID)
	ev.mu.RUnlock()

	return ev.log.Append("INFO", "slate/export", "slate", CustodyEvent{
		ItemID:     itemID,
		CaseNumber: caseNum,
		EventType:  "export",
		Timestamp:  time.Now().UTC(),
		Actor:      actor,
		ActorRole:  actorRole,
		ExportRef:  exportRef,
	})
}

// RecordDestroyed marks an item as destroyed. Blocked if item is under legal hold.
func (ev *Store) RecordDestroyed(itemID, actor, actorRole, notes string) error {
	ev.mu.Lock()
	defer ev.mu.Unlock()

	item, ok := ev.items[itemID]
	if !ok {
		return fmt.Errorf("item not found: %s", itemID)
	}
	if item.LegalHold {
		return fmt.Errorf("item %s is under legal hold — cannot destroy", itemID)
	}
	item.Status = "destroyed"
	caseNum := item.CaseNumber
	if err := ev.saveCatalog(); err != nil {
		return err
	}
	return ev.log.Append("WARN", "slate/destroyed", "slate", CustodyEvent{
		ItemID:     itemID,
		CaseNumber: caseNum,
		EventType:  "destroyed",
		Timestamp:  time.Now().UTC(),
		Actor:      actor,
		ActorRole:  actorRole,
		Notes:      notes,
	})
}

// AppendSystem logs a system-level event (init, start, etc.).
func (ev *Store) AppendSystem(level, event, notes string) error {
	return ev.log.Append(level, event, "slate-system", map[string]string{"notes": notes})
}

// GetItem returns a copy of the current item state.
func (ev *Store) GetItem(itemID string) (*Item, bool) {
	ev.mu.RLock()
	defer ev.mu.RUnlock()
	item, ok := ev.items[itemID]
	if !ok {
		return nil, false
	}
	cp := *item
	return &cp, true
}

// GetItems returns all items, optionally filtered by case number.
func (ev *Store) GetItems(caseNumber string) []*Item {
	ev.mu.RLock()
	defer ev.mu.RUnlock()
	var out []*Item
	for _, item := range ev.items {
		if caseNumber == "" || item.CaseNumber == caseNumber {
			cp := *item
			out = append(out, &cp)
		}
	}
	return out
}

// GetAllEvents decrypts and returns all audit log entries.
func (ev *Store) GetAllEvents() ([]store.Entry, error) {
	return store.ReadAll(ev.dir, ev.key)
}

// VerifyChain checks the tamper-evident hash chain of the underlying log and
// reports the first break, if any.
func (ev *Store) VerifyChain() (store.ChainResult, error) {
	return store.VerifyChain(ev.dir, ev.key)
}

// EventsForItem returns all audit log entries whose custody event references
// itemID, in log order.
func (ev *Store) EventsForItem(itemID string) ([]store.Entry, error) {
	all, err := store.ReadAll(ev.dir, ev.key)
	if err != nil {
		return nil, err
	}
	var out []store.Entry
	for _, e := range all {
		if len(e.Data) == 0 {
			continue
		}
		var ce CustodyEvent
		if err := json.Unmarshal(e.Data, &ce); err != nil {
			continue
		}
		if ce.ItemID == itemID {
			out = append(out, e)
		}
	}
	return out, nil
}

// AcceptIncomingTransfer records an item received from a peer node, preserving
// the item's original ID so the custody chain is continuous across the handoff.
// It refuses if an item with that ID already exists locally (replay / duplicate
// protection). It logs a transfer event on THIS node citing the transfer bundle.
func (ev *Store) AcceptIncomingTransfer(item *Item, actor, actorRole, fromNode, thisNode, bundleRef string) error {
	ev.mu.Lock()
	defer ev.mu.Unlock()

	if _, exists := ev.items[item.ID]; exists {
		return fmt.Errorf("item %s already exists on this node — refusing duplicate transfer", item.ID)
	}
	cp := *item
	cp.CurrentNode = thisNode
	cp.Status = "active"
	cp.LegalHold = false
	cp.HoldReason = ""
	ev.items[cp.ID] = &cp
	if err := ev.saveCatalog(); err != nil {
		return err
	}
	return ev.log.Append("INFO", "slate/transfer_in", "slate", CustodyEvent{
		ItemID:     cp.ID,
		CaseNumber: cp.CaseNumber,
		EventType:  "transfer",
		Timestamp:  time.Now().UTC(),
		Actor:      actor,
		ActorRole:  actorRole,
		FromNode:   fromNode,
		ToNode:     thisNode,
		BundleRef:  bundleRef,
		Notes:      fmt.Sprintf("received from %s via bundle %s", fromNode, bundleRef),
	})
}

// RecordOutgoingTransfer logs on THIS node that custody of an item was handed off
// to a peer via a signed transfer bundle. Blocked if the item is under legal hold.
func (ev *Store) RecordOutgoingTransfer(itemID, actor, actorRole, toNode, bundleRef, notes string) error {
	ev.mu.Lock()
	defer ev.mu.Unlock()

	item, ok := ev.items[itemID]
	if !ok {
		return fmt.Errorf("item not found: %s", itemID)
	}
	if item.LegalHold {
		return fmt.Errorf("item %s is under legal hold — release hold before transfer", itemID)
	}
	fromNode := item.CurrentNode
	item.Status = "transferred"
	item.CurrentNode = toNode
	if err := ev.saveCatalog(); err != nil {
		return err
	}
	return ev.log.Append("INFO", "slate/transfer_out", "slate", CustodyEvent{
		ItemID:     itemID,
		CaseNumber: item.CaseNumber,
		EventType:  "transfer",
		Timestamp:  time.Now().UTC(),
		Actor:      actor,
		ActorRole:  actorRole,
		FromNode:   fromNode,
		ToNode:     toNode,
		BundleRef:  bundleRef,
		Notes:      notes,
	})
}

func (ev *Store) caseNumberFor(itemID string) string {
	if item, ok := ev.items[itemID]; ok {
		return item.CaseNumber
	}
	return ""
}

func (ev *Store) loadCatalog() error {
	path := filepath.Join(ev.dir, catalogFile)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &ev.items)
}

func (ev *Store) saveCatalog() error {
	path := filepath.Join(ev.dir, catalogFile)
	data, err := json.MarshalIndent(ev.items, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// newItemID generates an ID like EV-20260512-a3b2c1d0.
func newItemID() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("EV-%s-%s", time.Now().UTC().Format("20060102"), hex.EncodeToString(b[:])), nil
}
