// slate — SLATE: Secure Log Audit for Trace Evidence
//
// Tamper-evident chain-of-custody evidence management for law enforcement.
// Role-based API access. Encrypted, hash-chained audit log. Ed25519-signed
// court export bundles.
//
// Usage:
//
//	slate init       [--department NAME] [--node ID]
//	slate status
//	slate intake     --case C --desc D [--cat CATEGORY] [--node NODE] [--actor NAME]
//	slate transfer   --item ID --from NODE --to NODE [--actor NAME] [--notes TEXT]
//	slate hold set   --item ID --reason TEXT [--actor NAME]
//	slate hold release --item ID [--actor NAME] [--notes TEXT]
//	slate export     --case C [--sign] [--actor NAME]
//	slate token add  --role ROLE --name NAME
//	slate token list
//	slate token revoke TOKEN
//	slate keygen
//	slate peer discover [--for DUR]
//	slate peer refresh  [--for DUR] [--dry-run]
//	slate peer transfer --item ID --to NODE [--encrypt]
//	slate serve      [--port PORT] [--peer-listen HOST:PORT] [--announce] [--require-encryption]
//	slate version
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "embed"

	"golang.org/x/crypto/hkdf"

	"github.com/bigblue-r4/slate/internal/apiwire"
	"github.com/bigblue-r4/slate/internal/discovery"
	"github.com/bigblue-r4/slate/internal/evidence"
	slateexport "github.com/bigblue-r4/slate/internal/export"
	"github.com/bigblue-r4/slate/internal/machid"
	"github.com/bigblue-r4/slate/internal/peer"
	"github.com/bigblue-r4/slate/internal/query"
	"github.com/bigblue-r4/slate/internal/roles"
	"github.com/bigblue-r4/slate/internal/soul"
	"github.com/bigblue-r4/slate/internal/tokens"
)

//go:embed static/index.html
var dashboardHTML []byte

const version = "1.2.0"

// ── context keys ──────────────────────────────────────────────────────────────

type contextKey string

const (
	ctxTokenEntry contextKey = "slate.token_entry"
)

// ── Config ────────────────────────────────────────────────────────────────────

// Config is persisted to ~/.slate/config.json.
type Config struct {
	Department    string `json:"department"`
	NodeID        string `json:"node_id"`
	Port          int    `json:"port"`
	SigningKeyPub string `json:"signing_key_pub"` // public key for verifying exports; private key never stored
}

// ── entry point ───────────────────────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "init":
		runInit()
	case "status":
		runStatus()
	case "intake":
		runIntake()
	case "transfer":
		runTransfer()
	case "hold":
		runHold()
	case "export":
		runExport()
	case "audit":
		runAudit()
	case "import":
		runImport()
	case "batch":
		runBatch()
	case "verify":
		runVerify()
	case "peer":
		runPeer()
	case "token":
		runToken()
	case "keygen":
		runKeygen()
	case "serve":
		runServe()
	case "version", "--version", "-v":
		runVersion()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

// ── commands ──────────────────────────────────────────────────────────────────

func runInit() {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dept := fs.String("department", "", "Department name")
	nodeID := fs.String("node", "node-001", "Node identifier for this installation")
	_ = fs.Parse(os.Args[2:])

	dir := slateDir()
	primaryDir := filepath.Join(dir, "primary")

	if _, err := os.Stat(primaryDir); err == nil {
		fatal("already initialized at %s — remove that directory to re-initialize", dir)
	}

	soulDst := filepath.Join(dir, "soul.toml")
	if err := installSoul(soulDst); err != nil {
		fatal("install soul: %v", err)
	}

	s, err := soul.Load(soulDst)
	if err != nil {
		fatal("soul verification failed: %v\nDo not proceed.", err)
	}
	info("soul verified: %s v%s", s.Identity.AgentName, s.Identity.AgentVersion)

	key, err := deriveSLATEKey(machid.Get())
	if err != nil {
		fatal("derive key: %v", err)
	}
	ev, err := evidence.Open(primaryDir, key)
	if err != nil {
		fatal("open store: %v", err)
	}
	defer ev.Close()

	if err := ev.AppendSystem("INFO", "slate/init", "SLATE initialized"); err != nil {
		fatal("write init event: %v", err)
	}

	cfg := Config{Department: *dept, NodeID: *nodeID, Port: 8890}
	if err := saveConfig(dir, cfg); err != nil {
		fatal("save config: %v", err)
	}

	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║  SLATE — Secure Log Audit for Trace Evidence                  ║")
	fmt.Println("║  Initialized.                                                 ║")
	fmt.Println("║                                                               ║")
	fmt.Printf("║  Node     : %-48s║\n", *nodeID)
	fmt.Printf("║  Data dir : %-48s║\n", dir)
	fmt.Println("║                                                               ║")
	fmt.Println("║  Next: add your first access token                            ║")
	fmt.Println(`║  slate token add --role chief --name "Chief Johnson"           ║`)
	fmt.Println("║                                                               ║")
	fmt.Println("║  Then start the dashboard:                                    ║")
	fmt.Println("║  slate serve                                                  ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
}

func runStatus() {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
	_ = fs.Parse(os.Args[2:])

	dir := slateDir()
	cfg := mustLoadConfig(dir)
	key := mustDeriveKey()

	soulPath := filepath.Join(dir, "soul.toml")
	soulStatus := "OK"
	if _, err := soul.Load(soulPath); err != nil {
		soulStatus = "FAILED"
	}

	ev, err := evidence.Open(filepath.Join(dir, "primary"), key)
	if err != nil {
		fatal("open store: %v", err)
	}
	defer ev.Close()

	items := ev.GetItems("")
	holdCount := 0
	for _, it := range items {
		if it.LegalHold {
			holdCount++
		}
	}
	events, _ := ev.GetAllEvents()

	ts, _ := tokens.Open(filepath.Join(dir, "tokens.json"))
	tokenCount := 0
	if ts != nil {
		tokenCount = ts.Len()
	}

	var lastEvent string
	var lastAt *time.Time
	if len(events) > 0 {
		e := events[len(events)-1]
		lastEvent = e.Event
		t := e.Timestamp
		lastAt = &t
	}

	if *jsonOut {
		resp := map[string]any{
			"version":     version,
			"node_id":     cfg.NodeID,
			"department":  cfg.Department,
			"soul_status": soulStatus,
			"item_count":  len(items),
			"hold_count":  holdCount,
			"log_entries": len(events),
			"token_count": tokenCount,
		}
		if lastEvent != "" && lastAt != nil {
			resp["last_event"] = lastEvent
			resp["last_event_at"] = lastAt
		}
		apiwire.Print(resp)
		return
	}

	fmt.Println("─────────────────────────────────────────────────────────")
	fmt.Printf("SLATE  v%s — Secure Log Audit for Trace Evidence\n", version)
	fmt.Printf("Node         : %s\n", cfg.NodeID)
	fmt.Printf("Department   : %s\n", cfg.Department)
	fmt.Printf("Soul         : %s (%s)\n", soulPath, soulStatus)
	fmt.Printf("Items        : %d total / %d on legal hold\n", len(items), holdCount)
	fmt.Printf("Log entries  : %d\n", len(events))
	fmt.Printf("Access tokens: %d configured\n", tokenCount)
	if lastEvent != "" && lastAt != nil {
		fmt.Printf("Last event   : [%s] %s\n", lastAt.Format(time.RFC3339), lastEvent)
	}
	fmt.Println("─────────────────────────────────────────────────────────")
}

func runIntake() {
	fs := flag.NewFlagSet("intake", flag.ExitOnError)
	caseNum := fs.String("case", "", "Case number (required)")
	cat := fs.String("cat", "other", "Category: narcotics, firearms, digital_media, documents, other")
	desc := fs.String("desc", "", "Description (required)")
	actor := fs.String("actor", osUser(), "Actor name for audit log")
	role := fs.String("role", "", "Actor role for audit log (optional)")
	node := fs.String("node", "", "Current node/location")
	jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
	_ = fs.Parse(os.Args[2:])

	if *caseNum == "" || *desc == "" {
		usageErr(*jsonOut, "usage: slate intake --case CASE --desc DESC [--cat CATEGORY] [--node NODE] [--actor NAME] [--role ROLE]")
	}

	ev, _ := mustOpenStore()
	defer ev.Close()

	item := &evidence.Item{
		CaseNumber:  *caseNum,
		Description: *desc,
		Category:    *cat,
		CurrentNode: *node,
	}
	if err := ev.RecordIntake(item, *actor, *role); err != nil {
		failCmd(*jsonOut, apiwire.CodeInternal, fmt.Sprintf("intake: %v", err))
	}
	if *jsonOut {
		apiwire.Print(item)
		return
	}
	fmt.Printf("Intake recorded: %s\n", item.ID)
	fmt.Printf("  Case     : %s\n", item.CaseNumber)
	fmt.Printf("  Category : %s\n", item.Category)
	fmt.Printf("  Actor    : %s\n", *actor)
}

func runTransfer() {
	fs := flag.NewFlagSet("transfer", flag.ExitOnError)
	itemID := fs.String("item", "", "Item ID (required)")
	from := fs.String("from", "", "From node (required)")
	to := fs.String("to", "", "To node (required)")
	actor := fs.String("actor", osUser(), "Actor name for audit log")
	role := fs.String("role", "", "Actor role for audit log (optional)")
	notes := fs.String("notes", "", "Transfer notes")
	jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
	_ = fs.Parse(os.Args[2:])

	if *itemID == "" || *from == "" || *to == "" {
		usageErr(*jsonOut, "usage: slate transfer --item ID --from NODE --to NODE [--actor NAME] [--role ROLE] [--notes TEXT]")
	}

	ev, _ := mustOpenStore()
	defer ev.Close()

	if err := ev.RecordTransfer(*itemID, *actor, *role, *from, *to, *notes); err != nil {
		failCmd(*jsonOut, apiwire.CodeBadRequest, fmt.Sprintf("transfer: %v", err))
	}
	if *jsonOut {
		apiwire.Print(map[string]string{"item_id": *itemID, "from_node": *from, "to_node": *to})
		return
	}
	fmt.Printf("Transfer recorded: %s → %s (%s)\n", *from, *to, *itemID)
}

func runHold() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: slate hold <set|release> [flags]")
		os.Exit(1)
	}
	switch os.Args[2] {
	case "set":
		fs := flag.NewFlagSet("hold set", flag.ExitOnError)
		itemID := fs.String("item", "", "Item ID (required)")
		reason := fs.String("reason", "", "Hold reason (required)")
		actor := fs.String("actor", osUser(), "Actor name for audit log")
		role := fs.String("role", "", "Actor role for audit log (optional)")
		jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
		_ = fs.Parse(os.Args[3:])
		if *itemID == "" || *reason == "" {
			usageErr(*jsonOut, "usage: slate hold set --item ID --reason TEXT [--actor NAME] [--role ROLE]")
		}
		ev, _ := mustOpenStore()
		defer ev.Close()
		if err := ev.SetLegalHold(*itemID, *actor, *role, *reason); err != nil {
			failCmd(*jsonOut, apiwire.CodeBadRequest, fmt.Sprintf("hold set: %v", err))
		}
		if *jsonOut {
			apiwire.Print(map[string]any{"item_id": *itemID, "legal_hold": true, "reason": *reason})
			return
		}
		fmt.Printf("Legal hold set: %s\n", *itemID)

	case "release":
		fs := flag.NewFlagSet("hold release", flag.ExitOnError)
		itemID := fs.String("item", "", "Item ID (required)")
		actor := fs.String("actor", osUser(), "Actor name for audit log")
		role := fs.String("role", "", "Actor role for audit log (optional)")
		notes := fs.String("notes", "", "Release notes")
		jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
		_ = fs.Parse(os.Args[3:])
		if *itemID == "" {
			usageErr(*jsonOut, "usage: slate hold release --item ID [--actor NAME] [--role ROLE] [--notes TEXT]")
		}
		ev, _ := mustOpenStore()
		defer ev.Close()
		if err := ev.ReleaseLegalHold(*itemID, *actor, *role, *notes); err != nil {
			failCmd(*jsonOut, apiwire.CodeBadRequest, fmt.Sprintf("hold release: %v", err))
		}
		if *jsonOut {
			apiwire.Print(map[string]any{"item_id": *itemID, "legal_hold": false})
			return
		}
		fmt.Printf("Legal hold released: %s\n", *itemID)

	default:
		fmt.Fprintf(os.Stderr, "unknown hold subcommand: %s\n", os.Args[2])
		os.Exit(1)
	}
}

func runExport() {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	caseNum := fs.String("case", "", "Case number (required)")
	actor := fs.String("actor", osUser(), "Actor name for audit log")
	role := fs.String("role", "", "Actor role for audit log (optional)")
	sign := fs.Bool("sign", false, "Sign with SLATE_SIGN_KEY env var")
	jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
	_ = fs.Parse(os.Args[2:])

	if *caseNum == "" {
		usageErr(*jsonOut, "usage: slate export --case CASE [--sign] [--actor NAME] [--role ROLE]")
	}

	dir := slateDir()
	cfg := mustLoadConfig(dir)
	ev, _ := mustOpenStore()
	defer ev.Close()

	entries, err := ev.GetAllEvents()
	if err != nil {
		failCmd(*jsonOut, apiwire.CodeInternal, fmt.Sprintf("read events: %v", err))
	}
	bundle, err := slateexport.Generate(entries, *caseNum, cfg.Department, cfg.NodeID)
	if err != nil {
		failCmd(*jsonOut, apiwire.CodeInternal, fmt.Sprintf("generate bundle: %v", err))
	}
	if *sign {
		privKey := os.Getenv("SLATE_SIGN_KEY")
		if privKey == "" {
			failCmd(*jsonOut, apiwire.CodeBadRequest, "--sign requires SLATE_SIGN_KEY env var (private key hex)")
		}
		if err := slateexport.Sign(bundle, privKey); err != nil {
			failCmd(*jsonOut, apiwire.CodeInternal, fmt.Sprintf("sign: %v", err))
		}
	}

	outPath := filepath.Join(dir, "exports", bundle.BundleID+".ndjson")
	if err := slateexport.WriteNDJSON(bundle, outPath); err != nil {
		failCmd(*jsonOut, apiwire.CodeInternal, fmt.Sprintf("write bundle: %v", err))
	}
	for _, item := range ev.GetItems(*caseNum) {
		_ = ev.RecordExport(item.ID, *actor, *role, bundle.BundleID)
	}

	if *jsonOut {
		apiwire.Print(map[string]any{
			"bundle_id":    bundle.BundleID,
			"case_number":  bundle.CaseNumber,
			"entry_count":  bundle.EntryCount,
			"sha256_chain": bundle.SHA256Chain,
			"signed":       bundle.Signature != "",
			"path":         outPath,
		})
		return
	}
	fmt.Printf("Export bundle: %s\n", bundle.BundleID)
	fmt.Printf("  Case        : %s\n", *caseNum)
	fmt.Printf("  Entries     : %d\n", bundle.EntryCount)
	fmt.Printf("  SHA-256     : %s\n", bundle.SHA256Chain)
	if bundle.Signature != "" {
		fmt.Printf("  Signed      : yes\n")
	}
	fmt.Printf("  Output      : %s\n", outPath)
}

func runVersion() {
	fs := flag.NewFlagSet("version", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
	// os.Args[1] may be "version", "--version" or "-v"; parse the remainder.
	if len(os.Args) > 2 {
		_ = fs.Parse(os.Args[2:])
	}
	if *jsonOut {
		apiwire.Print(map[string]string{"version": version, "name": "slate", "schema": apiwire.Schema})
		return
	}
	fmt.Printf("slate %s — Secure Log Audit for Trace Evidence\n", version)
}

// ── audit query ────────────────────────────────────────────────────────────────

func runAudit() {
	if len(os.Args) < 3 || os.Args[2] != "query" {
		fmt.Fprintln(os.Stderr, "usage: slate audit query [--case C] [--item ID] [--type EVENT] [--role ROLE] [--actor NAME] [--from DATE] [--to DATE] [--text STR] [--json]")
		os.Exit(1)
	}
	fs := flag.NewFlagSet("audit query", flag.ExitOnError)
	ptrs := map[string]*string{}
	for _, k := range []string{"case", "item", "type", "role", "actor", "from", "to", "text"} {
		ptrs[k] = fs.String(k, "", "filter by "+k)
	}
	jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
	_ = fs.Parse(os.Args[3:])

	f, err := query.FilterFromFunc(func(k string) string {
		if p, ok := ptrs[k]; ok {
			return *p
		}
		return ""
	})
	if err != nil {
		failCmd(*jsonOut, apiwire.CodeBadRequest, fmt.Sprintf("bad filter: %v", err))
	}

	ev, _ := mustOpenStore()
	defer ev.Close()
	entries, err := ev.GetAllEvents()
	if err != nil {
		failCmd(*jsonOut, apiwire.CodeInternal, fmt.Sprintf("read events: %v", err))
	}
	matched := f.FilterEntries(entries)

	if *jsonOut {
		apiwire.Print(matched)
		return
	}
	if len(matched) == 0 {
		fmt.Println("No matching events.")
		return
	}
	fmt.Printf("%-5s  %-20s  %-13s  %-18s  %-16s  %s\n", "SEQ", "TIMESTAMP", "EVENT", "ITEM", "ACTOR", "NOTES")
	fmt.Println(strings.Repeat("─", 110))
	for _, e := range matched {
		var ce evidence.CustodyEvent
		if len(e.Data) > 0 {
			_ = json.Unmarshal(e.Data, &ce)
		}
		et := ce.EventType
		if et == "" {
			et = e.Event
		}
		fmt.Printf("%-5d  %-20s  %-13s  %-18s  %-16s  %s\n",
			e.Seq, e.Timestamp.UTC().Format("2006-01-02 15:04:05"), et,
			truncate(ce.ItemID, 18), truncate(ce.Actor, 16), truncate(ce.Notes, 40))
	}
	fmt.Printf("\n%d event(s).\n", len(matched))
}

// ── bulk import ────────────────────────────────────────────────────────────────

// importRow is one row of a bulk-intake file (CSV header or JSON keys).
type importRow struct {
	CaseNumber  string `json:"case_number"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Node        string `json:"node"`
}

var validCategories = map[string]bool{
	"narcotics": true, "firearms": true, "digital_media": true, "documents": true, "other": true,
}

func runImport() {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	file := fs.String("file", "", "Path to CSV or JSON file (required)")
	format := fs.String("format", "", "Force format: csv or json (default: infer from extension)")
	dryRun := fs.Bool("dry-run", false, "Validate only; write nothing")
	actor := fs.String("actor", osUser(), "Actor name for audit log")
	role := fs.String("role", "", "Actor role for audit log (optional)")
	jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
	_ = fs.Parse(os.Args[2:])

	if *file == "" {
		usageErr(*jsonOut, "usage: slate import --file PATH [--format csv|json] [--dry-run] [--actor NAME] [--role ROLE] [--json]")
	}

	data, err := os.ReadFile(*file)
	if err != nil {
		failCmd(*jsonOut, apiwire.CodeBadRequest, fmt.Sprintf("read file: %v", err))
	}
	fmtType := *format
	if fmtType == "" {
		if strings.HasSuffix(strings.ToLower(*file), ".json") {
			fmtType = "json"
		} else {
			fmtType = "csv"
		}
	}

	rows, err := parseImport(data, fmtType)
	if err != nil {
		failCmd(*jsonOut, apiwire.CodeBadRequest, fmt.Sprintf("parse %s: %v", fmtType, err))
	}

	// Validate ALL rows first — the batch is atomic on validation.
	type rowErr struct {
		Row     int    `json:"row"`
		Message string `json:"message"`
	}
	var errs []rowErr
	for i, r := range rows {
		if r.CaseNumber == "" {
			errs = append(errs, rowErr{i + 1, "case_number is required"})
		}
		if r.Description == "" {
			errs = append(errs, rowErr{i + 1, "description is required"})
		}
		if r.Category != "" && !validCategories[r.Category] {
			errs = append(errs, rowErr{i + 1, fmt.Sprintf("unknown category %q", r.Category)})
		}
	}
	if len(errs) > 0 {
		if *jsonOut {
			apiwire.PrintErr(apiwire.CodeBadRequest, fmt.Sprintf("%d row(s) invalid — nothing imported", len(errs)))
		} else {
			fmt.Fprintf(os.Stderr, "Import aborted — %d invalid row(s), nothing written:\n", len(errs))
			for _, e := range errs {
				fmt.Fprintf(os.Stderr, "  row %d: %s\n", e.Row, e.Message)
			}
		}
		os.Exit(1)
	}

	if *dryRun {
		if *jsonOut {
			apiwire.Print(map[string]any{"dry_run": true, "valid_rows": len(rows), "imported": 0})
			return
		}
		fmt.Printf("Dry run OK: %d row(s) valid, nothing written.\n", len(rows))
		return
	}

	ev, _ := mustOpenStore()
	defer ev.Close()

	imported := make([]*evidence.Item, 0, len(rows))
	for i, r := range rows {
		cat := r.Category
		if cat == "" {
			cat = "other"
		}
		item := &evidence.Item{
			CaseNumber:  r.CaseNumber,
			Description: r.Description,
			Category:    cat,
			CurrentNode: r.Node,
		}
		if err := ev.RecordIntake(item, *actor, *role); err != nil {
			// I/O failure after partial writes: the append-only log cannot be
			// rolled back. Report exactly how far we got.
			failCmd(*jsonOut, apiwire.CodeInternal,
				fmt.Sprintf("row %d: intake failed after %d written: %v", i+1, len(imported), err))
		}
		imported = append(imported, item)
	}

	if *jsonOut {
		apiwire.Print(map[string]any{"dry_run": false, "valid_rows": len(rows), "imported": len(imported), "items": imported})
		return
	}
	fmt.Printf("Imported %d item(s):\n", len(imported))
	for _, it := range imported {
		fmt.Printf("  %s  %s  (%s)\n", it.ID, it.CaseNumber, it.Category)
	}
}

func parseImport(data []byte, format string) ([]importRow, error) {
	switch format {
	case "json":
		var rows []importRow
		if err := json.Unmarshal(data, &rows); err != nil {
			return nil, err
		}
		return rows, nil
	case "csv":
		r := csv.NewReader(strings.NewReader(string(data)))
		r.TrimLeadingSpace = true
		records, err := r.ReadAll()
		if err != nil {
			return nil, err
		}
		if len(records) < 1 {
			return nil, fmt.Errorf("empty file")
		}
		// Map header names to column indexes.
		idx := map[string]int{}
		for i, h := range records[0] {
			idx[strings.ToLower(strings.TrimSpace(h))] = i
		}
		col := func(rec []string, names ...string) string {
			for _, n := range names {
				if j, ok := idx[n]; ok && j < len(rec) {
					return strings.TrimSpace(rec[j])
				}
			}
			return ""
		}
		var rows []importRow
		for _, rec := range records[1:] {
			if len(rec) == 0 || (len(rec) == 1 && rec[0] == "") {
				continue
			}
			rows = append(rows, importRow{
				CaseNumber:  col(rec, "case_number", "case"),
				Description: col(rec, "description", "desc"),
				Category:    col(rec, "category", "cat"),
				Node:        col(rec, "node", "current_node"),
			})
		}
		return rows, nil
	default:
		return nil, fmt.Errorf("unknown format %q (use csv or json)", format)
	}
}

// ── batch operations ───────────────────────────────────────────────────────────

func runBatch() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: slate batch <transfer|hold> [flags]")
		os.Exit(1)
	}
	switch os.Args[2] {
	case "transfer":
		runBatchTransfer()
	case "hold":
		runBatchHold()
	default:
		fmt.Fprintf(os.Stderr, "unknown batch subcommand: %s\n", os.Args[2])
		os.Exit(1)
	}
}

// selectItemIDs resolves the target item IDs from either an explicit --items
// list or a query filter over the catalog.
func selectItemIDs(ev *evidence.Store, itemsCSV string, f query.Filter) []string {
	if itemsCSV != "" {
		var ids []string
		for _, id := range strings.Split(itemsCSV, ",") {
			if id = strings.TrimSpace(id); id != "" {
				ids = append(ids, id)
			}
		}
		return ids
	}
	var ids []string
	for _, it := range ev.GetItems("") {
		if f.MatchItem(it) {
			ids = append(ids, it.ID)
		}
	}
	return ids
}

func runBatchTransfer() {
	fs := flag.NewFlagSet("batch transfer", flag.ExitOnError)
	items := fs.String("items", "", "Comma-separated item IDs (or use --case/--category to select)")
	caseSel := fs.String("case", "", "Select all items in this case")
	catSel := fs.String("category", "", "Select all items in this category")
	from := fs.String("from", "", "From node")
	to := fs.String("to", "", "To node (required)")
	actor := fs.String("actor", osUser(), "Actor name for audit log")
	role := fs.String("role", "", "Actor role for audit log (optional)")
	notes := fs.String("notes", "", "Transfer notes")
	jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
	_ = fs.Parse(os.Args[3:])

	if *to == "" {
		usageErr(*jsonOut, "usage: slate batch transfer --to NODE (--items a,b,c | --case C | --category CAT) [--from NODE] [--notes TEXT]")
	}
	ev, _ := mustOpenStore()
	defer ev.Close()

	ids := selectItemIDs(ev, *items, query.Filter{Case: *caseSel, Category: *catSel})
	results := applyBatch(ids, func(id string) error {
		return ev.RecordTransfer(id, *actor, *role, *from, *to, *notes)
	})
	reportBatch(*jsonOut, "transfer", results)
}

func runBatchHold() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: slate batch hold <set|release> [flags]")
		os.Exit(1)
	}
	action := os.Args[3]
	fs := flag.NewFlagSet("batch hold", flag.ExitOnError)
	items := fs.String("items", "", "Comma-separated item IDs (or use --case/--category to select)")
	caseSel := fs.String("case", "", "Select all items in this case")
	catSel := fs.String("category", "", "Select all items in this category")
	reason := fs.String("reason", "", "Hold reason (required for set)")
	actor := fs.String("actor", osUser(), "Actor name for audit log")
	role := fs.String("role", "", "Actor role for audit log (optional)")
	notes := fs.String("notes", "", "Release notes")
	jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
	_ = fs.Parse(os.Args[4:])

	ev, _ := mustOpenStore()
	defer ev.Close()
	ids := selectItemIDs(ev, *items, query.Filter{Case: *caseSel, Category: *catSel})

	var results []batchResult
	switch action {
	case "set":
		if *reason == "" {
			usageErr(*jsonOut, "usage: slate batch hold set --reason TEXT (--items a,b,c | --case C)")
		}
		results = applyBatch(ids, func(id string) error {
			return ev.SetLegalHold(id, *actor, *role, *reason)
		})
	case "release":
		results = applyBatch(ids, func(id string) error {
			return ev.ReleaseLegalHold(id, *actor, *role, *notes)
		})
	default:
		fmt.Fprintf(os.Stderr, "unknown batch hold action: %s (use set or release)\n", action)
		os.Exit(1)
	}
	reportBatch(*jsonOut, "hold "+action, results)
}

type batchResult struct {
	ItemID string `json:"item_id"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
}

// applyBatch runs fn for each id, collecting per-item outcomes. Batch operations
// are per-item best-effort (each item is independently logged); a failure on one
// item does not stop the rest, and every outcome is reported.
func applyBatch(ids []string, fn func(string) error) []batchResult {
	results := make([]batchResult, 0, len(ids))
	for _, id := range ids {
		if err := fn(id); err != nil {
			results = append(results, batchResult{ItemID: id, OK: false, Error: err.Error()})
		} else {
			results = append(results, batchResult{ItemID: id, OK: true})
		}
	}
	return results
}

func reportBatch(jsonOut bool, op string, results []batchResult) {
	ok, failed := 0, 0
	for _, r := range results {
		if r.OK {
			ok++
		} else {
			failed++
		}
	}
	if jsonOut {
		apiwire.Print(map[string]any{"operation": op, "total": len(results), "ok": ok, "failed": failed, "results": results})
	} else {
		fmt.Printf("Batch %s: %d ok, %d failed (of %d)\n", op, ok, failed, len(results))
		for _, r := range results {
			if r.OK {
				fmt.Printf("  ✓ %s\n", r.ItemID)
			} else {
				fmt.Printf("  ✗ %s — %s\n", r.ItemID, r.Error)
			}
		}
	}
	if failed > 0 {
		os.Exit(1)
	}
}

// ── verify ─────────────────────────────────────────────────────────────────────

func runVerify() {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
	_ = fs.Parse(os.Args[2:])

	ev, _ := mustOpenStore()
	defer ev.Close()
	res, err := ev.VerifyChain()
	if err != nil {
		failCmd(*jsonOut, apiwire.CodeInternal, fmt.Sprintf("verify: %v", err))
	}
	if *jsonOut {
		apiwire.Print(res)
		if !res.OK {
			os.Exit(1)
		}
		return
	}
	if res.OK {
		fmt.Printf("✓ Chain intact — %d record(s) verified.\n", res.Entries)
		return
	}
	fmt.Printf("✗ Chain BROKEN at record %d", res.BreakAt)
	if res.Seq > 0 {
		fmt.Printf(" (seq %d)", res.Seq)
	}
	fmt.Printf(": %s\n", res.Reason)
	fmt.Printf("  %d record(s) verified before the break.\n", res.Entries)
	os.Exit(1)
}

// ── multi-node (peers) ─────────────────────────────────────────────────────────

func runPeer() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: slate peer <keygen|identity|add|list|remove|transfer|discover|refresh> [flags]")
		os.Exit(1)
	}
	switch os.Args[2] {
	case "keygen":
		runPeerKeygen()
	case "identity":
		runPeerIdentity()
	case "add":
		runPeerAdd()
	case "list":
		runPeerList()
	case "remove":
		runPeerRemove()
	case "transfer":
		runPeerTransfer()
	case "discover":
		runPeerDiscover()
	case "refresh":
		runPeerRefresh()
	default:
		fmt.Fprintf(os.Stderr, "unknown peer subcommand: %s\n", os.Args[2])
		os.Exit(1)
	}
}

func runPeerKeygen() {
	fs := flag.NewFlagSet("peer keygen", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
	_ = fs.Parse(os.Args[3:])
	pub, priv, err := peer.GenerateNodeKey()
	if err != nil {
		failCmd(*jsonOut, apiwire.CodeInternal, fmt.Sprintf("keygen: %v", err))
	}
	// The encryption key is derived from the same secret — no separate key to keep.
	edPriv, _, err := peer.DecodeNodeKey(priv)
	if err != nil {
		failCmd(*jsonOut, apiwire.CodeInternal, fmt.Sprintf("keygen: %v", err))
	}
	_, encPub, err := peer.DeriveEncKey(edPriv)
	if err != nil {
		failCmd(*jsonOut, apiwire.CodeInternal, fmt.Sprintf("derive encryption key: %v", err))
	}
	token := peer.IdentityToken(pub, encPub)
	if *jsonOut {
		apiwire.Print(map[string]string{"public_key": pub, "enc_pubkey": encPub, "identity": token, "private_key": priv})
		return
	}
	fmt.Println("Ed25519 node identity key pair generated (with a derived X25519 encryption key).")
	fmt.Println()
	fmt.Printf("Identity token (share with peers — signing + encryption public keys):\n%s\n\n", token)
	fmt.Printf("Private key (keep secret — set as %s):\n%s\n\n", peer.NodeKeyEnv, priv)
	fmt.Printf("Never store the private key on disk. Export it before serving:\n  export %s=%s\n", peer.NodeKeyEnv, priv)
}

func runPeerIdentity() {
	fs := flag.NewFlagSet("peer identity", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
	_ = fs.Parse(os.Args[3:])
	dir := slateDir()
	cfg := mustLoadConfig(dir)
	edPriv, pub, err := peer.LoadNodeKey()
	if err != nil {
		failCmd(*jsonOut, apiwire.CodeBadRequest, err.Error())
	}
	_, encPub, err := peer.DeriveEncKey(edPriv)
	if err != nil {
		failCmd(*jsonOut, apiwire.CodeInternal, fmt.Sprintf("derive encryption key: %v", err))
	}
	token := peer.IdentityToken(pub, encPub)
	if *jsonOut {
		apiwire.Print(map[string]string{"node_id": cfg.NodeID, "public_key": pub, "enc_pubkey": encPub, "identity": token})
		return
	}
	fmt.Printf("Node ID        : %s\n", cfg.NodeID)
	fmt.Printf("Signing key    : %s\n", pub)
	fmt.Printf("Encryption key : %s\n", encPub)
	fmt.Printf("Identity token : %s\n", token)
	fmt.Println("\nShare the identity token with peers so they can enroll this node:")
	fmt.Printf("  slate peer add --node %s --pubkey %s --addr <this-host:peer-port>\n", cfg.NodeID, token)
}

func runPeerAdd() {
	fs := flag.NewFlagSet("peer add", flag.ExitOnError)
	node := fs.String("node", "", "Peer node ID (required)")
	pubkey := fs.String("pubkey", "", "Peer identity token or Ed25519 signing key hex (required)")
	encPubkey := fs.String("enc-pubkey", "", "Peer X25519 encryption key hex (optional; overrides the one in --pubkey)")
	addr := fs.String("addr", "", "Peer receive address host:port (required for sending)")
	jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
	_ = fs.Parse(os.Args[3:])
	if *node == "" || *pubkey == "" {
		usageErr(*jsonOut, "usage: slate peer add --node ID --pubkey TOKEN --addr HOST:PORT")
	}
	// --pubkey accepts either a combined identity token ("<sig>.<enc>") or a bare
	// signing key (legacy). An explicit --enc-pubkey wins if given.
	sigPub, encPub := peer.SplitIdentityToken(*pubkey)
	if *encPubkey != "" {
		encPub = *encPubkey
	}
	ps := mustOpenPeerStore()
	if err := ps.Add(*node, sigPub, *addr); err != nil {
		failCmd(*jsonOut, apiwire.CodeBadRequest, fmt.Sprintf("add peer: %v", err))
	}
	encStatus := "no (sealed transfers unavailable — re-enroll with an identity token)"
	if encPub != "" {
		if err := ps.SetEncKey(*node, encPub); err != nil {
			failCmd(*jsonOut, apiwire.CodeBadRequest, fmt.Sprintf("add peer encryption key: %v", err))
		}
		encStatus = "yes"
	}
	if *jsonOut {
		apiwire.Print(map[string]string{"node_id": *node, "address": *addr, "encryption": encStatus, "status": "enrolled"})
		return
	}
	fmt.Printf("Peer enrolled: %s (%s)\n", *node, *addr)
	fmt.Printf("  Encryption key enrolled: %s\n", encStatus)
}

func runPeerList() {
	fs := flag.NewFlagSet("peer list", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
	_ = fs.Parse(os.Args[3:])
	ps := mustOpenPeerStore()
	peers := ps.List()
	if *jsonOut {
		apiwire.Print(peers)
		return
	}
	if len(peers) == 0 {
		fmt.Println("No peers enrolled. Add one: slate peer add --node ID --pubkey HEX --addr HOST:PORT")
		return
	}
	fmt.Printf("%-20s  %-22s  %-12s  %-5s  %s\n", "NODE", "ADDRESS", "ADDED", "ENC", "PUBKEY (first 16)")
	fmt.Println(strings.Repeat("─", 86))
	for _, p := range peers {
		enc := "no"
		if p.EncPubKey != "" {
			enc = "yes"
		}
		fmt.Printf("%-20s  %-22s  %-12s  %-5s  %s\n", p.NodeID, p.Address, p.AddedAt, enc, truncate(p.PublicKey, 16))
	}
}

func runPeerRemove() {
	fs := flag.NewFlagSet("peer remove", flag.ExitOnError)
	node := fs.String("node", "", "Peer node ID (required)")
	jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
	_ = fs.Parse(os.Args[3:])
	if *node == "" {
		usageErr(*jsonOut, "usage: slate peer remove --node ID")
	}
	ps := mustOpenPeerStore()
	if err := ps.Remove(*node); err != nil {
		failCmd(*jsonOut, apiwire.CodeNotFound, fmt.Sprintf("remove peer: %v", err))
	}
	if *jsonOut {
		apiwire.Print(map[string]string{"node_id": *node, "status": "removed"})
		return
	}
	fmt.Printf("Peer removed: %s\n", *node)
}

func runPeerTransfer() {
	fs := flag.NewFlagSet("peer transfer", flag.ExitOnError)
	itemID := fs.String("item", "", "Item ID to hand off (required)")
	to := fs.String("to", "", "Destination peer node ID (required)")
	actor := fs.String("actor", osUser(), "Actor name for audit log")
	role := fs.String("role", "", "Actor role for audit log (optional)")
	notes := fs.String("notes", "", "Handoff notes")
	encrypt := fs.Bool("encrypt", false, "Encrypt the bundle end-to-end to the peer's enrolled key (sealed transfer)")
	jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
	_ = fs.Parse(os.Args[3:])
	if *itemID == "" || *to == "" {
		usageErr(*jsonOut, "usage: slate peer transfer --item ID --to NODE [--encrypt] [--notes TEXT]")
	}

	priv, _, err := peer.LoadNodeKey()
	if err != nil {
		failCmd(*jsonOut, apiwire.CodeBadRequest, err.Error())
	}

	dir := slateDir()
	cfg := mustLoadConfig(dir)
	ps := mustOpenPeerStore()
	dest, ok := ps.Lookup(*to)
	if !ok {
		failCmd(*jsonOut, apiwire.CodeNotFound, fmt.Sprintf("peer %q is not enrolled", *to))
	}
	if dest.Address == "" {
		failCmd(*jsonOut, apiwire.CodeBadRequest, fmt.Sprintf("peer %q has no address enrolled", *to))
	}

	ev, _ := mustOpenStore()
	defer ev.Close()
	item, found := ev.GetItem(*itemID)
	if !found {
		failCmd(*jsonOut, apiwire.CodeNotFound, fmt.Sprintf("item not found: %s", *itemID))
	}
	if item.LegalHold {
		failCmd(*jsonOut, apiwire.CodeBadRequest, fmt.Sprintf("item %s is under legal hold — cannot transfer", *itemID))
	}
	events, err := ev.EventsForItem(*itemID)
	if err != nil {
		failCmd(*jsonOut, apiwire.CodeInternal, fmt.Sprintf("read item events: %v", err))
	}

	bundle, err := peer.NewTransferBundle(cfg.NodeID, *to, *item, events, *notes)
	if err != nil {
		failCmd(*jsonOut, apiwire.CodeInternal, fmt.Sprintf("build bundle: %v", err))
	}
	if err := bundle.Sign(priv); err != nil {
		failCmd(*jsonOut, apiwire.CodeInternal, fmt.Sprintf("sign bundle: %v", err))
	}

	// Choose cleartext (default, wire-compatible) or sealed (end-to-end encrypted).
	var body []byte
	url := "http://" + dest.Address + "/api/peer/receive"
	if *encrypt {
		if dest.EncPubKey == "" {
			failCmd(*jsonOut, apiwire.CodeBadRequest,
				fmt.Sprintf("peer %q has no encryption key enrolled — re-enroll it with its identity token (`slate peer identity` on that node)", *to))
		}
		sealed, err := peer.SealTo(bundle, dest.EncPubKey)
		if err != nil {
			failCmd(*jsonOut, apiwire.CodeInternal, fmt.Sprintf("seal bundle: %v", err))
		}
		body, _ = json.Marshal(sealed)
		url = "http://" + dest.Address + "/api/peer/receive-sealed"
	} else {
		body, _ = json.Marshal(bundle)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		failCmd(*jsonOut, apiwire.CodeInternal, fmt.Sprintf("send to peer: %v", err))
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		failCmd(*jsonOut, apiwire.CodeInternal, fmt.Sprintf("peer rejected transfer (%d): %s", resp.StatusCode, strings.TrimSpace(string(respBody))))
	}

	// Peer accepted and verified. Record the outbound handoff on THIS node.
	if err := ev.RecordOutgoingTransfer(*itemID, *actor, *role, *to, bundle.BundleID, *notes); err != nil {
		failCmd(*jsonOut, apiwire.CodeInternal, fmt.Sprintf("record outgoing transfer: %v", err))
	}

	if *jsonOut {
		apiwire.Print(map[string]any{
			"status":    "transferred",
			"item_id":   *itemID,
			"to":        *to,
			"bundle_id": bundle.BundleID,
			"encrypted": *encrypt,
		})
		return
	}
	mode := "signed, cleartext"
	if *encrypt {
		mode = "signed + sealed (end-to-end encrypted)"
	}
	fmt.Printf("Custody transferred: %s → %s\n", *itemID, *to)
	fmt.Printf("  Bundle : %s (%s; verified by peer)\n", bundle.BundleID, mode)
	fmt.Printf("  Events : %d custody record(s) sent\n", len(events))
}

// runPeerDiscover listens for signed presence beacons on the LAN and prints the
// nodes it hears. It is READ-ONLY: discovery never enrolls or changes trust. The
// fingerprint column is for out-of-band verification before running `peer add`.
func runPeerDiscover() {
	fs := flag.NewFlagSet("peer discover", flag.ExitOnError)
	forDur := fs.Duration("for", 6*time.Second, "How long to listen for beacons")
	group := fs.String("group", discovery.DefaultGroup, "Discovery multicast group")
	port := fs.Int("discovery-port", discovery.DefaultPort, "Discovery multicast port")
	jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
	_ = fs.Parse(os.Args[3:])

	groupAddr := fmt.Sprintf("%s:%d", *group, *port)
	if !*jsonOut {
		fmt.Printf("Listening for SLATE peers on %s for %s …\n", groupAddr, *forDur)
	}
	found, err := discovery.Listen(context.Background(), groupAddr, *forDur)
	if err != nil {
		failCmd(*jsonOut, apiwire.CodeInternal, fmt.Sprintf("discover: %v", err))
	}

	// Cross-reference against the enrolled peer store so the operator can see, at
	// a glance, who is new, who is enrolled, and whose address has drifted.
	ps := mustOpenPeerStore()
	type row struct {
		discovery.Result
		Status string `json:"status"` // new | enrolled | address-changed | key-mismatch
	}
	rows := make([]row, 0, len(found))
	for _, r := range found {
		status := "new"
		if p, ok := ps.Lookup(r.NodeID); ok {
			switch {
			case p.PublicKey != r.PubKey:
				status = "key-mismatch"
			case p.Address != r.Addr:
				status = "address-changed"
			default:
				status = "enrolled"
			}
		}
		rows = append(rows, row{Result: r, Status: status})
	}

	if *jsonOut {
		apiwire.Print(rows)
		return
	}
	if len(rows) == 0 {
		fmt.Println("No peers announced. (Nodes must run `slate serve --peer-listen … --announce`.)")
		return
	}
	fmt.Printf("%-20s  %-22s  %-16s  %-19s  %s\n", "NODE", "ADDRESS", "STATUS", "FINGERPRINT", "DEPARTMENT")
	fmt.Println(strings.Repeat("─", 96))
	for _, r := range rows {
		fmt.Printf("%-20s  %-22s  %-16s  %-19s  %s\n", r.NodeID, r.Addr, r.Status, r.Fingerprint, r.Department)
	}
	fmt.Println("\nDiscovery does not grant trust. Verify a fingerprint out of band, then enroll:")
	fmt.Println("  slate peer add --node ID --pubkey HEX --addr HOST:PORT")
	fmt.Println("For nodes already enrolled whose address moved, run: slate peer refresh")
}

// runPeerRefresh updates the addresses of already-enrolled peers from signed
// beacons. This is the only auto-mutating discovery action, and it is safe: a
// peer's address is updated only when a beacon signed by that peer's ENROLLED
// public key is heard. A beacon claiming the peer's node ID under a DIFFERENT key
// is a possible impersonation — it is refused and reported, never applied.
func runPeerRefresh() {
	fs := flag.NewFlagSet("peer refresh", flag.ExitOnError)
	forDur := fs.Duration("for", 6*time.Second, "How long to listen for beacons")
	group := fs.String("group", discovery.DefaultGroup, "Discovery multicast group")
	port := fs.Int("discovery-port", discovery.DefaultPort, "Discovery multicast port")
	dryRun := fs.Bool("dry-run", false, "Show what would change without writing")
	jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
	_ = fs.Parse(os.Args[3:])

	groupAddr := fmt.Sprintf("%s:%d", *group, *port)
	if !*jsonOut {
		fmt.Printf("Listening for enrolled peers on %s for %s …\n", groupAddr, *forDur)
	}
	found, err := discovery.Listen(context.Background(), groupAddr, *forDur)
	if err != nil {
		failCmd(*jsonOut, apiwire.CodeInternal, fmt.Sprintf("refresh: %v", err))
	}
	byNode := make(map[string]discovery.Result, len(found))
	for _, r := range found {
		byNode[r.NodeID] = r
	}

	ps := mustOpenPeerStore()
	type change struct {
		NodeID  string `json:"node_id"`
		From    string `json:"from"`
		To      string `json:"to"`
		Applied bool   `json:"applied"`
		Result  string `json:"result"` // updated | would-update | key-mismatch
	}
	var changes []change
	for _, p := range ps.List() {
		r, ok := byNode[p.NodeID]
		if !ok {
			continue // not heard this round
		}
		if r.PubKey != p.PublicKey {
			changes = append(changes, change{NodeID: p.NodeID, From: p.Address, To: r.Addr, Result: "key-mismatch"})
			continue
		}
		if r.Addr == p.Address {
			continue // already current
		}
		c := change{NodeID: p.NodeID, From: p.Address, To: r.Addr}
		if *dryRun {
			c.Result = "would-update"
		} else if err := ps.SetAddress(p.NodeID, r.Addr); err != nil {
			failCmd(*jsonOut, apiwire.CodeInternal, fmt.Sprintf("update %s: %v", p.NodeID, err))
		} else {
			c.Applied = true
			c.Result = "updated"
		}
		changes = append(changes, c)
	}

	if *jsonOut {
		apiwire.Print(changes)
		return
	}
	if len(changes) == 0 {
		fmt.Println("All enrolled peers heard are already at their current address (nothing to update).")
		return
	}
	for _, c := range changes {
		switch c.Result {
		case "key-mismatch":
			fmt.Printf("⚠ %s: beacon key does NOT match the enrolled key — refused (possible impersonation)\n", c.NodeID)
		case "would-update":
			fmt.Printf("• %s: %s → %s (dry run, not written)\n", c.NodeID, c.From, c.To)
		case "updated":
			fmt.Printf("✓ %s: %s → %s\n", c.NodeID, c.From, c.To)
		}
	}
}

func mustOpenPeerStore() *peer.Store {
	ps, err := peer.Open(filepath.Join(slateDir(), "peers.json"))
	if err != nil {
		fatal("open peer store: %v", err)
	}
	return ps
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func runToken() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: slate token <add|list|revoke> [flags]")
		os.Exit(1)
	}
	dir := slateDir()
	ts, err := tokens.Open(filepath.Join(dir, "tokens.json"))
	if err != nil {
		fatal("open token store: %v", err)
	}

	switch os.Args[2] {
	case "add":
		fs := flag.NewFlagSet("token add", flag.ExitOnError)
		role := fs.String("role", "", "Role: chief, evidence_clerk, tech_admin, officer, auditor (required)")
		name := fs.String("name", "", "Person's name — appears in audit logs (required)")
		jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
		_ = fs.Parse(os.Args[3:])
		if *role == "" || *name == "" {
			usageErr(*jsonOut, "usage: slate token add --role ROLE --name NAME")
		}
		token, err := ts.Add(*role, *name)
		if err != nil {
			failCmd(*jsonOut, apiwire.CodeBadRequest, fmt.Sprintf("add token: %v", err))
		}
		if *jsonOut {
			apiwire.Print(map[string]string{"name": *name, "role": *role, "token": token})
			return
		}
		fmt.Printf("Token added for %s (%s).\n", *name, *role)
		fmt.Printf("\nToken (copy now — cannot be recovered):\n%s\n", token)
		fmt.Println("\nStore this token securely. It grants full API access for this role.")

	case "list":
		fs := flag.NewFlagSet("token list", flag.ExitOnError)
		jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
		_ = fs.Parse(os.Args[3:])
		entries := ts.List()
		if *jsonOut {
			out := make([]map[string]string, 0, len(entries))
			for _, e := range entries {
				out = append(out, map[string]string{
					"name": e.Name, "role": e.Role, "added_at": e.AddedAt,
					"token_prefix": tokenPrefix(e.Token),
				})
			}
			apiwire.Print(out)
			return
		}
		if len(entries) == 0 {
			fmt.Println("No tokens configured. Run: slate token add --role chief --name \"Name\"")
			return
		}
		fmt.Printf("%-18s  %-16s  %-10s  %s\n", "NAME", "ROLE", "ADDED", "TOKEN (first 12)")
		fmt.Println(strings.Repeat("─", 72))
		for _, e := range entries {
			fmt.Printf("%-18s  %-16s  %-10s  %s\n", e.Name, e.Role, e.AddedAt, tokenPrefix(e.Token))
		}

	case "revoke":
		fs := flag.NewFlagSet("token revoke", flag.ExitOnError)
		jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
		_ = fs.Parse(os.Args[3:])
		rest := fs.Args()
		if len(rest) < 1 {
			usageErr(*jsonOut, "usage: slate token revoke TOKEN")
		}
		if err := ts.Revoke(rest[0]); err != nil {
			failCmd(*jsonOut, apiwire.CodeNotFound, fmt.Sprintf("revoke: %v", err))
		}
		if *jsonOut {
			apiwire.Print(map[string]string{"status": "revoked"})
			return
		}
		fmt.Println("Token revoked.")

	default:
		fmt.Fprintf(os.Stderr, "unknown token subcommand: %s\n", os.Args[2])
		os.Exit(1)
	}
}

func runKeygen() {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "Emit machine-readable JSON")
	_ = fs.Parse(os.Args[2:])
	pub, priv, err := slateexport.GenerateKeyPair()
	if err != nil {
		failCmd(*jsonOut, apiwire.CodeInternal, fmt.Sprintf("keygen: %v", err))
	}
	if *jsonOut {
		apiwire.Print(map[string]string{"public_key": pub, "private_key": priv})
		return
	}
	fmt.Println("Ed25519 signing key pair generated.")
	fmt.Println()
	fmt.Printf("Public key  (store in config, safe to share): %s\n\n", pub)
	fmt.Printf("Private key (keep secret — set as SLATE_SIGN_KEY):\n%s\n\n", priv)
	fmt.Println("Never store the private key in config.json or commit it to version control.")
}

func runServe() {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	port := fs.Int("port", 0, "Port (overrides config, default 8890)")
	peerListen := fs.String("peer-listen", "", "Enable LAN peer-transfer listener on host:port (e.g. 0.0.0.0:8891). Off by default.")
	announce := fs.Bool("announce", false, "Broadcast a signed presence beacon so peers can auto-discover this node (requires --peer-listen). Off by default.")
	discoveryGroup := fs.String("discovery-group", discovery.DefaultGroup, "Discovery multicast group (with --announce)")
	discoveryPort := fs.Int("discovery-port", discovery.DefaultPort, "Discovery multicast port (with --announce)")
	requireEncryption := fs.Bool("require-encryption", false, "Accept only end-to-end encrypted (sealed) transfers; refuse cleartext bundles (requires --peer-listen)")
	_ = fs.Parse(os.Args[2:])

	dir := slateDir()
	cfg := mustLoadConfig(dir)
	if *port > 0 {
		cfg.Port = *port
	}
	if cfg.Port == 0 {
		cfg.Port = 8890
	}

	ts, err := tokens.Open(filepath.Join(dir, "tokens.json"))
	if err != nil {
		fatal("open token store: %v", err)
	}
	if ts.Len() == 0 {
		fatal("no access tokens configured.\n" +
			"  Add one first:  slate token add --role chief --name \"Your Name\"\n" +
			"  Then run:       slate serve")
	}

	key := mustDeriveKey()
	ev, err := evidence.Open(filepath.Join(dir, "primary"), key)
	if err != nil {
		fatal("open store: %v", err)
	}

	srv := &server{store: ev, cfg: cfg, dir: dir, key: key, tokenStore: ts}

	// Optional LAN peer-transfer listener. This is the ONLY part of SLATE that
	// binds beyond 127.0.0.1, it is off unless --peer-listen is given, and it
	// authenticates by verifying signed transfer bundles (not tokens).
	if *peerListen != "" {
		ps, err := peer.Open(filepath.Join(dir, "peers.json"))
		if err != nil {
			fatal("open peer store: %v", err)
		}
		srv.peerStore = ps

		// If a node key is available, derive this node's X25519 key so it can open
		// sealed (encrypted) transfers. Absent a key, only cleartext is accepted.
		if edPriv, _, err := peer.LoadNodeKey(); err == nil {
			if encPriv, _, derr := peer.DeriveEncKey(edPriv); derr == nil {
				srv.nodeEncPriv = encPriv
			}
		}

		peerMux := http.NewServeMux()
		if *requireEncryption {
			if srv.nodeEncPriv == nil {
				fatal("--require-encryption needs SLATE_NODE_KEY set so this node can decrypt sealed transfers")
			}
			// Cleartext endpoint refuses everything; only sealed transfers are accepted.
			peerMux.HandleFunc("/api/peer/receive", func(w http.ResponseWriter, r *http.Request) {
				apiwire.WriteErr(w, http.StatusForbidden, apiwire.CodeForbidden,
					"this node requires encrypted transfers — resend with `slate peer transfer --encrypt`")
			})
		} else {
			peerMux.HandleFunc("/api/peer/receive", srv.handlePeerReceive)
		}
		peerMux.HandleFunc("/api/peer/receive-sealed", srv.handlePeerReceiveSealed)
		encStatus := "cleartext or sealed"
		if *requireEncryption {
			encStatus = "sealed only"
		} else if srv.nodeEncPriv == nil {
			encStatus = "cleartext only (set SLATE_NODE_KEY to accept sealed)"
		}
		fmt.Printf("Peer-transfer listener: http://%s  (enrolled peers: %d; accepts: %s)\n", *peerListen, len(ps.List()), encStatus)
		go func() {
			if err := http.ListenAndServe(*peerListen, peerMux); err != nil {
				fatal("peer listener: %v", err)
			}
		}()

		// Optional signed presence beacon for LAN auto-discovery. Opt-in on top of
		// the listener: it advertises identity + port only, never grants trust.
		if *announce {
			priv, _, err := peer.LoadNodeKey()
			if err != nil {
				fatal("--announce requires a node key: %v", err)
			}
			_, portStr, err := net.SplitHostPort(*peerListen)
			if err != nil {
				fatal("--peer-listen must be host:port to announce: %v", err)
			}
			listenPort, err := strconv.Atoi(portStr)
			if err != nil {
				fatal("invalid peer-listen port: %v", err)
			}
			ann := &discovery.Announcement{
				NodeID:     cfg.NodeID,
				Port:       listenPort,
				Department: cfg.Department,
				Time:       time.Now().UTC(),
			}
			if err := ann.Sign(priv); err != nil {
				fatal("sign beacon: %v", err)
			}
			groupAddr := fmt.Sprintf("%s:%d", *discoveryGroup, *discoveryPort)
			fmt.Printf("Discovery beacon: announcing %s on %s every %s\n", cfg.NodeID, groupAddr, discovery.DefaultInterval)
			go func() {
				if err := discovery.Broadcast(context.Background(), groupAddr, ann, discovery.DefaultInterval); err != nil {
					fmt.Fprintf(os.Stderr, "discovery beacon stopped: %v\n", err)
				}
			}()
		}
	} else if *announce {
		fatal("--announce requires --peer-listen (there is nothing to advertise without the listener)")
	} else if *requireEncryption {
		fatal("--require-encryption requires --peer-listen (there is no listener to protect without it)")
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", srv.handleDashboard)
	mux.Handle("/api/whoami", srv.require(roles.PermStatus)(http.HandlerFunc(srv.handleWhoami)))
	mux.Handle("/api/status", srv.require(roles.PermStatus)(http.HandlerFunc(srv.handleStatus)))
	mux.Handle("/api/items", srv.require(roles.PermStatus)(http.HandlerFunc(srv.handleItems)))
	mux.Handle("/api/events", srv.require(roles.PermAuditRead)(http.HandlerFunc(srv.handleEvents)))
	mux.Handle("/api/intake", srv.require(roles.PermIntake)(http.HandlerFunc(srv.handleIntake)))
	mux.Handle("/api/transfer", srv.require(roles.PermTransfer)(http.HandlerFunc(srv.handleTransfer)))
	mux.Handle("/api/hold/set", srv.require(roles.PermHoldSet)(http.HandlerFunc(srv.handleHoldSet)))
	mux.Handle("/api/hold/release", srv.require(roles.PermHoldRelease)(http.HandlerFunc(srv.handleHoldRelease)))
	mux.Handle("/api/export", srv.require(roles.PermExport)(http.HandlerFunc(srv.handleExport)))
	mux.Handle("/api/stream", srv.require(roles.PermStatus)(http.HandlerFunc(srv.handleStream)))

	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Port)
	fmt.Printf("SLATE dashboard: http://%s\n", addr)
	fmt.Printf("Node: %s  Dept: %s  Tokens: %d\n", cfg.NodeID, cfg.Department, ts.Len())
	if err := http.ListenAndServe(addr, mux); err != nil {
		fatal("serve: %v", err)
	}
}

// ── HTTP server ───────────────────────────────────────────────────────────────

type server struct {
	store       *evidence.Store
	cfg         Config
	dir         string
	key         []byte
	tokenStore  *tokens.Store
	peerStore   *peer.Store      // enrolled peers (nil unless the peer listener is enabled)
	nodeEncPriv *ecdh.PrivateKey // this node's X25519 key for opening sealed bundles (nil if SLATE_NODE_KEY unset)

	mu   sync.Mutex             // guards subs
	subs map[chan struct{}]bool // active SSE subscribers
}

// publish notifies all connected SSE subscribers that state changed. It is a
// best-effort, non-blocking send — a slow client simply misses this tick and
// picks up the next one (or reconciles on its poll fallback).
func (s *server) publish() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (s *server) subscribe() chan struct{} {
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	if s.subs == nil {
		s.subs = make(map[chan struct{}]bool)
	}
	s.subs[ch] = true
	s.mu.Unlock()
	return ch
}

func (s *server) unsubscribe(ch chan struct{}) {
	s.mu.Lock()
	delete(s.subs, ch)
	s.mu.Unlock()
}

// handleStream is a Server-Sent Events endpoint. It emits a "change" event
// whenever a mutating request publishes, plus a periodic "ping" so proxies and
// clients can detect a dead connection. The dashboard falls back to polling if
// the stream drops.
func (s *server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		apiwire.WriteErr(w, http.StatusInternalServerError, apiwire.CodeInternal, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := s.subscribe()
	defer s.unsubscribe(ch)

	fmt.Fprintf(w, "event: ready\ndata: {\"schema\":%q}\n\n", apiwire.Schema)
	flusher.Flush()

	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ch:
			fmt.Fprint(w, "event: change\ndata: {}\n\n")
			flusher.Flush()
		case <-ping.C:
			fmt.Fprint(w, "event: ping\ndata: {}\n\n")
			flusher.Flush()
		}
	}
}

// require returns middleware that verifies the Bearer token has the named permission.
// On success it stores the token entry in the request context for handlers to read.
func (s *server) require(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			var tok string
			switch {
			case strings.HasPrefix(auth, "Bearer "):
				tok = strings.TrimPrefix(auth, "Bearer ")
			case r.URL.Query().Get("token") != "":
				// Query-param fallback exists only so the browser EventSource
				// (which cannot set headers) can authenticate over the
				// localhost-only stream. Safe here because serve binds 127.0.0.1.
				tok = r.URL.Query().Get("token")
			default:
				w.Header().Set("WWW-Authenticate", `Bearer realm="SLATE"`)
				apiwire.WriteErr(w, http.StatusUnauthorized, apiwire.CodeUnauthorized, "missing or malformed Bearer token")
				return
			}
			// Re-read the token store on each request so tokens can be added or
			// revoked without restarting the server.
			_ = s.tokenStore.Reload()
			entry, ok := s.tokenStore.Lookup(tok)
			if !ok {
				apiwire.WriteErr(w, http.StatusUnauthorized, apiwire.CodeUnauthorized, "invalid token")
				return
			}
			if !roles.Can(roles.Role(entry.Role), perm) {
				apiwire.WriteErr(w, http.StatusForbidden, apiwire.CodeForbidden,
					fmt.Sprintf("role %q does not have permission %q", entry.Role, perm))
				return
			}
			ctx := context.WithValue(r.Context(), ctxTokenEntry, entry)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func entryFrom(r *http.Request) (tokens.Entry, bool) {
	e, ok := r.Context().Value(ctxTokenEntry).(tokens.Entry)
	return e, ok
}

func actorFrom(r *http.Request) string {
	if e, ok := entryFrom(r); ok && e.Name != "" {
		return e.Name
	}
	return "unknown"
}

func roleFrom(r *http.Request) string {
	if e, ok := entryFrom(r); ok {
		return e.Role
	}
	return ""
}

func (s *server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(dashboardHTML)
}

func (s *server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	if !requireGet(w, r) {
		return
	}
	e, _ := entryFrom(r)
	role := roles.Role(e.Role)
	perms := map[string]bool{
		roles.PermIntake:      roles.Can(role, roles.PermIntake),
		roles.PermTransfer:    roles.Can(role, roles.PermTransfer),
		roles.PermHoldSet:     roles.Can(role, roles.PermHoldSet),
		roles.PermHoldRelease: roles.Can(role, roles.PermHoldRelease),
		roles.PermExport:      roles.Can(role, roles.PermExport),
		roles.PermDestroy:     roles.Can(role, roles.PermDestroy),
		roles.PermAuditRead:   roles.Can(role, roles.PermAuditRead),
		roles.PermNodeAdmin:   roles.Can(role, roles.PermNodeAdmin),
		roles.PermStatus:      roles.Can(role, roles.PermStatus),
	}
	apiwire.WriteOK(w, map[string]any{
		"role":        e.Role,
		"name":        e.Name,
		"permissions": perms,
	})
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !requireGet(w, r) {
		return
	}
	items := s.store.GetItems("")
	holdCount := 0
	for _, it := range items {
		if it.LegalHold {
			holdCount++
		}
	}
	events, _ := s.store.GetAllEvents()
	resp := map[string]any{
		"node_id":     s.cfg.NodeID,
		"department":  s.cfg.Department,
		"version":     version,
		"item_count":  len(items),
		"hold_count":  holdCount,
		"log_entries": len(events),
	}
	if len(events) > 0 {
		e := events[len(events)-1]
		resp["last_event"] = e.Event
		resp["last_event_at"] = e.Timestamp
	}
	apiwire.WriteOK(w, resp)
}

func (s *server) handleItems(w http.ResponseWriter, r *http.Request) {
	if !requireGet(w, r) {
		return
	}
	f, err := query.FilterFromFunc(r.URL.Query().Get)
	if err != nil {
		apiwire.WriteErr(w, http.StatusBadRequest, apiwire.CodeBadRequest, "bad filter: "+err.Error())
		return
	}
	all := s.store.GetItems("")
	items := make([]*evidence.Item, 0, len(all))
	for _, it := range all {
		if f.MatchItem(it) {
			items = append(items, it)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	apiwire.WriteOK(w, items)
}

func (s *server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !requireGet(w, r) {
		return
	}
	events, err := s.store.GetAllEvents()
	if err != nil {
		apiwire.WriteErr(w, http.StatusInternalServerError, apiwire.CodeInternal, "read events: "+err.Error())
		return
	}
	f, err := query.FilterFromFunc(r.URL.Query().Get)
	if err != nil {
		apiwire.WriteErr(w, http.StatusBadRequest, apiwire.CodeBadRequest, "bad filter: "+err.Error())
		return
	}
	// Legacy alias: ?date=YYYY-MM-DD narrows to a single day.
	if d := r.URL.Query().Get("date"); d != "" && f.DateFrom.IsZero() && f.DateTo.IsZero() {
		f.DateFrom, _ = query.ParseDate(d)
		f.DateTo, _ = query.EndOfDay(d)
	}
	apiwire.WriteOK(w, f.FilterEntries(events))
}

func (s *server) handleIntake(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req struct {
		CaseNumber  string `json:"case_number"`
		Description string `json:"description"`
		Category    string `json:"category"`
		Node        string `json:"node"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if req.CaseNumber == "" || req.Description == "" {
		apiwire.WriteErr(w, http.StatusBadRequest, apiwire.CodeBadRequest, "case_number and description are required")
		return
	}
	if req.Category == "" {
		req.Category = "other"
	}
	item := &evidence.Item{
		CaseNumber:  req.CaseNumber,
		Description: req.Description,
		Category:    req.Category,
		CurrentNode: req.Node,
	}
	if err := s.store.RecordIntake(item, actorFrom(r), roleFrom(r)); err != nil {
		apiwire.WriteErr(w, http.StatusInternalServerError, apiwire.CodeInternal, err.Error())
		return
	}
	s.publish()
	apiwire.WriteOK(w, item)
}

func (s *server) handleTransfer(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req struct {
		ItemID   string `json:"item_id"`
		FromNode string `json:"from_node"`
		ToNode   string `json:"to_node"`
		Notes    string `json:"notes"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if req.ItemID == "" || req.ToNode == "" {
		apiwire.WriteErr(w, http.StatusBadRequest, apiwire.CodeBadRequest, "item_id and to_node are required")
		return
	}
	if err := s.store.RecordTransfer(req.ItemID, actorFrom(r), roleFrom(r), req.FromNode, req.ToNode, req.Notes); err != nil {
		apiwire.WriteErr(w, http.StatusBadRequest, apiwire.CodeBadRequest, err.Error())
		return
	}
	s.publish()
	apiwire.WriteOK(w, map[string]string{"status": "ok", "item_id": req.ItemID})
}

func (s *server) handleHoldSet(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req struct {
		ItemID string `json:"item_id"`
		Reason string `json:"reason"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if req.ItemID == "" || req.Reason == "" {
		apiwire.WriteErr(w, http.StatusBadRequest, apiwire.CodeBadRequest, "item_id and reason are required")
		return
	}
	if err := s.store.SetLegalHold(req.ItemID, actorFrom(r), roleFrom(r), req.Reason); err != nil {
		apiwire.WriteErr(w, http.StatusBadRequest, apiwire.CodeBadRequest, err.Error())
		return
	}
	s.publish()
	apiwire.WriteOK(w, map[string]string{"status": "ok", "item_id": req.ItemID})
}

func (s *server) handleHoldRelease(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req struct {
		ItemID string `json:"item_id"`
		Notes  string `json:"notes"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if req.ItemID == "" {
		apiwire.WriteErr(w, http.StatusBadRequest, apiwire.CodeBadRequest, "item_id is required")
		return
	}
	if err := s.store.ReleaseLegalHold(req.ItemID, actorFrom(r), roleFrom(r), req.Notes); err != nil {
		apiwire.WriteErr(w, http.StatusBadRequest, apiwire.CodeBadRequest, err.Error())
		return
	}
	s.publish()
	apiwire.WriteOK(w, map[string]string{"status": "ok", "item_id": req.ItemID})
}

func (s *server) handleExport(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var req struct {
		CaseNumber string `json:"case_number"`
		Sign       bool   `json:"sign"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if req.CaseNumber == "" {
		apiwire.WriteErr(w, http.StatusBadRequest, apiwire.CodeBadRequest, "case_number is required")
		return
	}

	entries, err := s.store.GetAllEvents()
	if err != nil {
		apiwire.WriteErr(w, http.StatusInternalServerError, apiwire.CodeInternal, "read events: "+err.Error())
		return
	}
	bundle, err := slateexport.Generate(entries, req.CaseNumber, s.cfg.Department, s.cfg.NodeID)
	if err != nil {
		apiwire.WriteErr(w, http.StatusInternalServerError, apiwire.CodeInternal, "generate: "+err.Error())
		return
	}
	if req.Sign {
		privKey := os.Getenv("SLATE_SIGN_KEY")
		if privKey == "" {
			apiwire.WriteErr(w, http.StatusBadRequest, apiwire.CodeBadRequest, "signing requires SLATE_SIGN_KEY env var")
			return
		}
		if err := slateexport.Sign(bundle, privKey); err != nil {
			apiwire.WriteErr(w, http.StatusInternalServerError, apiwire.CodeInternal, "sign: "+err.Error())
			return
		}
	}

	outPath := filepath.Join(s.dir, "exports", bundle.BundleID+".ndjson")
	if err := slateexport.WriteNDJSON(bundle, outPath); err != nil {
		apiwire.WriteErr(w, http.StatusInternalServerError, apiwire.CodeInternal, "write: "+err.Error())
		return
	}
	actor, role := actorFrom(r), roleFrom(r)
	for _, item := range s.store.GetItems(req.CaseNumber) {
		_ = s.store.RecordExport(item.ID, actor, role, bundle.BundleID)
	}
	s.publish()
	apiwire.WriteOK(w, map[string]any{
		"bundle_id":    bundle.BundleID,
		"case_number":  bundle.CaseNumber,
		"entry_count":  bundle.EntryCount,
		"sha256_chain": bundle.SHA256Chain,
		"signed":       bundle.Signature != "",
		"path":         outPath,
	})
}

// handlePeerReceive accepts a signed custody transfer bundle from a peer node.
// It is served ONLY on the explicit LAN listener and authenticates by verifying
// the bundle's signature against the ENROLLED public key for the claimed sender.
// Every outcome — accept or reject — is written to the audit log.
func (s *server) handlePeerReceive(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	var b peer.TransferBundle
	if !decodeBody(w, r, &b) {
		return
	}
	s.acceptTransferBundle(w, &b, false)
}

// handlePeerReceiveSealed accepts an end-to-end encrypted transfer bundle. The
// node decrypts it with its own X25519 key (derived from SLATE_NODE_KEY), then
// runs the identical enrolled-sender signature check as the cleartext path — so
// encryption adds confidentiality without changing the authentication model.
func (s *server) handlePeerReceiveSealed(w http.ResponseWriter, r *http.Request) {
	if !requirePost(w, r) {
		return
	}
	if s.nodeEncPriv == nil {
		apiwire.WriteErr(w, http.StatusServiceUnavailable, apiwire.CodeInternal,
			"this node cannot accept sealed transfers: SLATE_NODE_KEY is not set")
		return
	}
	var sealed peer.SealedBundle
	if !decodeBody(w, r, &sealed) {
		return
	}
	b, err := sealed.Open(s.nodeEncPriv)
	if err != nil {
		// The sender is unknown until decryption succeeds, so this is logged
		// without a node attribution — a failed decrypt reveals nothing else.
		_ = s.store.AppendSystem("WARN", "slate/peer_reject",
			fmt.Sprintf("rejected sealed transfer: %v", err))
		apiwire.WriteErr(w, http.StatusBadRequest, apiwire.CodeBadRequest, "sealed bundle could not be opened: "+err.Error())
		return
	}
	s.acceptTransferBundle(w, b, true)
}

// acceptTransferBundle runs the shared enrolled-sender verification and custody
// acceptance used by both the cleartext and sealed receive paths.
func (s *server) acceptTransferBundle(w http.ResponseWriter, b *peer.TransferBundle, sealed bool) {
	// Re-read peers.json so enrollment/revocation applies without a restart.
	_ = s.peerStore.Reload()

	// The sender must be enrolled. An unknown node is rejected and logged.
	p, ok := s.peerStore.Lookup(b.FromNode)
	if !ok {
		_ = s.store.AppendSystem("WARN", "slate/peer_reject",
			fmt.Sprintf("rejected transfer bundle %s from unenrolled node %q", b.BundleID, b.FromNode))
		apiwire.WriteErr(w, http.StatusForbidden, apiwire.CodeForbidden, "sender node is not enrolled")
		return
	}

	// Verify the signature against the ENROLLED key — never the bundle's own claim.
	if err := b.Verify(p.PublicKey); err != nil {
		_ = s.store.AppendSystem("WARN", "slate/peer_reject",
			fmt.Sprintf("rejected transfer bundle %s from %q: %v", b.BundleID, b.FromNode, err))
		apiwire.WriteErr(w, http.StatusBadRequest, apiwire.CodeBadRequest, "bundle verification failed: "+err.Error())
		return
	}

	item := b.Item
	if err := s.store.AcceptIncomingTransfer(&item, "peer:"+b.FromNode, "", b.FromNode, s.cfg.NodeID, b.BundleID); err != nil {
		_ = s.store.AppendSystem("WARN", "slate/peer_reject",
			fmt.Sprintf("could not accept bundle %s from %q: %v", b.BundleID, b.FromNode, err))
		apiwire.WriteErr(w, http.StatusConflict, apiwire.CodeConflict, err.Error())
		return
	}
	s.publish()
	apiwire.WriteOK(w, map[string]any{
		"status":    "accepted",
		"bundle_id": b.BundleID,
		"item_id":   item.ID,
		"node":      s.cfg.NodeID,
		"encrypted": sealed,
	})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func mustOpenStore() (*evidence.Store, []byte) {
	dir := slateDir()
	mustLoadConfig(dir) // verifies initialized
	key := mustDeriveKey()
	ev, err := evidence.Open(filepath.Join(dir, "primary"), key)
	if err != nil {
		fatal("open store: %v", err)
	}
	return ev, key
}

func mustDeriveKey() []byte {
	key, err := deriveSLATEKey(machid.Get())
	if err != nil {
		fatal("derive key: %v", err)
	}
	return key
}

func mustLoadConfig(dir string) Config {
	cfg, err := loadConfig(dir)
	if err != nil {
		fatal("not initialized — run: slate init")
	}
	return cfg
}

func slateDir() string {
	if d := os.Getenv("SLATE_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".slate")
}

// deriveSLATEKey derives the AES-256 log key from the machine ID using HKDF-SHA256
// with SLATE-specific salt and info labels, distinct from the general witness key.
func deriveSLATEKey(machineID string) ([]byte, error) {
	r := hkdf.New(sha256.New, []byte(machineID),
		[]byte("slate-kdf-salt-2026"),
		[]byte("slate-aes256-gcm-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

func installSoul(dst string) error {
	if _, err := os.Stat(dst); err == nil {
		return nil // already present
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return err
	}
	exe, _ := os.Executable()
	candidates := []string{
		filepath.Join(filepath.Dir(exe), "../../payload/default-soul.toml"),
		"payload/default-soul.toml",
	}
	for _, src := range candidates {
		data, err := os.ReadFile(src)
		if err != nil {
			continue
		}
		return os.WriteFile(dst, data, 0400)
	}
	return fmt.Errorf("default soul file not found — clone the repo and run init from it")
}

func loadConfig(dir string) (Config, error) {
	var cfg Config
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return cfg, err
	}
	return cfg, json.Unmarshal(data, &cfg)
}

func saveConfig(dir string, cfg Config) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "config.json"), data, 0600)
}

// requireGet enforces GET and writes an envelope error otherwise.
func requireGet(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		apiwire.WriteErr(w, http.StatusMethodNotAllowed, apiwire.CodeBadRequest, "method not allowed")
		return false
	}
	return true
}

// requirePost enforces POST and writes an envelope error otherwise.
func requirePost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		apiwire.WriteErr(w, http.StatusMethodNotAllowed, apiwire.CodeBadRequest, "method not allowed")
		return false
	}
	return true
}

// decodeBody decodes a JSON request body, writing an envelope error on failure.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		apiwire.WriteErr(w, http.StatusBadRequest, apiwire.CodeBadRequest, "bad request: "+err.Error())
		return false
	}
	return true
}

// usageErr prints a usage message (as an envelope error under --json) and exits 1.
func usageErr(jsonOut bool, msg string) {
	if jsonOut {
		apiwire.PrintErr(apiwire.CodeBadRequest, msg)
	} else {
		fmt.Fprintln(os.Stderr, msg)
	}
	os.Exit(1)
}

// failCmd reports a command failure (as an envelope error under --json) and exits 1.
func failCmd(jsonOut bool, code, msg string) {
	if jsonOut {
		apiwire.PrintErr(code, msg)
		os.Exit(1)
	}
	fatal("%s", msg)
}

// tokenPrefix masks a token to its first 12 characters for display.
func tokenPrefix(tok string) string {
	if len(tok) > 12 {
		return tok[:12] + "…"
	}
	return tok
}

func osUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "unknown"
}

func info(format string, args ...interface{}) {
	fmt.Printf("[slate] "+format+"\n", args...)
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[slate] FATAL: "+format+"\n", args...)
	os.Exit(1)
}

func usage() {
	fmt.Fprintf(os.Stderr, `slate %s — Secure Log Audit for Trace Evidence

Commands:
  init         [--department NAME] [--node ID]    Initialize SLATE data store
  status                                          Show system status
  intake       --case C --desc D                  Record evidence intake
  transfer     --item ID --from N --to N          Transfer custody (same node)
  hold set     --item ID --reason TEXT            Set legal hold
  hold release --item ID                          Release legal hold
  export       --case C [--sign]                  Generate court export bundle
  audit query  [filters]                          Query the audit log
  import       --file PATH [--dry-run]            Bulk intake from CSV/JSON (atomic)
  batch        transfer|hold [selectors]          Multi-item operations
  verify                                          Check audit-log hash chain integrity
  peer         keygen|identity|add|list|remove|transfer   Multi-node LAN custody
  token add    --role ROLE --name NAME            Add access token
  token list                                      List tokens
  token revoke TOKEN                              Revoke token
  keygen                                          Generate Ed25519 export signing key pair
  serve        [--port PORT] [--peer-listen H:P]  Start dashboard (+ optional peer listener)
  version                                         Show version

Every command accepts --json for stable, schema-versioned output (schema %q).

Roles: chief, evidence_clerk, tech_admin, officer, auditor

Environment:
  SLATE_DIR        Override data directory (default: ~/.slate)
  SLATE_SIGN_KEY   Ed25519 private key hex for signing exports
  SLATE_NODE_KEY   Ed25519 private key hex for node identity (peer transfers)

`, version, apiwire.Schema)
}
