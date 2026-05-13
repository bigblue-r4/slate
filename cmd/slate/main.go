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
//	slate serve      [--port PORT]
//	slate version
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "embed"

	"golang.org/x/crypto/hkdf"

	"github.com/bigblue-r4/slate/internal/evidence"
	slateexport "github.com/bigblue-r4/slate/internal/export"
	"github.com/bigblue-r4/slate/internal/machid"
	"github.com/bigblue-r4/slate/internal/roles"
	"github.com/bigblue-r4/slate/internal/soul"
	"github.com/bigblue-r4/slate/internal/tokens"
)

//go:embed static/index.html
var dashboardHTML []byte

const version = "1.0.0"

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
	case "token":
		runToken()
	case "keygen":
		runKeygen()
	case "serve":
		runServe()
	case "version", "--version", "-v":
		fmt.Printf("slate %s — Secure Log Audit for Trace Evidence\n", version)
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
	node := fs.String("node", "", "Current node/location")
	_ = fs.Parse(os.Args[2:])

	if *caseNum == "" || *desc == "" {
		fmt.Fprintln(os.Stderr, "usage: slate intake --case CASE --desc DESC [--cat CATEGORY] [--node NODE] [--actor NAME]")
		os.Exit(1)
	}

	ev, _ := mustOpenStore()
	defer ev.Close()

	item := &evidence.Item{
		CaseNumber:  *caseNum,
		Description: *desc,
		Category:    *cat,
		CurrentNode: *node,
	}
	if err := ev.RecordIntake(item, *actor); err != nil {
		fatal("intake: %v", err)
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
	notes := fs.String("notes", "", "Transfer notes")
	_ = fs.Parse(os.Args[2:])

	if *itemID == "" || *from == "" || *to == "" {
		fmt.Fprintln(os.Stderr, "usage: slate transfer --item ID --from NODE --to NODE [--actor NAME] [--notes TEXT]")
		os.Exit(1)
	}

	ev, _ := mustOpenStore()
	defer ev.Close()

	if err := ev.RecordTransfer(*itemID, *actor, *from, *to, *notes); err != nil {
		fatal("transfer: %v", err)
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
		_ = fs.Parse(os.Args[3:])
		if *itemID == "" || *reason == "" {
			fmt.Fprintln(os.Stderr, "usage: slate hold set --item ID --reason TEXT [--actor NAME]")
			os.Exit(1)
		}
		ev, _ := mustOpenStore()
		defer ev.Close()
		if err := ev.SetLegalHold(*itemID, *actor, *reason); err != nil {
			fatal("hold set: %v", err)
		}
		fmt.Printf("Legal hold set: %s\n", *itemID)

	case "release":
		fs := flag.NewFlagSet("hold release", flag.ExitOnError)
		itemID := fs.String("item", "", "Item ID (required)")
		actor := fs.String("actor", osUser(), "Actor name for audit log")
		notes := fs.String("notes", "", "Release notes")
		_ = fs.Parse(os.Args[3:])
		if *itemID == "" {
			fmt.Fprintln(os.Stderr, "usage: slate hold release --item ID [--actor NAME] [--notes TEXT]")
			os.Exit(1)
		}
		ev, _ := mustOpenStore()
		defer ev.Close()
		if err := ev.ReleaseLegalHold(*itemID, *actor, *notes); err != nil {
			fatal("hold release: %v", err)
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
	sign := fs.Bool("sign", false, "Sign with SLATE_SIGN_KEY env var")
	_ = fs.Parse(os.Args[2:])

	if *caseNum == "" {
		fmt.Fprintln(os.Stderr, "usage: slate export --case CASE [--sign] [--actor NAME]")
		os.Exit(1)
	}

	dir := slateDir()
	cfg := mustLoadConfig(dir)
	ev, _ := mustOpenStore()
	defer ev.Close()

	entries, err := ev.GetAllEvents()
	if err != nil {
		fatal("read events: %v", err)
	}
	bundle, err := slateexport.Generate(entries, *caseNum, cfg.Department, cfg.NodeID)
	if err != nil {
		fatal("generate bundle: %v", err)
	}
	if *sign {
		privKey := os.Getenv("SLATE_SIGN_KEY")
		if privKey == "" {
			fatal("--sign requires SLATE_SIGN_KEY env var (private key hex)")
		}
		if err := slateexport.Sign(bundle, privKey); err != nil {
			fatal("sign: %v", err)
		}
	}

	outPath := filepath.Join(dir, "exports", bundle.BundleID+".ndjson")
	if err := slateexport.WriteNDJSON(bundle, outPath); err != nil {
		fatal("write bundle: %v", err)
	}
	for _, item := range ev.GetItems(*caseNum) {
		_ = ev.RecordExport(item.ID, *actor, bundle.BundleID)
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
		_ = fs.Parse(os.Args[3:])
		if *role == "" || *name == "" {
			fmt.Fprintln(os.Stderr, "usage: slate token add --role ROLE --name NAME")
			os.Exit(1)
		}
		token, err := ts.Add(*role, *name)
		if err != nil {
			fatal("add token: %v", err)
		}
		fmt.Printf("Token added for %s (%s).\n", *name, *role)
		fmt.Printf("\nToken (copy now — cannot be recovered):\n%s\n", token)
		fmt.Println("\nStore this token securely. It grants full API access for this role.")

	case "list":
		entries := ts.List()
		if len(entries) == 0 {
			fmt.Println("No tokens configured. Run: slate token add --role chief --name \"Name\"")
			return
		}
		fmt.Printf("%-18s  %-16s  %-10s  %s\n", "NAME", "ROLE", "ADDED", "TOKEN (first 12)")
		fmt.Println(strings.Repeat("─", 72))
		for _, e := range entries {
			masked := e.Token
			if len(masked) > 12 {
				masked = masked[:12] + "…"
			}
			fmt.Printf("%-18s  %-16s  %-10s  %s\n", e.Name, e.Role, e.AddedAt, masked)
		}

	case "revoke":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: slate token revoke TOKEN")
			os.Exit(1)
		}
		if err := ts.Revoke(os.Args[3]); err != nil {
			fatal("revoke: %v", err)
		}
		fmt.Println("Token revoked.")

	default:
		fmt.Fprintf(os.Stderr, "unknown token subcommand: %s\n", os.Args[2])
		os.Exit(1)
	}
}

func runKeygen() {
	pub, priv, err := slateexport.GenerateKeyPair()
	if err != nil {
		fatal("keygen: %v", err)
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

	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Port)
	fmt.Printf("SLATE dashboard: http://%s\n", addr)
	fmt.Printf("Node: %s  Dept: %s  Tokens: %d\n", cfg.NodeID, cfg.Department, ts.Len())
	if err := http.ListenAndServe(addr, mux); err != nil {
		fatal("serve: %v", err)
	}
}

// ── HTTP server ───────────────────────────────────────────────────────────────

type server struct {
	store      *evidence.Store
	cfg        Config
	dir        string
	key        []byte
	tokenStore *tokens.Store
}

// require returns middleware that verifies the Bearer token has the named permission.
// On success it stores the token entry in the request context for handlers to read.
func (s *server) require(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				w.Header().Set("WWW-Authenticate", `Bearer realm="SLATE"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			tok := strings.TrimPrefix(auth, "Bearer ")
			// Re-read the token store on each request so tokens can be added or
			// revoked without restarting the server.
			_ = s.tokenStore.Reload()
			entry, ok := s.tokenStore.Lookup(tok)
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if !roles.Can(roles.Role(entry.Role), perm) {
				http.Error(w,
					fmt.Sprintf("forbidden: role %q does not have permission %q", entry.Role, perm),
					http.StatusForbidden)
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

func (s *server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(dashboardHTML)
}

func (s *server) handleWhoami(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
	writeJSON(w, map[string]interface{}{
		"role":        e.Role,
		"name":        e.Name,
		"permissions": perms,
	})
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
	resp := map[string]interface{}{
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
	writeJSON(w, resp)
}

func (s *server) handleItems(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	items := s.store.GetItems(r.URL.Query().Get("case"))
	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	writeJSON(w, items)
}

func (s *server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	events, err := s.store.GetAllEvents()
	if err != nil {
		http.Error(w, "read events: "+err.Error(), http.StatusInternalServerError)
		return
	}
	caseFilter := r.URL.Query().Get("case")
	dateFilter := r.URL.Query().Get("date") // YYYY-MM-DD prefix match
	if caseFilter == "" && dateFilter == "" {
		writeJSON(w, events)
		return
	}
	var out []interface{}
	for _, e := range events {
		if dateFilter != "" && !strings.HasPrefix(e.Timestamp.UTC().Format(time.RFC3339), dateFilter) {
			continue
		}
		if caseFilter != "" && e.Data != nil {
			var d struct {
				CaseNumber string `json:"case_number"`
			}
			if err := json.Unmarshal(e.Data, &d); err != nil || d.CaseNumber != caseFilter {
				continue
			}
		}
		out = append(out, e)
	}
	writeJSON(w, out)
}

func (s *server) handleIntake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		CaseNumber  string `json:"case_number"`
		Description string `json:"description"`
		Category    string `json:"category"`
		Node        string `json:"node"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.CaseNumber == "" || req.Description == "" {
		http.Error(w, "case_number and description are required", http.StatusBadRequest)
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
	if err := s.store.RecordIntake(item, actorFrom(r)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, item)
}

func (s *server) handleTransfer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ItemID   string `json:"item_id"`
		FromNode string `json:"from_node"`
		ToNode   string `json:"to_node"`
		Notes    string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.ItemID == "" || req.ToNode == "" {
		http.Error(w, "item_id and to_node are required", http.StatusBadRequest)
		return
	}
	if err := s.store.RecordTransfer(req.ItemID, actorFrom(r), req.FromNode, req.ToNode, req.Notes); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"status": "ok", "item_id": req.ItemID})
}

func (s *server) handleHoldSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ItemID string `json:"item_id"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.ItemID == "" || req.Reason == "" {
		http.Error(w, "item_id and reason are required", http.StatusBadRequest)
		return
	}
	if err := s.store.SetLegalHold(req.ItemID, actorFrom(r), req.Reason); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"status": "ok", "item_id": req.ItemID})
}

func (s *server) handleHoldRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ItemID string `json:"item_id"`
		Notes  string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.ItemID == "" {
		http.Error(w, "item_id is required", http.StatusBadRequest)
		return
	}
	if err := s.store.ReleaseLegalHold(req.ItemID, actorFrom(r), req.Notes); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"status": "ok", "item_id": req.ItemID})
}

func (s *server) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		CaseNumber string `json:"case_number"`
		Sign       bool   `json:"sign"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.CaseNumber == "" {
		http.Error(w, "case_number is required", http.StatusBadRequest)
		return
	}

	entries, err := s.store.GetAllEvents()
	if err != nil {
		http.Error(w, "read events: "+err.Error(), http.StatusInternalServerError)
		return
	}
	bundle, err := slateexport.Generate(entries, req.CaseNumber, s.cfg.Department, s.cfg.NodeID)
	if err != nil {
		http.Error(w, "generate: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if req.Sign {
		privKey := os.Getenv("SLATE_SIGN_KEY")
		if privKey == "" {
			http.Error(w, "signing requires SLATE_SIGN_KEY env var", http.StatusBadRequest)
			return
		}
		if err := slateexport.Sign(bundle, privKey); err != nil {
			http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	outPath := filepath.Join(s.dir, "exports", bundle.BundleID+".ndjson")
	if err := slateexport.WriteNDJSON(bundle, outPath); err != nil {
		http.Error(w, "write: "+err.Error(), http.StatusInternalServerError)
		return
	}
	actor := actorFrom(r)
	for _, item := range s.store.GetItems(req.CaseNumber) {
		_ = s.store.RecordExport(item.ID, actor, bundle.BundleID)
	}
	writeJSON(w, map[string]interface{}{
		"bundle_id":    bundle.BundleID,
		"case_number":  bundle.CaseNumber,
		"entry_count":  bundle.EntryCount,
		"sha256_chain": bundle.SHA256Chain,
		"signed":       bundle.Signature != "",
		"path":         outPath,
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

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
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
  init        [--department NAME] [--node ID]    Initialize SLATE data store
  status                                          Show system status
  intake      --case C --desc D                  Record evidence intake
  transfer    --item ID --from N --to N           Transfer custody
  hold set    --item ID --reason TEXT             Set legal hold
  hold release --item ID                          Release legal hold
  export      --case C [--sign]                   Generate court export bundle
  token add   --role ROLE --name NAME             Add access token
  token list                                      List tokens
  token revoke TOKEN                              Revoke token
  keygen                                          Generate Ed25519 signing key pair
  serve       [--port PORT]                       Start dashboard server
  version                                         Show version

Roles: chief, evidence_clerk, tech_admin, officer, auditor

Environment:
  SLATE_DIR        Override data directory (default: ~/.slate)
  SLATE_SIGN_KEY   Ed25519 private key hex for signing exports

`, version)
}
