// Package apiwire defines the single stable JSON contract shared by the SLATE
// CLI (--json output) and the REST API served by `slate serve`. The dashboard
// consumes exactly this envelope — there is no second data path.
//
// Envelope shape (schema "slate.v1"):
//
//	{ "schema": "slate.v1", "ok": true,  "data": <payload> }
//	{ "schema": "slate.v1", "ok": false, "error": { "code": "...", "message": "..." } }
//
// The envelope is intentionally minimal and additive: new optional fields may be
// added to a payload without a schema bump; a schema bump (slate.v2) is reserved
// for a breaking change to an existing field.
package apiwire

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
)

// Schema is the current envelope schema version.
const Schema = "slate.v1"

// Envelope is the outer wrapper for every CLI --json emission and REST response.
type Envelope struct {
	Schema string    `json:"schema"`
	OK     bool      `json:"ok"`
	Data   any       `json:"data,omitempty"`
	Error  *ErrorObj `json:"error,omitempty"`
}

// ErrorObj is a machine-readable error payload.
type ErrorObj struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Common error codes. Keep these stable — clients may switch on them.
const (
	CodeBadRequest   = "bad_request"
	CodeUnauthorized = "unauthorized"
	CodeForbidden    = "forbidden"
	CodeNotFound     = "not_found"
	CodeConflict     = "conflict"
	CodeInternal     = "internal"
)

// OK wraps a payload in a success envelope.
func OK(data any) Envelope {
	return Envelope{Schema: Schema, OK: true, Data: data}
}

// Err wraps an error in a failure envelope.
func Err(code, message string) Envelope {
	return Envelope{Schema: Schema, OK: false, Error: &ErrorObj{Code: code, Message: message}}
}

// WriteJSON writes an envelope to an HTTP response with the given status code.
func WriteJSON(w http.ResponseWriter, status int, env Envelope) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(env)
}

// WriteOK is shorthand for a 200 success envelope.
func WriteOK(w http.ResponseWriter, data any) {
	WriteJSON(w, http.StatusOK, OK(data))
}

// WriteErr is shorthand for a failure envelope with a status code.
func WriteErr(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, Err(code, message))
}

// Print writes a success envelope to stdout (CLI --json path).
func Print(data any) {
	printEnvelope(os.Stdout, OK(data))
}

// PrintErr writes a failure envelope to stdout (CLI --json path).
func PrintErr(code, message string) {
	printEnvelope(os.Stdout, Err(code, message))
}

func printEnvelope(w io.Writer, env Envelope) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(env)
}
