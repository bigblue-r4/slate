package apiwire

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestOKEnvelope(t *testing.T) {
	env := OK(map[string]int{"n": 3})
	if env.Schema != Schema || !env.OK || env.Error != nil {
		t.Fatalf("unexpected OK envelope: %+v", env)
	}
}

func TestErrEnvelope(t *testing.T) {
	env := Err(CodeBadRequest, "nope")
	if env.OK || env.Error == nil || env.Error.Code != CodeBadRequest {
		t.Fatalf("unexpected Err envelope: %+v", env)
	}
}

func TestWriteOK(t *testing.T) {
	w := httptest.NewRecorder()
	WriteOK(w, map[string]string{"hello": "world"})
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type: %q", ct)
	}
	var env Envelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Schema != Schema || !env.OK {
		t.Fatalf("bad body: %+v", env)
	}
}

func TestWriteErrStatus(t *testing.T) {
	w := httptest.NewRecorder()
	WriteErr(w, 403, CodeForbidden, "denied")
	if w.Code != 403 {
		t.Fatalf("status: %d", w.Code)
	}
	var env Envelope
	_ = json.Unmarshal(w.Body.Bytes(), &env)
	if env.OK || env.Error.Code != CodeForbidden {
		t.Fatalf("bad error body: %+v", env)
	}
}
