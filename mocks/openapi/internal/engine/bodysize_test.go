package engine

import (
	"net/http"
	"strings"
	"testing"
)

// A request body of 1 MiB or more is refused as a violation of the rule maxBytes; one byte less is served.
func TestRequestBodyOfOneMiBIsRefused(t *testing.T) {
	h := newHarness(t, apiDocument, nil)
	base := h.open("run-body-size")
	jsonType := map[string]string{"Content-Type": "application/json"}
	// body builds a valid /login body of exactly n bytes: the schema allows any string for user.
	body := func(n int) string {
		const head, tail = `{"user":"`, `"}`
		return head + strings.Repeat("a", n-len(head)-len(tail)) + tail
	}
	if r := send(t, "POST", base+"/login", body(maxRequestBody-1), jsonType); r.status != http.StatusOK {
		t.Fatalf("a body one byte under the limit = %d (%.200s), want 200", r.status, r.body)
	}
	for _, n := range []int{maxRequestBody, maxRequestBody + 4096} {
		r := send(t, "POST", base+"/login", body(n), jsonType)
		if r.status != http.StatusBadRequest {
			t.Fatalf("a body of %d bytes = %d (%.200s), want 400", n, r.status, r.body)
		}
		if doc := r.json(t); doc["rule"] != ruleBodySize || doc["pointer"] != "/body" || doc["reason_code"] != "request-invalid" {
			t.Fatalf("a body of %d bytes: %s, want rule %s at /body", n, r.body, ruleBodySize)
		}
	}
}
