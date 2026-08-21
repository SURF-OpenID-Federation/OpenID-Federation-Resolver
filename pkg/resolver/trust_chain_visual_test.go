package resolver

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestVisualTrustChain builds a sample RP->Intermediary->TA chain and logs
// a Mermaid diagram representation of the resolved chain for visual inspection.
func TestVisualTrustChain(t *testing.T) {
	taServer := httptest.NewServer(nil)
	defer taServer.Close()
	intermediaryServer := httptest.NewServer(nil)
	defer intermediaryServer.Close()
	rpServer := httptest.NewServer(nil)
	defer rpServer.Close()

	mk := func(iss, sub, extra string) string {
		h := `{"typ":"JWT","alg":"RS256"}`
		p := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600%s}`, iss, sub, extra)
		return base64.RawURLEncoding.EncodeToString([]byte(h)) + "." + base64.RawURLEncoding.EncodeToString([]byte(p)) + ".signature"
	}

	rpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(mk(rpServer.URL, rpServer.URL, fmt.Sprintf(`,"authority_hints":["%s"]`, intermediaryServer.URL))))
	})

	intermediaryServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fetch" && r.URL.Query().Get("sub") == rpServer.URL {
			_, _ = w.Write([]byte(mk(intermediaryServer.URL, rpServer.URL, "")))
			return
		}
		_, _ = w.Write([]byte(mk(intermediaryServer.URL, intermediaryServer.URL, fmt.Sprintf(
			`,"authority_hints":["%s"],"metadata":{"federation_entity":{"federation_fetch_endpoint":"%s/fetch"}}`,
			taServer.URL, intermediaryServer.URL))))
	})

	taServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fetch" && r.URL.Query().Get("sub") == intermediaryServer.URL {
			_, _ = w.Write([]byte(mk(taServer.URL, intermediaryServer.URL, "")))
			return
		}
		if r.URL.Path == "/resolve" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(mk(taServer.URL, taServer.URL, fmt.Sprintf(
			`,"metadata":{"federation_entity":{"federation_fetch_endpoint":"%s/fetch"}}`, taServer.URL))))
	})

	resolver, err := NewFederationResolver(&Config{
		TrustAnchors:       []string{taServer.URL},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	})
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	chain, err := resolver.ResolveTrustChain(context.Background(), rpServer.URL, true)
	if err != nil {
		t.Fatalf("failed to resolve trust chain: %v", err)
	}
	if len(chain.Chain) < 4 {
		t.Fatalf("expected at least 4 chain entries, got %d", len(chain.Chain))
	}

	mermaid := "flowchart LR\n"
	for i, e := range chain.Chain {
		node := fmt.Sprintf("N%d", i)
		label := fmt.Sprintf("%s\\niss=%s", e.Subject, e.Issuer)
		mermaid += node + "[\"" + label + "\"]\n"
	}
	for i := 0; i < len(chain.Chain)-1; i++ {
		mermaid += fmt.Sprintf("N%d --> N%d\n", i, i+1)
	}

	t.Logf("Mermaid diagram:\n%s", mermaid)
}
