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
	taServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer taServer.Close()

	intermediaryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer intermediaryServer.Close()

	rpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer rpServer.Close()

	// RP returns authority hint to intermediary
	rpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)
		header := `{"typ":"JWT","alg":"RS256"}`
		payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"authority_hints":["%s"]}`, intermediaryServer.URL, rpServer.URL, intermediaryServer.URL)
		jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
		w.Write([]byte(jwt))
	})

	// Intermediary returns subordinate about RP on /resolve and authority_hint -> TA
	intermediaryServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/resolve" {
			sub := r.URL.Query().Get("sub")
			if sub == rpServer.URL {
				w.Header().Set("Content-Type", "application/jwt")
				w.WriteHeader(http.StatusOK)
				header := `{"typ":"JWT","alg":"RS256"}`
				payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"authority_hints":["%s"]}`, intermediaryServer.URL, sub, intermediaryServer.URL)
				jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
				w.Write([]byte(jwt))
				return
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// Intermediary self statement
		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)
		header := `{"typ":"JWT","alg":"RS256"}`
		payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600,"authority_hints":["%s"]}`, taServer.URL, intermediaryServer.URL, taServer.URL)
		jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
		w.Write([]byte(jwt))
	})

	// TA resolves intermediary
	taServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/resolve" {
			sub := r.URL.Query().Get("sub")
			if sub == intermediaryServer.URL {
				w.Header().Set("Content-Type", "application/jwt")
				w.WriteHeader(http.StatusOK)
				header := `{"typ":"JWT","alg":"RS256"}`
				// Return a TA-issued statement about the requested subject
				payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600}`, taServer.URL, sub)
				jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
				w.Write([]byte(jwt))
				return
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// TA self statement
		w.Header().Set("Content-Type", "application/jwt")
		w.WriteHeader(http.StatusOK)
		header := `{"typ":"JWT","alg":"RS256"}`
		payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":1634320000,"exp":1634323600}`, taServer.URL, taServer.URL)
		jwt := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
		w.Write([]byte(jwt))
	})

	config := &Config{
		TrustAnchors:       []string{taServer.URL},
		RequestTimeout:     5 * time.Second,
		ValidateSignatures: false,
	}

	resolver, err := NewFederationResolver(config)
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}

	ctx := context.Background()
	chain, err := resolver.ResolveTrustChain(ctx, rpServer.URL, false)
	if err != nil {
		t.Fatalf("failed to resolve trust chain: %v", err)
	}

	// Build Mermaid diagram
	mermaid := "flowchart LR\n"
	for i, e := range chain.Chain {
		node := fmt.Sprintf("N%d", i)
		label := e.Subject
		mermaid += node + "[\"" + label + "\"]\n"
	}
	for i := 0; i < len(chain.Chain)-1; i++ {
		a := fmt.Sprintf("N%d", i)
		b := fmt.Sprintf("N%d", i+1)
		mermaid += a + " --> " + b + "\n"
	}

	t.Logf("Mermaid diagram:\n%s", mermaid)
}
