package resolver

import (
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func sortedStringsM(v interface{}) []string {
	sl := toStringSliceM(v)
	cp := append([]string(nil), sl...)
	sort.Strings(cp)
	return cp
}

func cachedStmt(iss, sub string, claims map[string]interface{}) CachedEntityStatement {
	if claims == nil {
		claims = map[string]interface{}{}
	}
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = iss
	}
	if _, ok := claims["sub"]; !ok {
		claims["sub"] = sub
	}
	return CachedEntityStatement{
		EntityID:     sub,
		Issuer:       iss,
		Subject:      sub,
		ParsedClaims: claims,
	}
}

func leafEC(iss string, metadata map[string]interface{}) CachedEntityStatement {
	c := map[string]interface{}{"iss": iss, "sub": iss}
	if metadata != nil {
		c["metadata"] = metadata
	}
	return cachedStmt(iss, iss, c)
}

func subPolicy(iss, sub string, policy, overlay map[string]interface{}) CachedEntityStatement {
	c := map[string]interface{}{"iss": iss, "sub": sub}
	if policy != nil {
		c["metadata_policy"] = policy
	}
	if overlay != nil {
		c["metadata"] = overlay
	}
	return cachedStmt(iss, sub, c)
}

func opPol(param string, ops map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"openid_provider": map[string]interface{}{param: ops}}
}

func mustApplyCached(t *testing.T, chain []CachedEntityStatement) map[string]interface{} {
	t.Helper()
	md, err := applyMetadataPolicy(chain)
	if err != nil {
		t.Fatalf("applyMetadataPolicy: %v", err)
	}
	return md
}

func entityType(t *testing.T, md map[string]interface{}, typ string) map[string]interface{} {
	t.Helper()
	got, ok := md[typ].(map[string]interface{})
	if !ok {
		t.Fatalf("missing %q in %+v", typ, md)
	}
	return got
}

func theoryPaperChain() []CachedEntityStatement {
	return []CachedEntityStatement{
		leafEC("https://op.example", map[string]interface{}{
			"openid_provider": map[string]interface{}{
				"issuer":                                "https://op.example",
				"scopes_supported":                      []interface{}{"openid", "profile", "email", "address", "phone"},
				"id_token_signing_alg_values_supported": []interface{}{"RS256", "ES256", "HS256"},
				"token_endpoint_auth_methods_supported": []interface{}{"client_secret_basic"},
				"subject_types_supported":               []interface{}{"public"},
				"claims_supported":                      []interface{}{"sub", "iss"},
				"contacts":                              []interface{}{"admin@op.example"},
			},
		}),
		subPolicy("https://int.example", "https://op.example",
			map[string]interface{}{
				"openid_provider": map[string]interface{}{
					"scopes_supported":                      map[string]interface{}{"subset_of": []interface{}{"openid", "profile", "email"}},
					"id_token_signing_alg_values_supported": map[string]interface{}{"subset_of": []interface{}{"ES256", "PS256"}},
					"claims_supported":                      map[string]interface{}{"add": []interface{}{"email"}},
					"userinfo_signed_response_alg":          map[string]interface{}{"default": "ES256"},
				},
			},
			map[string]interface{}{
				"openid_provider": map[string]interface{}{
					"contacts": []interface{}{"federation@int.example"},
				},
			},
		),
		subPolicy("https://ta.example", "https://int.example",
			map[string]interface{}{
				"openid_provider": map[string]interface{}{
					"scopes_supported":                      map[string]interface{}{"subset_of": []interface{}{"openid", "profile", "email", "phone"}},
					"id_token_signing_alg_values_supported": map[string]interface{}{"subset_of": []interface{}{"RS256", "ES256", "PS256"}},
					"token_endpoint_auth_methods_supported": map[string]interface{}{"add": []interface{}{"private_key_jwt"}},
					"subject_types_supported":               map[string]interface{}{"superset_of": []interface{}{"public"}},
					"contacts":                              map[string]interface{}{"essential": true},
				},
			},
			nil,
		),
		leafEC("https://ta.example", nil),
	}
}

func TestResolverTheoryPaperFederation_ResolvedMetadata(t *testing.T) {
	md := mustApplyCached(t, theoryPaperChain())
	op := entityType(t, md, "openid_provider")
	if op["issuer"] != "https://op.example" {
		t.Errorf("issuer: %v", op["issuer"])
	}
	if got := sortedStringsM(op["scopes_supported"]); !reflect.DeepEqual(got, []string{"email", "openid", "profile"}) {
		t.Errorf("scopes_supported: %v", got)
	}
	if got := sortedStringsM(op["id_token_signing_alg_values_supported"]); !reflect.DeepEqual(got, []string{"ES256"}) {
		t.Errorf("id_token algs: %v", got)
	}
	if got := sortedStringsM(op["token_endpoint_auth_methods_supported"]); !reflect.DeepEqual(got, []string{"client_secret_basic", "private_key_jwt"}) {
		t.Errorf("token auth: %v", got)
	}
	if got := sortedStringsM(op["subject_types_supported"]); !reflect.DeepEqual(got, []string{"public"}) {
		t.Errorf("subject_types: %v", got)
	}
	if got := sortedStringsM(op["claims_supported"]); !reflect.DeepEqual(got, []string{"email", "iss", "sub"}) {
		t.Errorf("claims_supported: %v", got)
	}
	if op["userinfo_signed_response_alg"] != "ES256" {
		t.Errorf("userinfo alg: %v", op["userinfo_signed_response_alg"])
	}
	if got := sortedStringsM(op["contacts"]); !reflect.DeepEqual(got, []string{"federation@int.example"}) {
		t.Errorf("contacts: %v", got)
	}
}

func TestResolverTheoryPaperFederation_NegativeCases(t *testing.T) {
	t.Run("one_of scalar not allowed", func(t *testing.T) {
		chain := theoryPaperChain()
		leaf := chain[0].ParsedClaims["metadata"].(map[string]interface{})["openid_provider"].(map[string]interface{})
		leaf["id_token_signed_response_alg"] = "RS256"
		ta := chain[2].ParsedClaims["metadata_policy"].(map[string]interface{})["openid_provider"].(map[string]interface{})
		ta["id_token_signed_response_alg"] = map[string]interface{}{"one_of": []interface{}{"ES256"}}
		if _, err := applyMetadataPolicy(chain); err == nil {
			t.Fatal("expected one_of failure")
		}
	})
	t.Run("superset_of missing required", func(t *testing.T) {
		chain := theoryPaperChain()
		leaf := chain[0].ParsedClaims["metadata"].(map[string]interface{})["openid_provider"].(map[string]interface{})
		leaf["subject_types_supported"] = []interface{}{"pairwise"}
		if _, err := applyMetadataPolicy(chain); err == nil {
			t.Fatal("expected superset_of failure")
		}
	})
	t.Run("essential contacts missing", func(t *testing.T) {
		chain := theoryPaperChain()
		leaf := chain[0].ParsedClaims["metadata"].(map[string]interface{})["openid_provider"].(map[string]interface{})
		delete(leaf, "contacts")
		delete(chain[1].ParsedClaims, "metadata")
		if _, err := applyMetadataPolicy(chain); err == nil {
			t.Fatal("expected essential failure")
		}
	})
	t.Run("empty subset_of merge", func(t *testing.T) {
		chain := theoryPaperChain()
		intPol := chain[1].ParsedClaims["metadata_policy"].(map[string]interface{})["openid_provider"].(map[string]interface{})
		intPol["scopes_supported"] = map[string]interface{}{"subset_of": []interface{}{"offline_access"}}
		if _, err := applyMetadataPolicy(chain); err == nil {
			t.Fatal("expected empty subset_of intersection to fail")
		}
	})
	t.Run("disagreeing value", func(t *testing.T) {
		chain := theoryPaperChain()
		intPol := chain[1].ParsedClaims["metadata_policy"].(map[string]interface{})["openid_provider"].(map[string]interface{})
		taPol := chain[2].ParsedClaims["metadata_policy"].(map[string]interface{})["openid_provider"].(map[string]interface{})
		intPol["token_endpoint_auth_method"] = map[string]interface{}{"value": "client_secret_basic"}
		taPol["token_endpoint_auth_method"] = map[string]interface{}{"value": "private_key_jwt"}
		if _, err := applyMetadataPolicy(chain); err == nil {
			t.Fatal("expected conflicting value to fail")
		}
	})
	t.Run("unknown metadata_policy_crit", func(t *testing.T) {
		chain := theoryPaperChain()
		chain[2].ParsedClaims["metadata_policy_crit"] = []interface{}{"regexp"}
		if _, err := applyMetadataPolicy(chain); err == nil {
			t.Fatal("expected unknown crit operator to fail")
		}
	})
}

func TestResolverResolveSwallowsPolicyError(t *testing.T) {
	chain := theoryPaperChain()
	intPol := chain[1].ParsedClaims["metadata_policy"].(map[string]interface{})["openid_provider"].(map[string]interface{})
	intPol["scopes_supported"] = map[string]interface{}{"subset_of": []interface{}{"offline_access"}}
	if _, err := applyMetadataPolicy(chain); err == nil {
		t.Fatal("setup")
	}
	if got := resolveMetadataFromCachedChain(chain); got != nil {
		t.Fatalf("wrapper hides error as nil: %+v", got)
	}
}

func TestResolverApply_EmptyAndLeafOnly(t *testing.T) {
	md, err := applyMetadataPolicy(nil)
	if err != nil || md != nil {
		t.Fatalf("empty: md=%v err=%v", md, err)
	}
	md = mustApplyCached(t, []CachedEntityStatement{
		leafEC("https://op.example", map[string]interface{}{
			"openid_provider": map[string]interface{}{"issuer": "https://op.example"},
		}),
	})
	if entityType(t, md, "openid_provider")["issuer"] != "https://op.example" {
		t.Fatal("leaf-only metadata lost")
	}
}

func TestResolverApply_ValueAddDefaultSubset(t *testing.T) {
	t.Run("value forces", func(t *testing.T) {
		md := mustApplyCached(t, []CachedEntityStatement{
			leafEC("https://rp.example", map[string]interface{}{
				"openid_relying_party": map[string]interface{}{"token_endpoint_auth_method": "none"},
			}),
			subPolicy("https://ta.example", "https://rp.example", map[string]interface{}{
				"openid_relying_party": map[string]interface{}{
					"token_endpoint_auth_method": map[string]interface{}{"value": "private_key_jwt"},
				},
			}, nil),
		})
		if entityType(t, md, "openid_relying_party")["token_endpoint_auth_method"] != "private_key_jwt" {
			t.Fatal(md)
		}
	})
	t.Run("default fills missing only", func(t *testing.T) {
		md := mustApplyCached(t, []CachedEntityStatement{
			leafEC("https://rp.example", map[string]interface{}{
				"openid_relying_party": map[string]interface{}{"token_endpoint_auth_method": "client_secret_post"},
			}),
			subPolicy("https://ta.example", "https://rp.example", map[string]interface{}{
				"openid_relying_party": map[string]interface{}{
					"token_endpoint_auth_method":   map[string]interface{}{"default": "private_key_jwt"},
					"userinfo_signed_response_alg": map[string]interface{}{"default": "ES256"},
				},
			}, nil),
		})
		rp := entityType(t, md, "openid_relying_party")
		if rp["token_endpoint_auth_method"] != "client_secret_post" {
			t.Errorf("default overwrote: %v", rp["token_endpoint_auth_method"])
		}
		if rp["userinfo_signed_response_alg"] != "ES256" {
			t.Errorf("default missing: %v", rp["userinfo_signed_response_alg"])
		}
	})
	t.Run("add then subset_of", func(t *testing.T) {
		md := mustApplyCached(t, []CachedEntityStatement{
			leafEC("https://op.example", map[string]interface{}{
				"openid_provider": map[string]interface{}{"scopes_supported": []interface{}{"openid"}},
			}),
			subPolicy("https://ta.example", "https://op.example", opPol("scopes_supported", map[string]interface{}{
				"add": []interface{}{"phone", "email"}, "subset_of": []interface{}{"openid", "email"},
			}), nil),
		})
		if got := sortedStringsM(entityType(t, md, "openid_provider")["scopes_supported"]); !reflect.DeepEqual(got, []string{"email", "openid"}) {
			t.Errorf("got %v", got)
		}
	})
}

func TestResolverApply_OneOfAndSuperset(t *testing.T) {
	t.Run("one_of allowed", func(t *testing.T) {
		md := mustApplyCached(t, []CachedEntityStatement{
			leafEC("https://op.example", map[string]interface{}{
				"openid_provider": map[string]interface{}{"subject_type": "pairwise"},
			}),
			subPolicy("https://ta.example", "https://op.example", opPol("subject_type", map[string]interface{}{
				"one_of": []interface{}{"public", "pairwise"},
			}), nil),
		})
		if entityType(t, md, "openid_provider")["subject_type"] != "pairwise" {
			t.Fatal(md)
		}
	})
	t.Run("one_of rejects", func(t *testing.T) {
		_, err := applyMetadataPolicy([]CachedEntityStatement{
			leafEC("https://op.example", map[string]interface{}{
				"openid_provider": map[string]interface{}{"subject_type": "public"},
			}),
			subPolicy("https://ta.example", "https://op.example", opPol("subject_type", map[string]interface{}{
				"one_of": []interface{}{"pairwise"},
			}), nil),
		})
		if err == nil {
			t.Fatal("expected one_of error, must not rewrite to pairwise")
		}
	})
	t.Run("one_of absent ok", func(t *testing.T) {
		if _, err := applyMetadataPolicy([]CachedEntityStatement{
			leafEC("https://op.example", map[string]interface{}{"openid_provider": map[string]interface{}{}}),
			subPolicy("https://ta.example", "https://op.example", opPol("subject_type", map[string]interface{}{
				"one_of": []interface{}{"pairwise"},
			}), nil),
		}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("superset extras ok", func(t *testing.T) {
		md := mustApplyCached(t, []CachedEntityStatement{
			leafEC("https://op.example", map[string]interface{}{
				"openid_provider": map[string]interface{}{"subject_types_supported": []interface{}{"public", "pairwise"}},
			}),
			subPolicy("https://ta.example", "https://op.example", opPol("subject_types_supported", map[string]interface{}{
				"superset_of": []interface{}{"public"},
			}), nil),
		})
		if got := sortedStringsM(entityType(t, md, "openid_provider")["subject_types_supported"]); !reflect.DeepEqual(got, []string{"pairwise", "public"}) {
			t.Errorf("must not invent or drop extras: %v", got)
		}
	})
	t.Run("superset must not add missing", func(t *testing.T) {
		_, err := applyMetadataPolicy([]CachedEntityStatement{
			leafEC("https://op.example", map[string]interface{}{
				"openid_provider": map[string]interface{}{"subject_types_supported": []interface{}{"pairwise"}},
			}),
			subPolicy("https://ta.example", "https://op.example", opPol("subject_types_supported", map[string]interface{}{
				"superset_of": []interface{}{"public"},
			}), nil),
		})
		if err == nil {
			t.Fatal("superset_of must fail, not union-in public")
		}
	})
}

func TestResolverApply_EssentialAndCrit(t *testing.T) {
	t.Run("essential missing", func(t *testing.T) {
		if _, err := applyMetadataPolicy([]CachedEntityStatement{
			leafEC("https://rp.example", map[string]interface{}{"openid_relying_party": map[string]interface{}{}}),
			subPolicy("https://ta.example", "https://rp.example", map[string]interface{}{
				"openid_relying_party": map[string]interface{}{"jwks_uri": map[string]interface{}{"essential": true}},
			}, nil),
		}); err == nil {
			t.Fatal("expected essential error")
		}
	})
	t.Run("essential satisfied by default", func(t *testing.T) {
		md := mustApplyCached(t, []CachedEntityStatement{
			leafEC("https://rp.example", map[string]interface{}{"openid_relying_party": map[string]interface{}{}}),
			subPolicy("https://ta.example", "https://rp.example", map[string]interface{}{
				"openid_relying_party": map[string]interface{}{
					"token_endpoint_auth_method": map[string]interface{}{"default": "private_key_jwt", "essential": true},
				},
			}, nil),
		})
		if entityType(t, md, "openid_relying_party")["token_endpoint_auth_method"] != "private_key_jwt" {
			t.Fatal(md)
		}
	})
	t.Run("known crit ok", func(t *testing.T) {
		chain := []CachedEntityStatement{
			leafEC("https://rp.example", map[string]interface{}{"openid_relying_party": map[string]interface{}{"client_name": "RP"}}),
			cachedStmt("https://ta.example", "https://rp.example", map[string]interface{}{
				"iss": "https://ta.example", "sub": "https://rp.example",
				"metadata_policy_crit": []interface{}{"value", "essential"},
				"metadata_policy": map[string]interface{}{
					"openid_relying_party": map[string]interface{}{"client_name": map[string]interface{}{"value": "Forced"}},
				},
			}),
		}
		if entityType(t, mustApplyCached(t, chain), "openid_relying_party")["client_name"] != "Forced" {
			t.Fatal("crit of known operators should apply")
		}
	})
	t.Run("crit not array", func(t *testing.T) {
		if _, err := applyMetadataPolicy([]CachedEntityStatement{
			leafEC("https://rp.example", map[string]interface{}{}),
			cachedStmt("https://ta.example", "https://rp.example", map[string]interface{}{
				"iss": "https://ta.example", "sub": "https://rp.example", "metadata_policy_crit": 1,
			}),
		}); err == nil {
			t.Fatal("expected crit type error")
		}
	})
}

func TestResolverApply_ChainShape(t *testing.T) {
	t.Run("self-signed TA policy ignored", func(t *testing.T) {
		md := mustApplyCached(t, []CachedEntityStatement{
			leafEC("https://op.example", map[string]interface{}{
				"openid_provider": map[string]interface{}{"scopes_supported": []interface{}{"openid", "address"}},
			}),
			subPolicy("https://ta.example", "https://op.example", nil, nil),
			cachedStmt("https://ta.example", "https://ta.example", map[string]interface{}{
				"iss": "https://ta.example", "sub": "https://ta.example",
				"metadata_policy": opPol("scopes_supported", map[string]interface{}{"subset_of": []interface{}{"openid"}}),
			}),
		})
		if got := sortedStringsM(entityType(t, md, "openid_provider")["scopes_supported"]); !reflect.DeepEqual(got, []string{"address", "openid"}) {
			t.Errorf("TA EC policy applied: %v", got)
		}
	})
	t.Run("non-immediate overlay ignored", func(t *testing.T) {
		md := mustApplyCached(t, []CachedEntityStatement{
			leafEC("https://rp.example", map[string]interface{}{
				"openid_relying_party": map[string]interface{}{"client_name": "Leaf"},
			}),
			subPolicy("https://int.example", "https://rp.example", nil, nil),
			subPolicy("https://ta.example", "https://int.example", nil, map[string]interface{}{
				"openid_relying_party": map[string]interface{}{"client_name": "TA Overlay"},
			}),
		})
		if entityType(t, md, "openid_relying_party")["client_name"] != "Leaf" {
			t.Errorf("got %v", entityType(t, md, "openid_relying_party")["client_name"])
		}
	})
	t.Run("overlay then policy", func(t *testing.T) {
		md := mustApplyCached(t, []CachedEntityStatement{
			leafEC("https://op.example", map[string]interface{}{
				"openid_provider": map[string]interface{}{"scopes_supported": []interface{}{"openid", "profile", "address"}},
			}),
			subPolicy("https://int.example", "https://op.example",
				opPol("scopes_supported", map[string]interface{}{"subset_of": []interface{}{"openid", "email"}}),
				map[string]interface{}{"openid_provider": map[string]interface{}{"scopes_supported": []interface{}{"openid", "email", "phone"}}},
			),
		})
		if got := sortedStringsM(entityType(t, md, "openid_provider")["scopes_supported"]); !reflect.DeepEqual(got, []string{"email", "openid"}) {
			t.Errorf("got %v", got)
		}
	})
	t.Run("OP policy does not rewrite RP", func(t *testing.T) {
		chain := theoryPaperChain()
		chain[0].ParsedClaims["metadata"].(map[string]interface{})["openid_relying_party"] = map[string]interface{}{
			"grant_types": []interface{}{"authorization_code", "implicit"},
		}
		rp := entityType(t, mustApplyCached(t, chain), "openid_relying_party")
		if got := sortedStringsM(rp["grant_types"]); !reflect.DeepEqual(got, []string{"authorization_code", "implicit"}) {
			t.Errorf("RP rewritten: %v", got)
		}
	})
	t.Run("four-hop subset", func(t *testing.T) {
		md := mustApplyCached(t, []CachedEntityStatement{
			leafEC("https://op.example", map[string]interface{}{
				"openid_provider": map[string]interface{}{
					"scopes_supported": []interface{}{"openid", "profile", "email", "address", "phone"},
				},
			}),
			subPolicy("https://int2.example", "https://op.example", opPol("scopes_supported", map[string]interface{}{
				"subset_of": []interface{}{"openid", "email"},
			}), nil),
			subPolicy("https://int1.example", "https://int2.example", opPol("scopes_supported", map[string]interface{}{
				"subset_of": []interface{}{"openid", "profile", "email", "phone"},
			}), nil),
			subPolicy("https://ta.example", "https://int1.example", opPol("scopes_supported", map[string]interface{}{
				"subset_of": []interface{}{"openid", "profile", "email", "phone", "offline_access"},
			}), nil),
			leafEC("https://ta.example", nil),
		})
		if got := sortedStringsM(entityType(t, md, "openid_provider")["scopes_supported"]); !reflect.DeepEqual(got, []string{"email", "openid"}) {
			t.Errorf("got %v", got)
		}
	})
}

func TestResolverMerge_Conflicts(t *testing.T) {
	t.Run("empty one_of", func(t *testing.T) {
		_, err := mergePoliciesMaps(
			opPol("alg", map[string]interface{}{"one_of": []interface{}{"ES256"}}),
			opPol("alg", map[string]interface{}{"one_of": []interface{}{"RS256"}}),
		)
		if err == nil {
			t.Fatal("expected empty one_of intersection error")
		}
	})
	t.Run("agreeing value", func(t *testing.T) {
		merged, err := mergePoliciesMaps(
			opPol("m", map[string]interface{}{"value": "private_key_jwt"}),
			opPol("m", map[string]interface{}{"value": "private_key_jwt"}),
		)
		if err != nil {
			t.Fatal(err)
		}
		if merged["openid_provider"].(map[string]interface{})["m"].(map[string]interface{})["value"] != "private_key_jwt" {
			t.Fatal(merged)
		}
	})
	t.Run("value beats downstream default", func(t *testing.T) {
		md := mustApplyCached(t, []CachedEntityStatement{
			leafEC("https://rp.example", map[string]interface{}{"openid_relying_party": map[string]interface{}{}}),
			subPolicy("https://int.example", "https://rp.example", map[string]interface{}{
				"openid_relying_party": map[string]interface{}{
					"token_endpoint_auth_method": map[string]interface{}{"default": "client_secret_basic"},
				},
			}, nil),
			subPolicy("https://ta.example", "https://int.example", map[string]interface{}{
				"openid_relying_party": map[string]interface{}{
					"token_endpoint_auth_method": map[string]interface{}{"value": "private_key_jwt"},
				},
			}, nil),
		})
		if entityType(t, md, "openid_relying_party")["token_endpoint_auth_method"] != "private_key_jwt" {
			t.Fatal(md)
		}
	})
}

func TestResolverCreateSignedResponse_PolicyError(t *testing.T) {
	cfg := &Config{
		AllowPrivateNetworks: true, EnableSigning: true, RequestTimeout: 2 * time.Second}
	r, err := NewFederationResolver(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.InitializeResolverKeys(); err != nil {
		t.Fatal(err)
	}
	ta := "https://ta.example"
	if err := r.RegisterTrustAnchor(&TrustAnchorRegistration{EntityID: ta, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	chain := theoryPaperChain()
	intPol := chain[1].ParsedClaims["metadata_policy"].(map[string]interface{})["openid_provider"].(map[string]interface{})
	intPol["scopes_supported"] = map[string]interface{}{"subset_of": []interface{}{"offline_access"}}
	_, err = r.CreateSignedTrustChainResponse(&CachedTrustChain{
		EntityID: "https://op.example", TrustAnchor: ta, Chain: chain, Status: "valid",
	}, ta)
	if err == nil || !strings.Contains(err.Error(), "metadata policy") {
		t.Fatalf("signed resolve must fail a policy-invalid chain, err=%v", err)
	}
}
