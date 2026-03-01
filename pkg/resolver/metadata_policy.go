package resolver

// metadata_policy.go implements the metadata policy engine per OpenID Federation 1.0
// §6.1.3 (Policy Operators) and §6.1.4 (Applying Metadata Policies).
//
// This is the resolver-internal equivalent of the shared/ package policy engine.

// resolveMetadataFromCachedChain extracts the leaf's metadata, collects all
// metadata_policy claims from Subordinate Statements (where iss != sub) starting
// from the most-superior, merges them per §6.1.3.2, then applies the merged
// policy per §6.1.4.
//
// Expected chain ordering (per spec §8.3.2 / §4):
//
//	[EC_leaf, SubStmt(Int→leaf), SubStmt(TA→Int), (EC_TA)]
//
// Returns a map keyed by entity-type (e.g. "openid_provider") → claim map.
func resolveMetadataFromCachedChain(chain []CachedEntityStatement) map[string]interface{} {
	if len(chain) == 0 {
		return nil
	}

	// ── 1. Leaf metadata ────────────────────────────────────────────────────────
	// Chain[0] must be the leaf Entity Configuration (iss == sub == leaf).
	var leafMetadata map[string]interface{}
	if chain[0].ParsedClaims != nil {
		if md, ok := chain[0].ParsedClaims["metadata"].(map[string]interface{}); ok {
			leafMetadata = deepCopyAnyMap(md)
		}
	}
	if leafMetadata == nil {
		leafMetadata = make(map[string]interface{})
	}

	// ── 2. Collect SubStmt metadata_policy and metadata overrides ────────────────
	// Iterate from most-superior to most-inferior (reverse of the chain order).
	// Skip the first element (leaf EC). Skip self-signed ECs (iss==sub ≠ leaf)
	// as they are Trust Anchor / Intermediary ECs which only carry metadata_policy
	// in edge cases; we still pick up any metadata_policy they set.
	type policyEntry struct {
		metadataPolicy map[string]interface{} // §3.1.3
		metadata       map[string]interface{} // immediate superior override §6.1.4.2
		isImmSup       bool                   // true for Chain[1] (direct parent of leaf)
	}

	// We collect entries most-superior-first (reversed), so Chain[len-1] first.
	var entries []policyEntry
	for i := len(chain) - 1; i >= 1; i-- {
		ce := chain[i]
		claims := ce.ParsedClaims
		if claims == nil {
			continue
		}
		isSubStmt := normalizeEntityID(ce.Issuer) != normalizeEntityID(ce.Subject)
		isImmSup := (i == 1) // Chain[1] is the immediate superior of the leaf
		entry := policyEntry{isImmSup: isImmSup}
		if mp, ok := claims["metadata_policy"].(map[string]interface{}); ok {
			entry.metadataPolicy = mp
		}
		// Only SubStmts carry overriding metadata (§6.1.4.2 uses metadata from the
		// immediate superior subordinate statement).
		if isSubStmt {
			if md, ok := claims["metadata"].(map[string]interface{}); ok {
				entry.metadata = md
			}
		}
		entries = append(entries, entry)
	}

	// ── 3. Apply immediate-superior metadata override (§6.1.4.2) ─────────────────
	// "If the immediate superior Subordinate Statement contains a metadata claim,
	//  the metadata from that claim supersedes the corresponding claims from the
	//  Entity Configuration."
	// Our entries are most-superior-first so the immediate superior is last.
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].isImmSup && entries[i].metadata != nil {
			for entityType, supVal := range entries[i].metadata {
				supMap, ok := supVal.(map[string]interface{})
				if !ok {
					continue
				}
				if existing, ok := leafMetadata[entityType].(map[string]interface{}); ok {
					for k, v := range supMap {
						existing[k] = v
					}
					leafMetadata[entityType] = existing
				} else {
					leafMetadata[entityType] = deepCopyAnyMap(supMap)
				}
			}
			break
		}
	}

	// ── 4. Merge all metadata_policy objects most-superior-first (§6.1.3.2) ──────
	var mergedPolicy map[string]interface{}
	for _, entry := range entries {
		if entry.metadataPolicy == nil {
			continue
		}
		if mergedPolicy == nil {
			mergedPolicy = deepCopyAnyMap(entry.metadataPolicy)
		} else {
			mergedPolicy = mergePoliciesMaps(mergedPolicy, entry.metadataPolicy)
		}
	}

	// ── 5. Apply the merged policy to the leaf metadata (§6.1.4.1) ───────────────
	if mergedPolicy != nil {
		leafMetadata = applyPolicyMap(leafMetadata, mergedPolicy)
	}

	return leafMetadata
}

// mergePoliciesMaps merges an upstream (more-superior) metadata_policy with a
// downstream (more-inferior) one per §6.1.3.2.
//
// Each key is an entity-type (e.g. "openid_provider"); each value is a map of
// claim name → operator object.
func mergePoliciesMaps(upstream, downstream map[string]interface{}) map[string]interface{} {
	result := deepCopyAnyMap(upstream)
	for entityType, downVal := range downstream {
		downMap, ok := downVal.(map[string]interface{})
		if !ok {
			continue
		}
		if upVal, exists := result[entityType]; exists {
			upMap, ok := upVal.(map[string]interface{})
			if !ok {
				result[entityType] = downMap
				continue
			}
			result[entityType] = mergeEntityTypePolicies(upMap, downMap)
		} else {
			result[entityType] = downMap
		}
	}
	return result
}

// mergeEntityTypePolicies merges two per-entity-type policy maps (claim → operators).
func mergeEntityTypePolicies(upstream, downstream map[string]interface{}) map[string]interface{} {
	result := deepCopyAnyMap(upstream)
	for claimName, downOp := range downstream {
		downOpMap, ok := downOp.(map[string]interface{})
		if !ok {
			continue
		}
		if upOp, exists := result[claimName]; exists {
			upOpMap, ok := upOp.(map[string]interface{})
			if !ok {
				result[claimName] = downOpMap
				continue
			}
			result[claimName] = mergeOperatorMaps(upOpMap, downOpMap)
		} else {
			result[claimName] = downOpMap
		}
	}
	return result
}

// mergeOperatorMaps merges operator maps for a single claim per §6.1.3.1.
func mergeOperatorMaps(upstream, downstream map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	// Copy upstream first
	for k, v := range upstream {
		result[k] = v
	}

	for op, downVal := range downstream {
		upVal, upExists := upstream[op]
		switch op {
		case "value":
			// value must be equal if both set
			result["value"] = downVal
		case "add":
			downSlice := toStringSliceM(downVal)
			if upExists {
				upSlice := toStringSliceM(upVal)
				result["add"] = unionStringSlicesM(upSlice, downSlice)
			} else {
				result["add"] = downSlice
			}
		case "default":
			if !upExists {
				result["default"] = downVal
			} // upstream wins for default
		case "subset_of":
			downSlice := toStringSliceM(downVal)
			if upExists {
				upSlice := toStringSliceM(upVal)
				result["subset_of"] = intersectStringSlicesM(upSlice, downSlice)
			} else {
				result["subset_of"] = downSlice
			}
		case "superset_of":
			downSlice := toStringSliceM(downVal)
			if upExists {
				upSlice := toStringSliceM(upVal)
				result["superset_of"] = unionStringSlicesM(upSlice, downSlice)
			} else {
				result["superset_of"] = downSlice
			}
		case "one_of":
			downSlice := toStringSliceM(downVal)
			if upExists {
				upSlice := toStringSliceM(upVal)
				result["one_of"] = intersectStringSlicesM(upSlice, downSlice)
			} else {
				result["one_of"] = downSlice
			}
		case "essential":
			// true wins over false
			if b, ok := downVal.(bool); ok && b {
				result["essential"] = true
			} else if !upExists {
				result["essential"] = downVal
			}
		default:
			result[op] = downVal
		}
	}
	return result
}

// applyPolicyMap applies a merged metadata_policy to resolved leaf metadata.
// Each top-level key in policy is an entity type; each value is a claim→operator map.
func applyPolicyMap(metadata, policy map[string]interface{}) map[string]interface{} {
	result := deepCopyAnyMap(metadata)
	for entityType, rawClaimPolicy := range policy {
		claimPolicy, ok := rawClaimPolicy.(map[string]interface{})
		if !ok {
			continue
		}
		var entityMeta map[string]interface{}
		if em, ok := result[entityType].(map[string]interface{}); ok {
			entityMeta = em
		} else {
			entityMeta = make(map[string]interface{})
		}
		entityMeta = applyClaimPolicy(entityMeta, claimPolicy)
		result[entityType] = entityMeta
	}
	return result
}

// applyClaimPolicy applies a per-entity-type claim→operator policy to a metadata map.
func applyClaimPolicy(metadata, claimPolicy map[string]interface{}) map[string]interface{} {
	result := deepCopyAnyMap(metadata)
	for claimName, rawOps := range claimPolicy {
		ops, ok := rawOps.(map[string]interface{})
		if !ok {
			continue
		}
		currentVal, exists := result[claimName]

		// value — forces the value regardless of what the leaf set
		if v, ok := ops["value"]; ok {
			result[claimName] = v
			continue
		}

		// add — extends a list claim
		if addRaw, ok := ops["add"]; ok {
			addSlice := toStringSliceM(addRaw)
			var curSlice []string
			if exists {
				curSlice = toStringSliceM(currentVal)
			}
			result[claimName] = unionStringSlicesM(curSlice, addSlice)
		}

		// default — sets the value only if absent
		if defVal, ok := ops["default"]; ok && !exists {
			result[claimName] = defVal
			exists = true
			currentVal = defVal
		}

		// subset_of — allowed values
		if subRaw, ok := ops["subset_of"]; ok && exists {
			allowed := toStringSliceM(subRaw)
			curSlice := toStringSliceM(currentVal)
			result[claimName] = intersectStringSlicesM(curSlice, allowed)
		}

		// superset_of — required values (only enforceable; we add missing ones)
		if supRaw, ok := ops["superset_of"]; ok {
			required := toStringSliceM(supRaw)
			var curSlice []string
			if exists {
				curSlice = toStringSliceM(currentVal)
			}
			result[claimName] = unionStringSlicesM(curSlice, required)
		}

		// one_of — exactly one of the allowed values
		if oneRaw, ok := ops["one_of"]; ok && exists {
			allowed := toStringSliceM(oneRaw)
			if s, ok := currentVal.(string); ok {
				found := false
				for _, a := range allowed {
					if s == a {
						found = true
						break
					}
				}
				if !found && len(allowed) > 0 {
					result[claimName] = allowed[0]
				}
			}
		}
	}
	return result
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func deepCopyAnyMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		switch vv := v.(type) {
		case map[string]interface{}:
			out[k] = deepCopyAnyMap(vv)
		case []interface{}:
			cp := make([]interface{}, len(vv))
			copy(cp, vv)
			out[k] = cp
		default:
			out[k] = v
		}
	}
	return out
}

func toStringSliceM(v interface{}) []string {
	switch vv := v.(type) {
	case []string:
		return vv
	case []interface{}:
		out := make([]string, 0, len(vv))
		for _, elem := range vv {
			if s, ok := elem.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{vv}
	}
	return nil
}

func unionStringSlicesM(a, b []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func intersectStringSlicesM(a, b []string) []string {
	set := make(map[string]bool)
	for _, s := range b {
		set[s] = true
	}
	out := make([]string, 0)
	for _, s := range a {
		if set[s] {
			out = append(out, s)
		}
	}
	return out
}

// canonicalTrustChainJWTs produces the trust_chain JWT array per §8.3.2:
//
//	[EC_leaf, SubStmt(Int→leaf), SubStmt(TA→Int), (EC_TA)]
//
// Intermediary self-signed ECs (iss==sub, but not the leaf and not the TA) are
// filtered out — they are implementation artifacts of chain traversal and are
// not part of the trust chain as defined in §4.
func canonicalTrustChainJWTs(chain []CachedEntityStatement, leafID, trustAnchorID string) []string {
	normLeaf := normalizeEntityID(leafID)
	normTA := normalizeEntityID(trustAnchorID)

	result := make([]string, 0, len(chain))
	for _, ce := range chain {
		if ce.Statement == "" {
			continue
		}
		normIss := normalizeEntityID(ce.Issuer)
		normSub := normalizeEntityID(ce.Subject)
		isSelfSigned := normIss == normSub
		if isSelfSigned {
			// Keep only the leaf EC and the trust anchor EC
			if normIss == normLeaf || normIss == normTA {
				result = append(result, ce.Statement)
			}
			// Intermediary ECs are silently dropped
		} else {
			// All SubStmts (iss != sub) are kept
			result = append(result, ce.Statement)
		}
	}
	return result
}
