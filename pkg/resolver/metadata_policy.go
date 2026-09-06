package resolver

import (
	"fmt"
	"log"
)

// metadata_policy.go implements the metadata policy engine per OpenID Federation 1.0
// §5.1.2–§5.1.3 (operators / crit) and §6.1.3–§6.1.4 (merge and apply).
//
// This is the resolver-internal equivalent of the federation shared/ engine.

// resolveMetadataFromCachedChain applies policies and returns nil if the chain
// is empty or the policy is invalid (errors are logged). Prefer applyMetadataPolicy
// when the caller must fail the resolve.
func resolveMetadataFromCachedChain(chain []CachedEntityStatement) map[string]interface{} {
	md, err := applyMetadataPolicy(chain)
	if err != nil {
		log.Printf("[WARN] metadata policy application failed: %v", err)
		return nil
	}
	return md
}

// applyMetadataPolicy merges and applies metadata_policy from the chain.
// chain[0] is the leaf Entity Configuration. Self-signed ECs after that are
// skipped. Unknown metadata_policy_crit operators and operator conflicts fail.
func applyMetadataPolicy(chain []CachedEntityStatement) (map[string]interface{}, error) {
	if len(chain) == 0 {
		return nil, nil
	}
	if err := checkMetadataPolicyCrit(chain); err != nil {
		return nil, err
	}

	var leafMetadata map[string]interface{}
	if chain[0].ParsedClaims != nil {
		if md, ok := chain[0].ParsedClaims["metadata"].(map[string]interface{}); ok {
			leafMetadata = deepCopyAnyMap(md)
		}
	}
	if leafMetadata == nil {
		leafMetadata = make(map[string]interface{})
	}

	type policyEntry struct {
		metadataPolicy map[string]interface{}
		metadata       map[string]interface{}
	}
	var entries []policyEntry
	for i := len(chain) - 1; i >= 1; i-- {
		ce := chain[i]
		claims := ce.ParsedClaims
		if claims == nil {
			continue
		}
		iss, sub := ce.Issuer, ce.Subject
		if iss == "" {
			iss, _ = claims["iss"].(string)
		}
		if sub == "" {
			sub, _ = claims["sub"].(string)
		}
		if normalizeEntityID(iss) == normalizeEntityID(sub) {
			continue
		}
		entry := policyEntry{}
		if mp, ok := claims["metadata_policy"].(map[string]interface{}); ok {
			entry.metadataPolicy = deepCopyAnyMap(mp)
		}
		if md, ok := claims["metadata"].(map[string]interface{}); ok {
			entry.metadata = deepCopyAnyMap(md)
		}
		entries = append(entries, entry)
	}

	if len(entries) > 0 {
		immediate := entries[len(entries)-1]
		if immediate.metadata != nil {
			for entityType, supVal := range immediate.metadata {
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
		}
	}

	var mergedPolicy map[string]interface{}
	for _, entry := range entries {
		if entry.metadataPolicy == nil {
			continue
		}
		if mergedPolicy == nil {
			mergedPolicy = deepCopyAnyMap(entry.metadataPolicy)
			continue
		}
		merged, err := mergePoliciesMaps(mergedPolicy, entry.metadataPolicy)
		if err != nil {
			return nil, err
		}
		mergedPolicy = merged
	}

	if mergedPolicy != nil {
		applied, err := applyPolicyMap(leafMetadata, mergedPolicy)
		if err != nil {
			return nil, err
		}
		leafMetadata = applied
	}
	return leafMetadata, nil
}

func checkMetadataPolicyCrit(chain []CachedEntityStatement) error {
	for _, ce := range chain {
		if ce.ParsedClaims == nil {
			continue
		}
		critRaw, ok := ce.ParsedClaims["metadata_policy_crit"]
		if !ok || critRaw == nil {
			continue
		}
		names := toStringSliceM(critRaw)
		switch critRaw.(type) {
		case []string, []interface{}:
		default:
			return fmt.Errorf("metadata_policy_crit must be an array of operator names")
		}
		for _, name := range names {
			if !knownPolicyOperators[name] {
				return fmt.Errorf("metadata_policy_crit lists unsupported operator %q", name)
			}
		}
	}
	return nil
}

var knownPolicyOperators = map[string]bool{
	"value": true, "add": true, "default": true,
	"subset_of": true, "superset_of": true, "one_of": true, "essential": true,
}

func mergePoliciesMaps(upstream, downstream map[string]interface{}) (map[string]interface{}, error) {
	result := deepCopyAnyMap(upstream)
	if result == nil {
		result = make(map[string]interface{})
	}
	for entityType, downVal := range downstream {
		downMap, ok := downVal.(map[string]interface{})
		if !ok {
			continue
		}
		if upVal, exists := result[entityType]; exists {
			upMap, ok := upVal.(map[string]interface{})
			if !ok {
				result[entityType] = deepCopyAnyMap(downMap)
				continue
			}
			merged, err := mergeEntityTypePolicies(upMap, downMap, entityType)
			if err != nil {
				return nil, err
			}
			result[entityType] = merged
		} else {
			result[entityType] = deepCopyAnyMap(downMap)
		}
	}
	return result, nil
}

func mergeEntityTypePolicies(upstream, downstream map[string]interface{}, entityType string) (map[string]interface{}, error) {
	result := deepCopyAnyMap(upstream)
	for claimName, downOp := range downstream {
		downOpMap, ok := downOp.(map[string]interface{})
		if !ok {
			continue
		}
		if upOp, exists := result[claimName]; exists {
			upOpMap, ok := upOp.(map[string]interface{})
			if !ok {
				result[claimName] = deepCopyAnyMap(downOpMap)
				continue
			}
			merged, err := mergeOperatorMaps(upOpMap, downOpMap)
			if err != nil {
				return nil, fmt.Errorf("metadata_policy %s.%s: %w", entityType, claimName, err)
			}
			result[claimName] = merged
		} else {
			result[claimName] = deepCopyAnyMap(downOpMap)
		}
	}
	return result, nil
}

func mergeOperatorMaps(upstream, downstream map[string]interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	for k, v := range upstream {
		result[k] = v
	}
	for op, downVal := range downstream {
		switch op {
		case "value":
			if upVal, exists := result["value"]; exists {
				if fmt.Sprintf("%v", upVal) != fmt.Sprintf("%v", downVal) {
					return nil, fmt.Errorf("policy conflict on 'value' operator")
				}
			}
			result["value"] = downVal
		case "add":
			result["add"] = unionStringSlicesM(toStringSliceM(result["add"]), toStringSliceM(downVal))
		case "default":
			if _, hasValue := result["value"]; !hasValue {
				result["default"] = downVal
			}
		case "subset_of":
			if upVal, exists := result["subset_of"]; exists {
				up, down := toStringSliceM(upVal), toStringSliceM(downVal)
				inter := intersectStringSlicesM(up, down)
				if len(up) > 0 && len(down) > 0 && len(inter) == 0 {
					return nil, fmt.Errorf("policy conflict: subset_of intersection is empty")
				}
				result["subset_of"] = inter
			} else {
				result["subset_of"] = toStringSliceM(downVal)
			}
		case "superset_of":
			result["superset_of"] = unionStringSlicesM(toStringSliceM(result["superset_of"]), toStringSliceM(downVal))
		case "one_of":
			if upVal, exists := result["one_of"]; exists {
				up, down := toStringSliceM(upVal), toStringSliceM(downVal)
				inter := intersectStringSlicesM(up, down)
				if len(up) > 0 && len(down) > 0 && len(inter) == 0 {
					return nil, fmt.Errorf("policy conflict: one_of intersection is empty")
				}
				result["one_of"] = inter
			} else {
				result["one_of"] = toStringSliceM(downVal)
			}
		case "essential":
			if upEss, ok := result["essential"].(bool); ok && upEss {
				result["essential"] = true
			} else {
				result["essential"] = downVal
			}
		default:
			result[op] = downVal
		}
	}
	return result, nil
}

func applyPolicyMap(metadata, policy map[string]interface{}) (map[string]interface{}, error) {
	result := deepCopyAnyMap(metadata)
	if result == nil {
		result = make(map[string]interface{})
	}
	for entityType, rawClaimPolicy := range policy {
		claimPolicy, ok := rawClaimPolicy.(map[string]interface{})
		if !ok {
			continue
		}
		var entityMeta map[string]interface{}
		if em, ok := result[entityType].(map[string]interface{}); ok {
			entityMeta = deepCopyAnyMap(em)
		} else {
			entityMeta = make(map[string]interface{})
		}
		applied, err := applyClaimPolicy(entityMeta, claimPolicy, entityType)
		if err != nil {
			return nil, err
		}
		result[entityType] = applied
	}
	return result, nil
}

func applyClaimPolicy(metadata, claimPolicy map[string]interface{}, entityType string) (map[string]interface{}, error) {
	result := deepCopyAnyMap(metadata)
	if result == nil {
		result = make(map[string]interface{})
	}
	for claimName, rawOps := range claimPolicy {
		ops, ok := rawOps.(map[string]interface{})
		if !ok {
			continue
		}
		if val, ok := ops["value"]; ok {
			result[claimName] = val
			continue
		}
		if addRaw, ok := ops["add"]; ok {
			result[claimName] = unionStringSlicesM(toStringSliceM(result[claimName]), toStringSliceM(addRaw))
		}
		if defVal, ok := ops["default"]; ok {
			if _, exists := result[claimName]; !exists {
				result[claimName] = defVal
			}
		}
		if subRaw, ok := ops["subset_of"]; ok {
			if current, exists := result[claimName]; exists {
				result[claimName] = intersectStringSlicesM(toStringSliceM(current), toStringSliceM(subRaw))
			}
		}
		if oneRaw, ok := ops["one_of"]; ok {
			if current, exists := result[claimName]; exists {
				if currentStr, ok := current.(string); ok {
					allowed := toStringSliceM(oneRaw)
					found := false
					for _, a := range allowed {
						if a == currentStr {
							found = true
							break
						}
					}
					if !found {
						return nil, fmt.Errorf("metadata_policy: %s.%s value %q is not in one_of %v", entityType, claimName, currentStr, allowed)
					}
				}
			}
		}
		if supRaw, ok := ops["superset_of"]; ok {
			if current, exists := result[claimName]; exists {
				have := map[string]bool{}
				for _, s := range toStringSliceM(current) {
					have[s] = true
				}
				for _, need := range toStringSliceM(supRaw) {
					if !have[need] {
						return nil, fmt.Errorf("metadata_policy: %s.%s does not satisfy superset_of (missing %q)", entityType, claimName, need)
					}
				}
			}
		}
		if ess, ok := ops["essential"].(bool); ok && ess {
			if _, exists := result[claimName]; !exists {
				return nil, fmt.Errorf("metadata_policy: %s.%s is essential but missing", entityType, claimName)
			}
		}
	}
	return result, nil
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
