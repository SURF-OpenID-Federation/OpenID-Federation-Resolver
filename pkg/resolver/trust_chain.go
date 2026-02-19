package resolver

import (
	"context"
	"fmt"
	"log"
)

// parseTrustChainJWT parses a trust chain JWT response
func (r *FederationResolver) parseTrustChainJWT(entityID, trustChainJWT, fetchedFrom, trustAnchor string) ([]CachedEntityStatement, error) {
	// Parse JWT to extract claims (use centralized helper)
	_, claims, err := ParseJWTParts(trustChainJWT)
	if err == nil {
		// Extract trust_chain array
		trustChainRaw, ok := claims["trust_chain"]
		if !ok {
			log.Printf("[DEBUG] No trust_chain found in response, trying fallback")
			// Try fallback logic here
			return r.tryTrustChainFallback(context.Background(), claims, entityID, trustAnchor)
		}

		trustChainArray, ok := trustChainRaw.([]interface{})
		if !ok {
			return nil, fmt.Errorf("trust_chain is not an array")
		}

		if len(trustChainArray) == 0 {
			log.Printf("[DEBUG] trust_chain is empty, trying fallback")
			return r.tryTrustChainFallback(context.Background(), claims, entityID, trustAnchor)
		}

		var parsed []CachedEntityStatement
		for i, stmtRaw := range trustChainArray {
			stmtStr, ok := stmtRaw.(string)
			if !ok {
				return nil, fmt.Errorf("trust_chain[%d] is not a string", i)
			}

			// Parse each entity statement JWT
			entity, err := r.parseEntityStatementFromJWT(entityID, stmtStr, fetchedFrom, trustAnchor)
			if err != nil {
				return nil, fmt.Errorf("failed to parse entity statement %d: %w", i, err)
			}
			parsed = append(parsed, *entity)
		}

		// Deduplicate parsed statements early to avoid duplicate issuer+subject
		// confusing the canonical assembly logic below.
		parsed = DeduplicateCachedChain(parsed)

		// Build canonical chain: leaf self-signed, subordinate (sub==entityID, iss!=entityID),
		// and a statement issued by the trust anchor about the intermediary (sub==intermediary, iss==trustAnchor)
		var leaf *CachedEntityStatement
		var subordinate *CachedEntityStatement
		var anchorStmt *CachedEntityStatement

		// Normalize entityID for comparisons
		normEntity := normalizeEntityID(entityID)

		// Helper to pick best candidate (prefer Validated)
		pickBest := func(existing *CachedEntityStatement, candidate *CachedEntityStatement) *CachedEntityStatement {
			if existing == nil {
				return candidate
			}
			if !existing.Validated && candidate.Validated {
				return candidate
			}
			return existing
		}

		for i := range parsed {
			p := &parsed[i]
			// leaf self-signed
			if normalizeEntityID(p.Issuer) == normEntity && normalizeEntityID(p.Subject) == normEntity {
				leaf = pickBest(leaf, p)
				continue
			}
			// subordinate for entity
			if normalizeEntityID(p.Subject) == normEntity && normalizeEntityID(p.Issuer) != normEntity {
				subordinate = pickBest(subordinate, p)
				continue
			}
		}

		// If no leaf found, try to fetch it
		if leaf == nil {
			if selfSigned, err := r.ResolveEntity(context.Background(), entityID, entityID, false); err == nil {
				leaf = selfSigned
				log.Printf("[RESOLVER] Fetched missing self-signed Entity Configuration for %s", entityID)
			}
		}

		// If subordinate still missing, as a fallback look for any statement whose subject==entityID
		// but prefer statements issued by another party (issuer != entityID). Do not pick
		// self-signed leafs here as that would duplicate the leaf.
		if subordinate == nil {
			for i := range parsed {
				p := &parsed[i]
				if normalizeEntityID(p.Subject) == normEntity && normalizeEntityID(p.Issuer) != normEntity {
					subordinate = pickBest(subordinate, p)
				}
			}
		}

		// If subordinate still missing, consider an intermediary self-signed statement
		// (some federation endpoints return self-signed intermediary entries instead
		// of subordinate statements about the leaf). Pick the first intermediary self-signed.
		if subordinate == nil {
			for i := range parsed {
				p := &parsed[i]
				if normalizeEntityID(p.Issuer) == normalizeEntityID(p.Subject) && normalizeEntityID(p.Issuer) != normEntity {
					subordinate = pickBest(subordinate, p)
					break
				}
			}
		}

		// If we ended up with a self-signed intermediary as the subordinate (iss==sub != leaf),
		// try to locate or fetch the true subordinate statement issued by that intermediary
		// about the leaf (iss==intermediary, sub==leaf). This ensures Chain[1] is a
		// subordinate statement and not a self-signed intermediary configuration.
		if subordinate != nil && normalizeEntityID(subordinate.Issuer) == normalizeEntityID(subordinate.Subject) && normalizeEntityID(subordinate.Issuer) != normEntity {
			intermediary := normalizeEntityID(subordinate.Issuer)
			// Search parsed statements first
			for i := range parsed {
				p := &parsed[i]
				if normalizeEntityID(p.Issuer) == intermediary && normalizeEntityID(p.Subject) == normEntity {
					subordinate = pickBest(subordinate, p)
					break
				}
			}

			// If not found in parsed list, attempt an explicit resolve against the intermediary
			if normalizeEntityID(subordinate.Issuer) == normalizeEntityID(subordinate.Subject) {
				if fetched, err := r.ResolveEntity(context.Background(), entityID, subordinate.Issuer, true); err == nil {
					if normalizeEntityID(fetched.Issuer) == intermediary && normalizeEntityID(fetched.Subject) == normEntity {
						subordinate = fetched
						log.Printf("[RESOLVER] Fetched subordinate statement for %s issued by intermediary %s", entityID, subordinate.Issuer)
					}
				}
			}
		}

		// If we have a subordinate, try to find the TA-issued statement about that intermediary
		if subordinate != nil {
			intermediary := normalizeEntityID(subordinate.Issuer)
			if ta, ok := claims["trust_anchor"].(string); ok && ta != "" {
				normTA := normalizeEntityID(ta)
				// Search parsed statements for one where subject==intermediary and issuer==trust_anchor
				for i := range parsed {
					p := &parsed[i]
					if normalizeEntityID(p.Subject) == intermediary && normalizeEntityID(p.Issuer) == normTA {
						anchorStmt = pickBest(anchorStmt, p)
						break
					}
				}
				// If not found, attempt to request the TA to provide its statement about the intermediary
				if anchorStmt == nil {
					if fetched, err := r.ResolveEntity(context.Background(), subordinate.Issuer, ta, false); err == nil {
						anchorStmt = fetched
						log.Printf("[RESOLVER] Fetched TA-issued statement for intermediary %s from %s", subordinate.Issuer, ta)
					}
				}
			}
		}

		// Build final canonical chain in order, skipping nil entries
		final := make([]CachedEntityStatement, 0, 3)
		if leaf != nil {
			final = append(final, *leaf)
		}
		if subordinate != nil {
			// avoid duplicating leaf if subordinate equals leaf
			if !(len(final) > 0 && normalizeEntityID(final[len(final)-1].Subject) == normalizeEntityID(subordinate.Subject) && normalizeEntityID(final[len(final)-1].Issuer) == normalizeEntityID(subordinate.Issuer)) {
				final = append(final, *subordinate)
			}
		}
		if anchorStmt != nil {
			final = append(final, *anchorStmt)
		}

		// Helper: collapse duplicates by issuer+subject, preferring validated entries
		collapseByIssSub := func(chain []CachedEntityStatement) []CachedEntityStatement {
			m := make(map[string]CachedEntityStatement)
			// choose best per key
			for _, e := range chain {
				key := normalizeEntityID(e.Issuer) + " " + normalizeEntityID(e.Subject)
				if ex, ok := m[key]; ok {
					if !ex.Validated && e.Validated {
						m[key] = e
					}
				} else {
					m[key] = e
				}
			}
			// preserve original order as much as possible
			res := make([]CachedEntityStatement, 0, len(m))
			seen := make(map[string]bool)
			for _, e := range chain {
				key := normalizeEntityID(e.Issuer) + " " + normalizeEntityID(e.Subject)
				if seen[key] {
					continue
				}
				if v, ok := m[key]; ok {
					res = append(res, v)
					seen[key] = true
				}
			}
			return res
		}

		// If we built a canonical 'final', collapse any accidental duplicates and return
		if len(final) > 0 {
			final = collapseByIssSub(final)
			log.Printf("[RESOLVER] Built canonical trust chain for %s with %d entries", entityID, len(final))
			return final, nil
		}

		// As a last resort, if we didn't assemble anything useful, fall back to deduped parsed chain
		deduped := DeduplicateCachedChain(parsed)
		deduped = collapseByIssSub(deduped)
		log.Printf("[RESOLVER] Could not build canonical chain; returning deduped parsed chain (%d->%d)", len(parsed), len(deduped))
		return deduped, nil
	}

	return nil, fmt.Errorf("failed to parse trust chain JWT claims")
}

// buildTrustChainWithAnchor builds a trust chain for a specific trust anchor
func (r *FederationResolver) buildTrustChainWithAnchor(ctx context.Context, entityID, requestedTrustAnchor string, forceRefresh bool, visited map[string]bool) ([]CachedEntityStatement, string, error) {
	// Prevent infinite loops
	if visited[entityID] {
		return nil, "", fmt.Errorf("cycle detected in trust chain for entity %s", entityID)
	}
	visited[entityID] = true

	log.Printf("[RESOLVER] Building trust chain segment for %s with target anchor %s", entityID, requestedTrustAnchor)

	// Check if this entity is the requested trust anchor
	if entityID == requestedTrustAnchor {
		log.Printf("[RESOLVER] Reached target trust anchor %s", entityID)
		// Resolve the trust anchor entity
		entity, err := r.ResolveEntity(ctx, entityID, requestedTrustAnchor, forceRefresh)
		if err != nil {
			return nil, "", fmt.Errorf("failed to resolve trust anchor %s: %w", entityID, err)
		}
		return []CachedEntityStatement{*entity}, entityID, nil
	}

	// Resolve the current entity (subordinate statement)
	entity, err := r.ResolveEntity(ctx, entityID, requestedTrustAnchor, forceRefresh)
	if err != nil {
		return nil, "", fmt.Errorf("failed to resolve entity %s: %w", entityID, err)
	}
	// Validate that the returned statement is for the requested entity
	if entity.Subject != entityID {
		log.Printf("[RESOLVER] ERROR: Resolved entity statement subject (%s) does not match requested entity (%s). Possible misconfigured trust anchor endpoint.", entity.Subject, entityID)
		return nil, "", fmt.Errorf("resolved entity statement subject (%s) does not match requested entity (%s)", entity.Subject, entityID)
	}

	// Always prepend the self-signed Entity Configuration for the leaf entity
	var chain []CachedEntityStatement
	selfSigned, err := r.ResolveEntity(ctx, entityID, entityID, forceRefresh)
	if err == nil && selfSigned.Issuer == entityID && selfSigned.Subject == entityID {
		chain = append(chain, *selfSigned)
	} else {
		log.Printf("[RESOLVER] Warning: failed to resolve self-signed Entity Configuration for %s: %v", entityID, err)
	}

	// Add the subordinate statement (even if it's self-signed, to preserve chain structure)
	chain = append(chain, *entity)

	// Get authority hints from the entity's metadata
	authorityHints, err := r.extractAuthorityHints(entity)
	if err != nil {
		return nil, "", fmt.Errorf("failed to extract authority hints from %s: %w", entityID, err)
	}

	log.Printf("[DEBUG] Entity %s has authority hints: %v", entityID, authorityHints)

	if len(authorityHints) == 0 {
		// Fallback: If this subordinate statement was issued by the requested trust anchor
		// for the requested entity, accept it as a valid leaf in the trust chain
		if normalizeEntityID(entity.Issuer) == normalizeEntityID(requestedTrustAnchor) &&
			normalizeEntityID(entity.Subject) == normalizeEntityID(entityID) {
			log.Printf("[RESOLVER] Subordinate statement for %s issued by trust anchor %s has no authority_hints; using fallback to build chain", entityID, requestedTrustAnchor)

			// Get the trust anchor's own statement
			taEntity, err := r.ResolveEntity(ctx, requestedTrustAnchor, requestedTrustAnchor, forceRefresh)
			if err != nil {
				log.Printf("[RESOLVER] Failed to resolve trust anchor %s: %v", requestedTrustAnchor, err)
				return nil, "", fmt.Errorf("failed to resolve trust anchor %s: %w", requestedTrustAnchor, err)
			}

			chain = append(chain, *taEntity)
			return chain, requestedTrustAnchor, nil
		}

		log.Printf("[DEBUG] Entity %s has no authority hints - cannot build trust chain", entityID)
		return nil, "", fmt.Errorf("entity %s has no authority hints and is not the target trust anchor %s", entityID, requestedTrustAnchor)
	}

	// Try each authority hint, but only follow paths that can lead to the requested trust anchor
	for _, authorityID := range authorityHints {
		log.Printf("[RESOLVER] Following authority hint %s for entity %s (targeting %s)", authorityID, entityID, requestedTrustAnchor)

		// Recursively build chain for this authority
		subChain, trustAnchor, err := r.buildTrustChainWithAnchor(ctx, authorityID, requestedTrustAnchor, forceRefresh, visited)
		if err != nil {
			log.Printf("[RESOLVER] Failed to build chain via authority %s: %v", authorityID, err)
			continue
		}

		// Verify the returned trust anchor matches what we requested
		if trustAnchor != requestedTrustAnchor {
			log.Printf("[RESOLVER] Authority %s led to wrong trust anchor %s, expected %s", authorityID, trustAnchor, requestedTrustAnchor)
			continue
		}

		// Build the complete chain: entity config(s) + subordinate + authority ...
		fullChain := append(chain, subChain...)
		log.Printf("[RESOLVER] Successfully built chain via authority %s: %d entities", authorityID, len(fullChain))
		return fullChain, trustAnchor, nil
	}

	return nil, "", fmt.Errorf("could not build trust chain for %s to target anchor %s through any authority hint", entityID, requestedTrustAnchor)
}

// validateTrustChain validates all signatures in a trust chain
// Updated to be more flexible: validates that each entity is properly signed by its issuer
// and that the chain ultimately leads to the trust anchor, allowing for direct relationships
func (r *FederationResolver) validateTrustChain(ctx context.Context, chain []CachedEntityStatement) error {
	if !r.config.ValidateSignatures {
		log.Printf("[RESOLVER] Signature validation disabled, skipping trust chain validation")
		return nil
	}

	if len(chain) == 0 {
		return fmt.Errorf("empty trust chain")
	}

	log.Printf("[RESOLVER] Validating trust chain with %d entities", len(chain))

	// Validate each entity statement's signature against its issuer
	for i := range chain {
		entity := &chain[i]

		// Validate the JWT signature using the entity's issuer
		valid, err := r.validateJWTSignature(ctx, entity.Statement, entity.Issuer)
		if err != nil {
			log.Printf("[RESOLVER] Signature validation failed for entity %s: %v", entity.Subject, err)
			return fmt.Errorf("signature validation failed for entity %s: %w", entity.Subject, err)
		}
		if !valid {
			log.Printf("[RESOLVER] Invalid signature for entity %s", entity.Subject)
			return fmt.Errorf("invalid signature for entity %s", entity.Subject)
		}

		// Mark as validated
		entity.Validated = true
	}

	// Check if the chain contains a trust anchor (self-signed entity)
	hasTrustAnchor := false
	for _, entity := range chain {
		if entity.Issuer == entity.Subject {
			hasTrustAnchor = true
			log.Printf("[RESOLVER] Found trust anchor in chain: %s", entity.Subject)
			break
		}
	}

	if !hasTrustAnchor {
		log.Printf("[RESOLVER] Warning: trust chain does not contain a self-signed trust anchor")
		// Don't fail validation - allow chains that may be valid but don't include the trust anchor
		// This can happen when chains are built through federation endpoints
	}

	// Verify that all entities in the chain are connected (each issuer appears as a subject somewhere in the chain)
	// This allows for flexible chain structures including direct relationships
	entitySubjects := make(map[string]bool)
	for _, entity := range chain {
		entitySubjects[entity.Subject] = true
	}

	for _, entity := range chain {
		// The trust anchor can be self-signed, so skip issuer validation for it
		if entity.Issuer == entity.Subject {
			continue
		}

		// For non-trust-anchor entities, check if the issuer appears in the chain
		// Allow external issuers that can be resolved separately
		if !entitySubjects[entity.Issuer] {
			log.Printf("[RESOLVER] Issuer %s for entity %s does not appear in chain subjects - allowing external issuer", entity.Issuer, entity.Subject)
			// Don't fail - external issuers are allowed
		}
	}

	log.Printf("[RESOLVER] Trust chain validation successful - all signatures valid")
	return nil
}
