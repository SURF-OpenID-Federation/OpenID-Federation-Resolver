package resolver

import (
	"context"
	"fmt"
	"log"
)

// parseTrustChainJWT parses a trust chain JWT response
func (r *FederationResolver) parseTrustChainJWT(ctx context.Context, entityID, trustChainJWT, fetchedFrom, trustAnchor string) ([]CachedEntityStatement, error) {
	// Parse JWT to extract claims (use centralized helper)
	_, claims, err := ParseJWTParts(trustChainJWT)
	if err == nil {
		// Extract trust_chain array
		trustChainRaw, ok := claims["trust_chain"]
		if !ok {
			log.Printf("[DEBUG] No trust_chain found in response, trying fallback")
			// Try fallback logic here
			return r.tryTrustChainFallback(ctx, claims, entityID, trustAnchor)
		}

		trustChainArray, ok := trustChainRaw.([]interface{})
		if !ok {
			return nil, fmt.Errorf("trust_chain is not an array")
		}

		if len(trustChainArray) == 0 {
			log.Printf("[DEBUG] trust_chain is empty, trying fallback")
			return r.tryTrustChainFallback(ctx, claims, entityID, trustAnchor)
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

		// Diagnostic: log parsed trust_chain entries for debugging
		for i := range parsed {
			p := &parsed[i]
			log.Printf("[RESOLVER][DIAG] Parsed trust_chain[%d]: Issuer=%s Subject=%s TrustAnchor=%s Validated=%v FetchedFrom=%s",
				i, p.Issuer, p.Subject, p.TrustAnchor, p.Validated, p.FetchedFrom)
		}

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
			if selfSigned, err := r.ResolveEntity(ctx, entityID, entityID, false); err == nil {
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
				log.Printf("[RESOLVER][DIAG] Attempting explicit subordinate fetch: ResolveEntity(entity=%s, trustAnchor=%s, forceRefresh=true)", entityID, subordinate.Issuer)
				fetched, err := r.ResolveEntity(ctx, entityID, subordinate.Issuer, true)
				if err != nil {
					log.Printf("[RESOLVER][DIAG] Explicit subordinate fetch failed from %s for %s: %v", subordinate.Issuer, entityID, err)
				} else {
					log.Printf("[RESOLVER][DIAG] Explicit subordinate fetch response from %s: Issuer=%s Subject=%s StatementLen=%d", subordinate.Issuer, fetched.Issuer, fetched.Subject, len(fetched.Statement))
					if normalizeEntityID(fetched.Issuer) == intermediary && normalizeEntityID(fetched.Subject) == normEntity {
						subordinate = fetched
						log.Printf("[RESOLVER] Fetched subordinate statement for %s issued by intermediary %s", entityID, subordinate.Issuer)
					}
				}
			}
		}

		// Prefer trust_anchor from the resolve-response; fall back to the request parameter.
		normTA := normalizeEntityID(trustAnchor)
		if ta, ok := claims["trust_anchor"].(string); ok && ta != "" {
			normTA = normalizeEntityID(ta)
		}

		// If we have a subordinate, try to find the TA-issued statement about that intermediary
		if subordinate != nil && normTA != "" {
			intermediary := normalizeEntityID(subordinate.Issuer)
			if intermediary != normTA {
				// Search parsed statements for one where subject==intermediary and issuer==trust_anchor
				for i := range parsed {
					p := &parsed[i]
					if normalizeEntityID(p.Subject) == intermediary && normalizeEntityID(p.Issuer) == normTA &&
						normalizeEntityID(p.Issuer) != normalizeEntityID(p.Subject) {
						anchorStmt = pickBest(anchorStmt, p)
						break
					}
				}
				// Prefer explicit /fetch over ResolveEntity (which often returns the intermediary EC)
				if anchorStmt == nil {
					if fetched, err := r.FetchSubordinateStatement(ctx, normTA, intermediary); err == nil {
						anchorStmt = fetched
						log.Printf("[RESOLVER] Fetched TA-issued subordinate for intermediary %s via /fetch", intermediary)
					} else {
						log.Printf("[RESOLVER] /fetch of TA→%s failed: %v", intermediary, err)
					}
				}
			}
		}

		// Keep the leaf EC plus every subordinate from the resolve payload
		// (including TA→intermediary). Do not drop extra hops just because
		// the 3-slot picker above only named one subordinate / one TA stmt.
		final := make([]CachedEntityStatement, 0, len(parsed)+3)
		appendUnique := func(stmt *CachedEntityStatement) {
			if stmt == nil {
				return
			}
			iss := normalizeEntityID(stmt.Issuer)
			sub := normalizeEntityID(stmt.Subject)
			for _, e := range final {
				if normalizeEntityID(e.Issuer) == iss && normalizeEntityID(e.Subject) == sub {
					return
				}
			}
			final = append(final, *stmt)
		}
		appendUnique(leaf)
		appendUnique(subordinate)
		appendUnique(anchorStmt)
		for i := range parsed {
			p := &parsed[i]
			iss := normalizeEntityID(p.Issuer)
			sub := normalizeEntityID(p.Subject)
			if iss == sub && iss != normEntity && (normTA == "" || iss != normTA) {
				// Drop intermediary Entity Configurations; they are not part of §4.
				continue
			}
			appendUnique(p)
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

		// If we built a canonical 'final', collapse duplicates and complete to the TA
		if len(final) > 0 {
			final = collapseByIssSub(final)
			if normTA != "" {
				completed, cerr := r.completeChainToTrustAnchor(ctx, final, entityID, normTA)
				if cerr != nil {
					return nil, fmt.Errorf("incomplete trust chain from resolve response: %w", cerr)
				}
				final = completed
			}
			log.Printf("[RESOLVER] Built canonical trust chain for %s with %d entries", entityID, len(final))
			return final, nil
		}

		// As a last resort, complete the deduped parsed chain to the TA
		deduped := DeduplicateCachedChain(parsed)
		deduped = collapseByIssSub(deduped)
		if normTA != "" && len(deduped) > 0 {
			completed, cerr := r.completeChainToTrustAnchor(ctx, deduped, entityID, normTA)
			if cerr != nil {
				return nil, fmt.Errorf("incomplete trust chain from resolve response: %w", cerr)
			}
			log.Printf("[RESOLVER] Completed fallback parsed chain for %s with %d entries", entityID, len(completed))
			return completed, nil
		}
		log.Printf("[RESOLVER] Could not build canonical chain; returning deduped parsed chain (%d->%d)", len(parsed), len(deduped))
		return deduped, nil
	}

	return nil, fmt.Errorf("failed to parse trust chain JWT claims")
}

// completeChainToTrustAnchor ensures a partial chain is rooted at trustAnchor:
//
//	[EC_leaf, SubStmt(superior→leaf), ..., SubStmt(TA→next), EC_TA]
//
// Missing SubStmt(TA→intermediary) statements are fetched via /fetch.
// Missing TA Entity Configuration is fetched from the TA well-known endpoint.
func (r *FederationResolver) completeChainToTrustAnchor(ctx context.Context, chain []CachedEntityStatement, leafID, trustAnchor string) ([]CachedEntityStatement, error) {
	normTA := normalizeEntityID(trustAnchor)
	normLeaf := normalizeEntityID(leafID)
	if normTA == "" {
		return nil, fmt.Errorf("trust anchor is required")
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("empty chain")
	}

	out := append([]CachedEntityStatement(nil), chain...)

	if err := r.appendMissingHopsToTA(ctx, &out, normLeaf, normTA); err != nil {
		return nil, err
	}

	if !chainHasTAEC(out, normTA) {
		taEC, err := r.tryDirectResolve(ctx, trustAnchor)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch trust anchor EC %s: %w", trustAnchor, err)
		}
		if normalizeEntityID(taEC.Issuer) != normTA || normalizeEntityID(taEC.Subject) != normTA {
			return nil, fmt.Errorf("trust anchor EC is not self-signed for %s", trustAnchor)
		}
		out = append(out, *taEC)
		log.Printf("[RESOLVER] Completed chain with TA Entity Configuration %s", trustAnchor)
	}

	if !isChainRootedAtTA(out, normLeaf, normTA) {
		return nil, fmt.Errorf("completed chain for %s still does not reach trust anchor %s", leafID, trustAnchor)
	}

	return out, nil
}

// appendMissingHopsToTA adds subordinate statements from the highest known issuer
// up to trustAnchor. Prefer TA /fetch of the current top entity so completion
// does not depend on the intermediary's well-known endpoint.
func (r *FederationResolver) appendMissingHopsToTA(ctx context.Context, out *[]CachedEntityStatement, leafID, trustAnchor string) error {
	if parentIssuer(*out, leafID) == "" && !chainHasSelfSigned(*out, leafID) {
		return fmt.Errorf("cannot determine superior of leaf %s to complete chain to %s", leafID, trustAnchor)
	}

	current := highestKnownIssuer(*out, leafID, trustAnchor)
	if current == "" {
		current = leafID
	}
	if current == trustAnchor {
		return nil
	}

	// Fast path: requested TA may issue a subordinate about the current top
	// (typical RP → intermediary → TA). This only needs the TA fetch endpoint.
	if !hasSubordinate(*out, trustAnchor, current) {
		if fetched, err := r.FetchSubordinateStatement(ctx, trustAnchor, current); err == nil {
			*out = append(*out, *fetched)
			log.Printf("[RESOLVER] Completed chain with subordinate %s→%s via TA /fetch", trustAnchor, current)
			return nil
		} else {
			log.Printf("[RESOLVER] TA /fetch %s→%s failed: %v; walking authority_hints", trustAnchor, current, err)
		}
	} else {
		return nil
	}

	visited := map[string]bool{leafID: true}
	for steps := 0; steps < 16; steps++ {
		if current == "" {
			return fmt.Errorf("empty superior while completing chain to %s", trustAnchor)
		}
		if current == trustAnchor {
			return nil
		}
		if visited[current] {
			return fmt.Errorf("cycle while completing chain at %s", current)
		}
		visited[current] = true

		if !hasSubordinate(*out, trustAnchor, current) {
			if fetched, err := r.FetchSubordinateStatement(ctx, trustAnchor, current); err == nil {
				*out = append(*out, *fetched)
				log.Printf("[RESOLVER] Completed chain with subordinate %s→%s via TA /fetch", trustAnchor, current)
				return nil
			}
		}

		ec, err := r.tryDirectResolve(ctx, current)
		if err != nil {
			return fmt.Errorf("failed to resolve entity configuration for %s: %w", current, err)
		}
		hints, err := r.extractAuthorityHints(ec)
		if err != nil {
			return fmt.Errorf("failed to extract authority_hints from %s: %w", current, err)
		}
		if len(hints) == 0 {
			return fmt.Errorf("entity %s has no authority_hints; cannot reach trust anchor %s", current, trustAnchor)
		}

		superior := pickAuthorityTowardTA(hints, trustAnchor)
		if !hasSubordinate(*out, superior, current) {
			subStmt, ferr := r.FetchSubordinateStatement(ctx, superior, current)
			if ferr != nil {
				if fetched, rerr := r.ResolveEntity(ctx, current, superior, true); rerr == nil &&
					normalizeEntityID(fetched.Issuer) == normalizeEntityID(superior) &&
					normalizeEntityID(fetched.Subject) == current &&
					normalizeEntityID(fetched.Issuer) != normalizeEntityID(fetched.Subject) {
					subStmt = fetched
				} else {
					return fmt.Errorf("failed to fetch subordinate statement %s→%s: %w", superior, current, ferr)
				}
			}
			*out = append(*out, *subStmt)
			log.Printf("[RESOLVER] Completed chain with subordinate %s→%s", superior, current)
		}
		current = normalizeEntityID(superior)
	}

	if current != trustAnchor {
		return fmt.Errorf("could not reach trust anchor %s while completing chain", trustAnchor)
	}
	return nil
}

func hasSubordinate(chain []CachedEntityStatement, issuer, subject string) bool {
	iss := normalizeEntityID(issuer)
	sub := normalizeEntityID(subject)
	for _, e := range chain {
		if normalizeEntityID(e.Issuer) == iss &&
			normalizeEntityID(e.Subject) == sub &&
			normalizeEntityID(e.Issuer) != normalizeEntityID(e.Subject) {
			return true
		}
	}
	return false
}

func chainHasSelfSigned(chain []CachedEntityStatement, entityID string) bool {
	id := normalizeEntityID(entityID)
	for _, e := range chain {
		if normalizeEntityID(e.Issuer) == id && normalizeEntityID(e.Subject) == id {
			return true
		}
	}
	return false
}

func parentIssuer(chain []CachedEntityStatement, subject string) string {
	sub := normalizeEntityID(subject)
	for _, e := range chain {
		if normalizeEntityID(e.Subject) == sub && normalizeEntityID(e.Issuer) != sub {
			return normalizeEntityID(e.Issuer)
		}
	}
	return ""
}

// highestKnownIssuer walks existing subordinates from the leaf toward the TA
// and returns the top-most issuer already present in the chain.
func highestKnownIssuer(chain []CachedEntityStatement, leafID, trustAnchor string) string {
	current := normalizeEntityID(leafID)
	ta := normalizeEntityID(trustAnchor)
	seen := map[string]bool{}
	for i := 0; i < 16; i++ {
		if current == ta || seen[current] {
			return current
		}
		seen[current] = true
		parent := parentIssuer(chain, current)
		if parent == "" {
			return current
		}
		current = parent
	}
	return current
}

// isChainRootedAtTA reports whether subordinate statements connect leafID up to trustAnchor
// and the trust anchor Entity Configuration is present.
func isChainRootedAtTA(chain []CachedEntityStatement, leafID, trustAnchor string) bool {
	normLeaf := normalizeEntityID(leafID)
	normTA := normalizeEntityID(trustAnchor)
	if !chainHasTAEC(chain, normTA) {
		return false
	}
	current := normLeaf
	for steps := 0; steps < 16; steps++ {
		if current == normTA {
			return true
		}
		next := ""
		for _, e := range chain {
			if normalizeEntityID(e.Subject) == current && normalizeEntityID(e.Issuer) != current {
				next = normalizeEntityID(e.Issuer)
				break
			}
		}
		if next == "" {
			return false
		}
		current = next
	}
	return false
}

func pickAuthorityTowardTA(hints []string, trustAnchor string) string {
	normTA := normalizeEntityID(trustAnchor)
	for _, h := range hints {
		if normalizeEntityID(h) == normTA {
			return normalizeEntityID(h)
		}
	}
	return normalizeEntityID(hints[0])
}

func chainHasTAEC(chain []CachedEntityStatement, trustAnchor string) bool {
	norm := normalizeEntityID(trustAnchor)
	for _, e := range chain {
		if normalizeEntityID(e.Issuer) == norm && normalizeEntityID(e.Subject) == norm {
			return true
		}
	}
	return false
}

// buildTrustChainWithAnchor builds a trust chain for a specific trust anchor
func (r *FederationResolver) buildTrustChainWithAnchor(ctx context.Context, entityID, requestedTrustAnchor string, forceRefresh bool, visited map[string]bool) ([]CachedEntityStatement, string, error) {
	// Prevent infinite loops
	if visited[entityID] {
		return nil, "", fmt.Errorf("cycle detected in trust chain for entity %s", entityID)
	}
	visited[entityID] = true

	log.Printf("[RESOLVER] Building trust chain segment for %s with target anchor %s", entityID, requestedTrustAnchor)

	normEntity := normalizeEntityID(entityID)
	normTA := normalizeEntityID(requestedTrustAnchor)

	// Check if this entity is the requested trust anchor
	if normEntity == normTA {
		log.Printf("[RESOLVER] Reached target trust anchor %s", entityID)
		entity, err := r.tryDirectResolve(ctx, entityID)
		if err != nil {
			return nil, "", fmt.Errorf("failed to resolve trust anchor %s: %w", entityID, err)
		}
		return []CachedEntityStatement{*entity}, entityID, nil
	}

	// Always use the self-signed Entity Configuration for authority_hints
	selfSigned, err := r.tryDirectResolve(ctx, entityID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to resolve Entity Configuration for %s: %w", entityID, err)
	}
	if normalizeEntityID(selfSigned.Issuer) != normEntity || normalizeEntityID(selfSigned.Subject) != normEntity {
		return nil, "", fmt.Errorf("Entity Configuration for %s is not self-signed (iss=%s sub=%s)", entityID, selfSigned.Issuer, selfSigned.Subject)
	}

	authorityHints, err := r.extractAuthorityHints(selfSigned)
	if err != nil {
		return nil, "", fmt.Errorf("failed to extract authority hints from %s: %w", entityID, err)
	}
	if len(authorityHints) == 0 {
		return nil, "", fmt.Errorf("entity %s has no authority hints and is not the target trust anchor %s", entityID, requestedTrustAnchor)
	}

	log.Printf("[DEBUG] Entity %s has authority hints: %v", entityID, authorityHints)

	// Prefer the requested TA when listed; otherwise try each hint
	orderedHints := make([]string, 0, len(authorityHints))
	if pick := pickAuthorityTowardTA(authorityHints, requestedTrustAnchor); pick != "" {
		orderedHints = append(orderedHints, pick)
	}
	for _, h := range authorityHints {
		if normalizeEntityID(h) != normalizeEntityID(orderedHints[0]) {
			orderedHints = append(orderedHints, h)
		}
	}

	for _, authorityID := range orderedHints {
		log.Printf("[RESOLVER] Following authority hint %s for entity %s (targeting %s)", authorityID, entityID, requestedTrustAnchor)

		// Prefer /fetch for the subordinate statement parent→child
		var subStmt *CachedEntityStatement
		if fetched, ferr := r.FetchSubordinateStatement(ctx, authorityID, entityID); ferr == nil {
			subStmt = fetched
		} else {
			log.Printf("[RESOLVER] /fetch %s→%s failed (%v); trying ResolveEntity", authorityID, entityID, ferr)
			resolved, rerr := r.ResolveEntity(ctx, entityID, authorityID, forceRefresh)
			if rerr != nil {
				log.Printf("[RESOLVER] ResolveEntity also failed for %s via %s: %v", entityID, authorityID, rerr)
				continue
			}
			// Accept only a real subordinate (iss==authority, sub==entity)
			if normalizeEntityID(resolved.Issuer) == normalizeEntityID(authorityID) &&
				normalizeEntityID(resolved.Subject) == normEntity &&
				normalizeEntityID(resolved.Issuer) != normalizeEntityID(resolved.Subject) {
				subStmt = resolved
			} else if normalizeEntityID(resolved.Subject) == normEntity &&
				normalizeEntityID(resolved.Issuer) != normEntity {
				// Accept any parent-signed subordinate about this entity
				subStmt = resolved
				authorityID = resolved.Issuer
			} else {
				log.Printf("[RESOLVER] ResolveEntity for %s via %s returned non-subordinate iss=%s sub=%s", entityID, authorityID, resolved.Issuer, resolved.Subject)
				continue
			}
		}

		// Recursively build chain for this authority up to the TA
		subChain, trustAnchor, err := r.buildTrustChainWithAnchor(ctx, authorityID, requestedTrustAnchor, forceRefresh, visited)
		if err != nil {
			log.Printf("[RESOLVER] Failed to build chain via authority %s: %v", authorityID, err)
			continue
		}
		if normalizeEntityID(trustAnchor) != normTA {
			log.Printf("[RESOLVER] Authority %s led to wrong trust anchor %s, expected %s", authorityID, trustAnchor, requestedTrustAnchor)
			continue
		}

		// Canonical assembly: EC_leaf + SubStmt(parent→leaf) + (path from parent to TA)
		// Drop intermediate self-signed ECs from subChain except the TA EC at the end.
		fullChain := []CachedEntityStatement{*selfSigned, *subStmt}
		for _, e := range subChain {
			if normalizeEntityID(e.Issuer) == normalizeEntityID(e.Subject) &&
				normalizeEntityID(e.Issuer) != normTA {
				// Skip intermediary Entity Configurations
				continue
			}
			fullChain = append(fullChain, e)
		}

		completed, cerr := r.completeChainToTrustAnchor(ctx, fullChain, entityID, requestedTrustAnchor)
		if cerr != nil {
			log.Printf("[RESOLVER] Chain via %s incomplete: %v", authorityID, cerr)
			continue
		}

		log.Printf("[RESOLVER] Successfully built chain via authority %s: %d entities", authorityID, len(completed))
		return completed, trustAnchor, nil
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
	// Enforce canonical structure: middle elements (neither first nor last)
	// MUST be subordinate statements (iss != sub). If a middle element is
	// self-signed, treat the chain as invalid per spec section 4.
	if len(chain) >= 3 {
		// Derive leaf subject: prefer explicit `Subject`, otherwise fall back to the element's EntityID
		leafSub := ""
		if chain[0].Subject != "" {
			leafSub = normalizeEntityID(chain[0].Subject)
		} else {
			leafSub = normalizeEntityID(chain[0].EntityID)
		}
		for i := 1; i <= len(chain)-2; i++ {
			if normalizeEntityID(chain[i].Issuer) == normalizeEntityID(chain[i].Subject) {
				// Check whether a parent-signed subordinate exists in the chain (must be a subordinate: iss != sub)
				subFound := false
				subIndex := -1
				for j := range chain {
					if normalizeEntityID(chain[j].Issuer) == normalizeEntityID(chain[i].Issuer) && normalizeEntityID(chain[j].Subject) == leafSub {
						// ensure the candidate is a subordinate statement (issuer != subject)
						if normalizeEntityID(chain[j].Issuer) != normalizeEntityID(chain[j].Subject) {
							subFound = true
							subIndex = j
							break
						}
					}
				}
				if subFound && subIndex >= 0 {
					log.Printf("[RESOLVER] Found parent-signed subordinate at Chain[%d]; replacing self-statement at Chain[%d] with subordinate at Chain[%d]", subIndex, i, subIndex)
					chain[i] = chain[subIndex]
					// After replacing with a parent-signed subordinate, attempt to fetch/insert a TA-issued subordinate
					// Locate a trust anchor in the chain (last self-signed preferred)
					taIdx := -1
					taID := ""
					for k := len(chain) - 1; k >= 0; k-- {
						if normalizeEntityID(chain[k].Issuer) == normalizeEntityID(chain[k].Subject) {
							taIdx = k
							taID = chain[k].Issuer
							break
						}
					}
					if taIdx >= 0 && taID != "" {
						intermediary := normalizeEntityID(chain[i].Issuer)
						// Check whether a TA-issued subordinate already exists
						exists := false
						for j := range chain {
							if normalizeEntityID(chain[j].Issuer) == normalizeEntityID(taID) && normalizeEntityID(chain[j].Subject) == intermediary {
								exists = true
								break
							}
						}
						if !exists {
							log.Printf("[RESOLVER][DIAG] Attempting to fetch TA-issued subordinate for intermediary %s from TA %s", intermediary, taID)
							fetchedTA, ferr := r.ResolveEntity(ctx, intermediary, taID, false)
							if ferr == nil {
								if normalizeEntityID(fetchedTA.Issuer) == normalizeEntityID(taID) && normalizeEntityID(fetchedTA.Subject) == intermediary && normalizeEntityID(fetchedTA.Issuer) != normalizeEntityID(fetchedTA.Subject) {
									ok, verr := r.validateJWTSignature(ctx, fetchedTA.Statement, fetchedTA.Issuer)
									if verr == nil && ok {
										log.Printf("[RESOLVER] Fetched and validated TA-issued subordinate for intermediary %s from TA %s; inserting before TA at index %d", intermediary, taID, taIdx)
										fetchedTA.Validated = true
										// Insert before taIdx
										newChain := make([]CachedEntityStatement, 0, len(chain)+1)
										newChain = append(newChain, chain[:taIdx]...)
										newChain = append(newChain, *fetchedTA)
										newChain = append(newChain, chain[taIdx:]...)
										chain = newChain
										// No need to continue here; chain modified in place
									} else {
										log.Printf("[RESOLVER][DIAG] Fetched TA subordinate did not validate: err=%v ok=%v", verr, ok)
									}
								} else {
									log.Printf("[RESOLVER][DIAG] Failed to fetch TA subordinate for %s from %s: %v", intermediary, taID, ferr)
								}
							}
						}
						continue
					}

					// If not found in the chain, attempt to explicitly fetch the parent-signed subordinate
					intermediary := normalizeEntityID(chain[i].Issuer)
					log.Printf("[RESOLVER][DIAG] No parent-signed subordinate found in chain for intermediary %s; attempting explicit ResolveEntity(entity=%s, trustAnchor=%s, forceRefresh=true)", intermediary, leafSub, intermediary)
					fetchedSub, ferr := r.ResolveEntity(ctx, leafSub, chain[i].Issuer, true)
					if ferr == nil {
						if normalizeEntityID(fetchedSub.Issuer) == intermediary && normalizeEntityID(fetchedSub.Subject) == leafSub && normalizeEntityID(fetchedSub.Issuer) != normalizeEntityID(fetchedSub.Subject) {
							// Validate the fetched statement's signature
							ok, verr := r.validateJWTSignature(ctx, fetchedSub.Statement, fetchedSub.Issuer)
							if verr == nil && ok {
								log.Printf("[RESOLVER] Fetched and validated parent-signed subordinate for %s issued by %s; inserting into chain", leafSub, fetchedSub.Issuer)
								fetchedSub.Validated = true
								chain[i] = *fetchedSub
								// After inserting with a parent-signed subordinate, attempt to fetch/insert a TA-issued subordinate
								// Locate a trust anchor in the chain (last self-signed preferred)
								taIdx := -1
								taID := ""
								for k := len(chain) - 1; k >= 0; k-- {
									if normalizeEntityID(chain[k].Issuer) == normalizeEntityID(chain[k].Subject) {
										taIdx = k
										taID = chain[k].Issuer
										break
									}
								}
								if taIdx >= 0 && taID != "" {
									intermediary := normalizeEntityID(chain[i].Issuer)
									// Check whether a TA-issued subordinate already exists
									exists := false
									for j := range chain {
										if normalizeEntityID(chain[j].Issuer) == normalizeEntityID(taID) && normalizeEntityID(chain[j].Subject) == intermediary {
											exists = true
											break
										}
									}
									if !exists {
										log.Printf("[RESOLVER][DIAG] Attempting to fetch TA-issued subordinate for intermediary %s from TA %s", intermediary, taID)
										fetchedTA, ferr := r.ResolveEntity(ctx, intermediary, taID, false)
										if ferr == nil {
											if normalizeEntityID(fetchedTA.Issuer) == normalizeEntityID(taID) && normalizeEntityID(fetchedTA.Subject) == intermediary && normalizeEntityID(fetchedTA.Issuer) != normalizeEntityID(fetchedTA.Subject) {
												ok, verr := r.validateJWTSignature(ctx, fetchedTA.Statement, fetchedTA.Issuer)
												if verr == nil && ok {
													log.Printf("[RESOLVER] Fetched and validated TA-issued subordinate for intermediary %s from TA %s; inserting before TA at index %d", intermediary, taID, taIdx)
													fetchedTA.Validated = true
													// Insert before taIdx
													newChain := make([]CachedEntityStatement, 0, len(chain)+1)
													newChain = append(newChain, chain[:taIdx]...)
													newChain = append(newChain, *fetchedTA)
													newChain = append(newChain, chain[taIdx:]...)
													chain = newChain
													// No need to continue here; chain modified in place
												} else {
													log.Printf("[RESOLVER][DIAG] Fetched TA subordinate did not validate: err=%v ok=%v", verr, ok)
												}
											} else {
												log.Printf("[RESOLVER][DIAG] Failed to fetch TA subordinate for %s from %s: %v", intermediary, taID, ferr)
											}
										}
									}
								}
								continue
							}
							log.Printf("[RESOLVER][DIAG] Fetched subordinate did not validate or was not a proper subordinate: err=%v ok=%v", verr, ok)
						}
						log.Printf("[RESOLVER][DIAG] Explicit subordinate fetch failed for intermediary=%s entity=%s: %v", chain[i].Issuer, leafSub, ferr)
					}
					// Dump chain for diagnostics to help match shared validator behavior
					log.Printf("[RESOLVER][DIAG] Middle-element self-statement detected at Chain[%d]; dumping chain:", i)
					for k, ce := range chain {
						log.Printf("[RESOLVER][DIAG] Chain[%d]: Issuer=%s Subject=%s EntityID=%s", k, ce.Issuer, ce.Subject, ce.EntityID)
					}
					return fmt.Errorf("Chain[%d]: \"iss\" equals \"sub\" (\"%s\"). Middle elements MUST be Subordinate Statements", i, chain[i].Issuer)
				}
			}
		}
	}
	log.Printf("[RESOLVER] Trust chain validation successful - all signatures valid")
	return nil
}
