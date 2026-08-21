package resolver

import (
	"context"
	"fmt"
	"log"
)

// parseTrustChainJWT turns a TA /resolve JWT into statements, then completes
// the chain to the trust anchor (fetch missing hops + TA Entity Configuration).
func (r *FederationResolver) parseTrustChainJWT(ctx context.Context, entityID, trustChainJWT, fetchedFrom, trustAnchor string) ([]CachedEntityStatement, error) {
	_, claims, err := ParseJWTParts(trustChainJWT)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trust chain JWT claims")
	}

	trustChainRaw, ok := claims["trust_chain"]
	if !ok {
		log.Printf("[DEBUG] No trust_chain found in response, trying fallback")
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

	// The caller's requested TA is the chain root. A resolve JWT may name a
	// superior (the PoC TA is itself a subordinate of eduGAIN); ignore that.
	normTA := normalizeEntityID(trustAnchor)

	parsed := make([]CachedEntityStatement, 0, len(trustChainArray))
	for i, stmtRaw := range trustChainArray {
		stmtStr, ok := stmtRaw.(string)
		if !ok {
			return nil, fmt.Errorf("trust_chain[%d] is not a string", i)
		}
		entity, err := r.parseEntityStatementFromJWT(entityID, stmtStr, fetchedFrom, trustAnchor)
		if err != nil {
			return nil, fmt.Errorf("failed to parse entity statement %d: %w", i, err)
		}
		parsed = append(parsed, *entity)
	}

	parsed = DeduplicateCachedChain(parsed)
	parsed = dropIntermediaryECs(parsed, entityID, normTA)
	if normTA == "" {
		return parsed, nil
	}
	return r.completeChainToTrustAnchor(ctx, parsed, entityID, normTA)
}

// completeChainToTrustAnchor produces the canonical chain:
//
//	[EC_leaf, SubStmt(superior→leaf), ..., SubStmt(TA→next), EC_TA]
//
// Missing hops are fetched with superior /fetch (TA /fetch first).
// The TA Entity Configuration is fetched from well-known.
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
	out = dropIntermediaryECs(out, normLeaf, normTA)

	if !chainHasSelfSigned(out, normLeaf) {
		leaf, err := r.tryDirectResolve(ctx, leafID)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch leaf Entity Configuration %s: %w", leafID, err)
		}
		out = append([]CachedEntityStatement{*leaf}, out...)
	}

	if err := r.walkFetchToTA(ctx, &out, normLeaf, normTA); err != nil {
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

	out = DeduplicateCachedChain(out)
	out = orderTrustChain(out, normLeaf, normTA)
	if !isChainRootedAtTA(out, normLeaf, normTA) {
		return nil, fmt.Errorf("completed chain for %s still does not reach trust anchor %s", leafID, trustAnchor)
	}
	return out, nil
}

// walkFetchToTA follows authority_hints from the leaf to the TA, fetching a
// Subordinate Statement (iss=parent, sub=child) at each hop. If the requested
// TA already lists the current entity, TA /fetch is used and the walk stops.
func (r *FederationResolver) walkFetchToTA(ctx context.Context, out *[]CachedEntityStatement, leafID, trustAnchor string) error {
	current := leafID
	visited := map[string]bool{}

	for steps := 0; steps < 16; steps++ {
		if current == trustAnchor {
			return nil
		}
		if visited[current] {
			return fmt.Errorf("cycle while completing chain at %s", current)
		}
		visited[current] = true

		if parent := parentIssuer(*out, current); parent != "" {
			current = parent
			continue
		}

		if fetched, err := r.FetchSubordinateStatement(ctx, trustAnchor, current); err == nil &&
			isSubordinateStmt(fetched, trustAnchor, current) {
			*out = append(*out, *fetched)
			log.Printf("[RESOLVER] Completed chain with subordinate %s→%s via TA /fetch", trustAnchor, current)
			current = trustAnchor
			continue
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
		subStmt, err := r.fetchSubordinate(ctx, superior, current)
		if err != nil {
			return err
		}
		*out = append(*out, *subStmt)
		log.Printf("[RESOLVER] Completed chain with subordinate %s→%s", superior, current)
		current = normalizeEntityID(superior)
	}

	if current != trustAnchor {
		return fmt.Errorf("could not reach trust anchor %s", trustAnchor)
	}
	return nil
}

func (r *FederationResolver) fetchSubordinate(ctx context.Context, parentID, childID string) (*CachedEntityStatement, error) {
	if fetched, err := r.FetchSubordinateStatement(ctx, parentID, childID); err == nil {
		return fetched, nil
	} else {
		fetched, rerr := r.ResolveEntity(ctx, childID, parentID, true)
		if rerr == nil && isSubordinateStmt(fetched, parentID, childID) {
			return fetched, nil
		}
		return nil, fmt.Errorf("failed to fetch subordinate statement %s→%s: %w", parentID, childID, err)
	}
}

// buildTrustChainWithAnchor walks authority_hints from entityID to the TA
// (the direct path when TA /resolve is missing or incomplete).
func (r *FederationResolver) buildTrustChainWithAnchor(ctx context.Context, entityID, requestedTrustAnchor string, forceRefresh bool, visited map[string]bool) ([]CachedEntityStatement, string, error) {
	if visited[entityID] {
		return nil, "", fmt.Errorf("cycle detected in trust chain for entity %s", entityID)
	}
	visited[entityID] = true

	log.Printf("[RESOLVER] Building trust chain segment for %s with target anchor %s", entityID, requestedTrustAnchor)

	normEntity := normalizeEntityID(entityID)
	normTA := normalizeEntityID(requestedTrustAnchor)

	if normEntity == normTA {
		entity, err := r.tryDirectResolve(ctx, entityID)
		if err != nil {
			return nil, "", fmt.Errorf("failed to resolve trust anchor %s: %w", entityID, err)
		}
		return []CachedEntityStatement{*entity}, entityID, nil
	}

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

	for _, authorityID := range orderHintsTowardTA(authorityHints, requestedTrustAnchor) {
		log.Printf("[RESOLVER] Following authority hint %s for entity %s (targeting %s)", authorityID, entityID, requestedTrustAnchor)

		subStmt, err := r.fetchSubordinate(ctx, authorityID, entityID)
		if err != nil {
			log.Printf("[RESOLVER] /fetch %s→%s failed: %v", authorityID, entityID, err)
			continue
		}
		authorityID = subStmt.Issuer

		subChain, trustAnchor, err := r.buildTrustChainWithAnchor(ctx, authorityID, requestedTrustAnchor, forceRefresh, visited)
		if err != nil {
			log.Printf("[RESOLVER] Failed to build chain via authority %s: %v", authorityID, err)
			continue
		}
		if normalizeEntityID(trustAnchor) != normTA {
			continue
		}

		fullChain := []CachedEntityStatement{*selfSigned, *subStmt}
		fullChain = append(fullChain, dropIntermediaryECs(subChain, entityID, normTA)...)

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

func (r *FederationResolver) validateTrustChain(ctx context.Context, chain []CachedEntityStatement) error {
	if len(chain) == 0 {
		return fmt.Errorf("empty trust chain")
	}

	if r.config.ValidateSignatures {
		for i := range chain {
			entity := &chain[i]
			valid, err := r.validateJWTSignature(ctx, entity.Statement, entity.Issuer)
			if err != nil {
				return fmt.Errorf("signature validation failed for entity %s: %w", entity.Subject, err)
			}
			if !valid {
				return fmt.Errorf("invalid signature for entity %s", entity.Subject)
			}
			entity.Validated = true
		}
	}

	for i := 1; i < len(chain)-1; i++ {
		if normalizeEntityID(chain[i].Issuer) == normalizeEntityID(chain[i].Subject) {
			return fmt.Errorf("Chain[%d]: \"iss\" equals \"sub\" (%q). Middle elements MUST be Subordinate Statements", i, chain[i].Issuer)
		}
	}

	log.Printf("[RESOLVER] Trust chain validation successful (%d statements)", len(chain))
	return nil
}

func dropIntermediaryECs(chain []CachedEntityStatement, leafID, trustAnchor string) []CachedEntityStatement {
	leaf := normalizeEntityID(leafID)
	ta := normalizeEntityID(trustAnchor)
	out := make([]CachedEntityStatement, 0, len(chain))
	for _, e := range chain {
		iss := normalizeEntityID(e.Issuer)
		sub := normalizeEntityID(e.Subject)
		if iss == sub && iss != leaf && (ta == "" || iss != ta) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func orderTrustChain(chain []CachedEntityStatement, leafID, trustAnchor string) []CachedEntityStatement {
	leaf := normalizeEntityID(leafID)
	ta := normalizeEntityID(trustAnchor)
	byPair := map[string]CachedEntityStatement{}
	for _, e := range chain {
		byPair[normalizeEntityID(e.Issuer)+"|"+normalizeEntityID(e.Subject)] = e
	}

	ordered := make([]CachedEntityStatement, 0, len(chain))
	if ec, ok := byPair[leaf+"|"+leaf]; ok {
		ordered = append(ordered, ec)
	}

	current := leaf
	seen := map[string]bool{leaf: true}
	for i := 0; i < 16; i++ {
		parent := parentIssuer(chain, current)
		if parent == "" {
			break
		}
		if stmt, ok := byPair[parent+"|"+current]; ok {
			ordered = append(ordered, stmt)
		}
		if parent == ta || seen[parent] {
			break
		}
		seen[parent] = true
		current = parent
	}
	if ec, ok := byPair[ta+"|"+ta]; ok {
		ordered = append(ordered, ec)
	}
	if len(ordered) == 0 {
		return chain
	}
	return DeduplicateCachedChain(ordered)
}

func isSubordinateStmt(stmt *CachedEntityStatement, issuer, subject string) bool {
	if stmt == nil {
		return false
	}
	iss := normalizeEntityID(stmt.Issuer)
	sub := normalizeEntityID(stmt.Subject)
	return iss == normalizeEntityID(issuer) && sub == normalizeEntityID(subject) && iss != sub
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
		next := parentIssuer(chain, current)
		if next == "" {
			return false
		}
		current = next
	}
	return false
}

func pickAuthorityTowardTA(hints []string, trustAnchor string) string {
	if len(hints) == 0 {
		return ""
	}
	normTA := normalizeEntityID(trustAnchor)
	for _, h := range hints {
		if normalizeEntityID(h) == normTA {
			return normalizeEntityID(h)
		}
	}
	return normalizeEntityID(hints[0])
}

func orderHintsTowardTA(hints []string, trustAnchor string) []string {
	if len(hints) == 0 {
		return nil
	}
	first := pickAuthorityTowardTA(hints, trustAnchor)
	out := []string{first}
	for _, h := range hints {
		if normalizeEntityID(h) != normalizeEntityID(first) {
			out = append(out, h)
		}
	}
	return out
}

func chainHasTAEC(chain []CachedEntityStatement, trustAnchor string) bool {
	return chainHasSelfSigned(chain, trustAnchor)
}
