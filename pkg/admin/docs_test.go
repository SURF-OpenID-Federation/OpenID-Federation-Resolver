package admin

import "testing"

func TestClassifyResponse(t *testing.T) {
	kind, doc := ClassifyResponse(200, []byte(`{"entity_id":"https://n.example","roles":["resolver"],"base":"/admin/v1","spec":"draft-kodden-oidfed-admin-00","capabilities":{"keys":["list"]}}`))
	if kind != SpecID || doc == nil {
		t.Fatalf("kind=%s doc=%+v", kind, doc)
	}
	if doc.Roles[0] != ResolverRole {
		t.Fatalf("roles=%v", doc.Roles)
	}
	kind, _ = ClassifyResponse(401, []byte(`{}`))
	if kind != "legacy" {
		t.Fatalf("unauth classify=%s", kind)
	}
}
