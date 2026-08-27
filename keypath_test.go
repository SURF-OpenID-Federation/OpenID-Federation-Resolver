package main

import "testing"

func TestResolveKeyPathDefaultsAndAliases(t *testing.T) {
	t.Setenv("KEYS_PATH", "")
	t.Setenv("KEYS_DIR", "")
	if got := resolveKeyPath(); got != "./keys" {
		t.Fatalf("default=%q", got)
	}

	t.Setenv("KEYS_DIR", "./from-keys-dir")
	if got := resolveKeyPath(); got != "./from-keys-dir" {
		t.Fatalf("KEYS_DIR=%q", got)
	}

	t.Setenv("KEYS_PATH", "./from-keys-path")
	if got := resolveKeyPath(); got != "./from-keys-path" {
		t.Fatalf("KEYS_PATH=%q", got)
	}
}
