package main

import (
	"os"
	"path/filepath"
	"testing"

	"gitlab.com/sidecat-dev/aauth-conformance/internal/conformance"
)

func TestGoRoleSourcesCanReuseOutputDirectory(t *testing.T) {
	root, work := t.TempDir(), t.TempDir()
	source := filepath.Join(root, "adapters", "go")
	if err := os.MkdirAll(source, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "deferred.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{conformance.DeferredRole, conformance.ResourceRole, conformance.DeferredRole, conformance.FederatedRole, conformance.AgentRole, conformance.PersonServerRole} {
		if err := selectGoRoleSource(root, work, role); err != nil {
			t.Fatal(err)
		}
		_, err := os.Stat(filepath.Join(work, "deferred.go"))
		if role == conformance.DeferredRole && err != nil {
			t.Fatalf("deferred source missing: %v", err)
		}
		if role != conformance.DeferredRole && !os.IsNotExist(err) {
			t.Fatalf("%s retained deferred source: %v", role, err)
		}
	}
}
