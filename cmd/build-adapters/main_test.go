package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.com/sidecat-dev/aauth-conformance/internal/conformance"
)

// A role-selection regression must catch a launcher compiled without its native
// feature or AS dependency before it can advertise conformance claims.
func TestRustRoleBuildSelectsNativeFeatures(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	working, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(working) })
	source, bins := t.TempDir(), t.TempDir()
	for _, name := range []string{"aauth-rust-core", "aauth-rust-resource", "aauth-rust-agent", "aauth-rust-jose", "aauth-rust-person-server", "aauth-rust-access-server"} {
		if err := os.MkdirAll(filepath.Join(source, "crates", name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"Cargo.lock", "rust-toolchain.toml"} {
		if err := os.WriteFile(filepath.Join(source, name), nil, 0644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}, {"-c", "user.name=Adapter Test", "-c", "user.email=adapter@example.test", "commit", "-qm", "fixture"}} {
		command := exec.Command("git", args...)
		command.Dir = source
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git fixture: %v: %s", err, output)
		}
	}
	// Cargo is the external build boundary. Capture its selected features while
	// the builder itself creates real manifests, source copies and targets.json.
	cargo := `#!/bin/sh
printf '%s\n' "$@" > "$AAUTH_TEST_CARGO_ARGS"
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--target-dir" ]; then shift; adapter_target="$1"; fi
  shift
done
mkdir -p "$adapter_target/debug"
printf '#!/bin/sh\nexit 0\n' > "$adapter_target/debug/aauth-conformance-rust-adapter"
`
	if err := os.WriteFile(filepath.Join(bins, "cargo"), []byte(cargo), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bins+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, test := range []struct{ role, feature string }{
		{conformance.ResourceRole, ""},
		{conformance.FederatedRole, "federation"},
		{conformance.DeferredRole, "deferred"},
		{conformance.SubagentRole, "subagent"},
	} {
		t.Run(test.role, func(t *testing.T) {
			out := t.TempDir()
			argsPath := filepath.Join(out, "cargo-args")
			t.Setenv("AAUTH_TEST_CARGO_ARGS", argsPath)
			previousFlags, previousArgs := flag.CommandLine, os.Args
			flag.CommandLine = flag.NewFlagSet("build-adapters", flag.ContinueOnError)
			os.Args = []string{"build-adapters", "-rust-source", source, "-role", test.role, "-out", out}
			t.Cleanup(func() { flag.CommandLine, os.Args = previousFlags, previousArgs })
			if err := run(); err != nil {
				t.Fatal(err)
			}
			args, err := os.ReadFile(argsPath)
			if err != nil {
				t.Fatal(err)
			}
			if test.feature == "" && strings.Contains(string(args), "--features") || test.feature != "" && !strings.Contains(string(args), "--features\n"+test.feature+"\n") {
				t.Fatalf("%s Cargo invocation: %s", test.role, args)
			}
			manifest, err := os.ReadFile(filepath.Join(out, "aauth-rust-adapter", "Cargo.toml"))
			if err != nil {
				t.Fatal(err)
			}
			hasAccess := strings.Contains(string(manifest), "[dependencies.aauth-rust-access-server]") && strings.Contains(string(manifest), "aauth-rust-access-server = { path =")
			if hasAccess != (test.feature != "") {
				t.Fatalf("%s native AS dependency selected: %v", test.role, hasAccess)
			}
			if _, err := os.Stat(filepath.Join(out, "targets.json")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

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

// Unqualified Go support must produce an honest manifest without even looking
// inside the moving source checkout or calling the Go compiler.
func TestGoSubagentBuildDeclaresUnavailableWithoutSourceAccess(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	working, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(working)
	previousFlags, previousArgs := flag.CommandLine, os.Args
	defer func() { flag.CommandLine, os.Args = previousFlags, previousArgs }()
	out := t.TempDir()
	flag.CommandLine = flag.NewFlagSet("build-adapters", flag.ContinueOnError)
	os.Args = []string{"build-adapters", "-go-source", "/nonexistent-unmeasured-source", "-role", conformance.SubagentRole, "-out", out}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	var targets conformance.Targets
	if err := conformance.ReadJSON(filepath.Join(out, "targets.json"), &targets); err != nil {
		t.Fatal(err)
	}
	if len(targets.Implementations) != 1 {
		t.Fatal("missing explicit Go status")
	}
	target := targets.Implementations[0]
	if target.Revision != "not_measured" || target.Unavailable == "" || len(target.Command) != 0 || len(target.Claims) != 0 {
		t.Fatalf("unmeasured Go falsely qualified: %+v", target)
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "targets.json" {
		t.Fatalf("unmeasured source created a build: %+v", entries)
	}
}
