// build-adapters compiles launchers against caller-selected local SUT checkouts.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"gitlab.com/sidecat-dev/aauth-conformance/internal/conformance"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
func run() error {
	goSource := flag.String("go-source", "", "aauth-go checkout (required unless -rust-source is supplied)")
	rustSource := flag.String("rust-source", "", "aauth-rust checkout (required unless -go-source is supplied)")
	communitySource := flag.String("community-source", "", "github.com/aauth-dev/aauth-go checkout, built with adapters/community-go")
	out := flag.String("out", "build", "build output directory")
	role := flag.String("role", conformance.ResourceRole, strings.Join(conformance.Roles(), ", "))
	recommended := flag.Bool("claim-recommended", false, "also claim the role's SHOULD-level (recommended) clauses")
	flag.Parse()
	if *goSource == "" && *rustSource == "" && *communitySource == "" {
		return fmt.Errorf("supply -go-source, -rust-source and/or -community-source")
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	directory, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(directory, 0755); err != nil {
		return err
	}
	suite, err := conformance.Load(root)
	if err != nil {
		return err
	}
	if _, err = suite.ForRole(*role); err != nil && !generatedRoles[*role] {
		return err
	}
	claims := conformance.Claims(suite, *role)
	if *recommended {
		claims = append(claims, conformance.RecommendedClaims(suite, *role)...)
	}
	targets := conformance.Targets{Version: 1, Role: *role}
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	for _, item := range []struct{ id, source string }{{"aauth-go", *goSource}, {"aauth-rust", *rustSource}, {"aauth-go-community", *communitySource}} {
		if item.source == "" {
			continue
		}
		source, err := filepath.Abs(item.source)
		if err != nil {
			return err
		}
		revision, err := exec.Command("git", "-C", source, "rev-parse", "HEAD").Output()
		if err != nil {
			return fmt.Errorf("source checkout: %w", err)
		}
		dirty, err := exec.Command("git", "-C", source, "status", "--porcelain", "--untracked-files=no").Output()
		if err != nil {
			return err
		}
		rev := strings.TrimSpace(string(revision))
		if len(dirty) > 0 {
			rev += "+dirty"
		}
		if reason := unavailableRoles[*role][item.id]; reason != "" {
			fmt.Printf("%s at %s: not offered for %s\n", item.id, rev, *role)
			targets.Implementations = append(targets.Implementations, conformance.Target{ID: item.id, Revision: rev, Unavailable: reason})
			continue
		}
		work := filepath.Join(directory, item.id+"-adapter")
		if err = os.MkdirAll(work, 0755); err != nil {
			return err
		}
		binary := filepath.Join(directory, item.id+"-launcher"+suffix)
		if item.id == "aauth-go-community" {
			if err = buildCommunity(root, work, source, binary); err != nil {
				return err
			}
		} else if item.id == "aauth-go" {
			if err = selectGoRoleSource(root, work, *role); err != nil {
				return err
			}
			if err = copyFile(filepath.Join(root, "adapters/go/main.go"), filepath.Join(work, "main.go")); err != nil {
				return err
			}
			if err = copyFile(filepath.Join(root, "adapters/go/main_test.go"), filepath.Join(work, "main_test.go")); err != nil {
				return err
			}
			if err = copyFile(filepath.Join(root, "adapters/go/go.mod"), filepath.Join(work, "go.mod")); err != nil {
				return err
			}
			if err = command(work, "go", "mod", "edit", "-replace=gitlab.com/sidecat-dev/aauth-go="+source); err != nil {
				return err
			}
			if err = command(work, "go", "mod", "tidy"); err != nil {
				return err
			}
			if err = command(work, "go", "build", "-buildvcs=false", "-o", binary, "."); err != nil {
				return err
			}
		} else {
			if err = os.MkdirAll(filepath.Join(work, "src"), 0755); err != nil {
				return err
			}
			rustFiles, listError := filepath.Glob(filepath.Join(root, "adapters/rust/src/*.rs"))
			if listError != nil {
				return listError
			}
			for _, sourceFile := range rustFiles {
				if err = copyFile(sourceFile, filepath.Join(work, "src", filepath.Base(sourceFile))); err != nil {
					return err
				}
			}
			if len(rustFiles) == 0 {
				return fmt.Errorf("Rust adapter source is missing")
			}
			manifest, err := os.ReadFile(filepath.Join(root, "adapters/rust/Cargo.toml"))
			if err != nil {
				return err
			}
			for _, name := range rustRoleCrates[*role] {
				manifest = append(manifest, []byte("\n[dependencies."+name+"]\nversion = \"=0.1.0-alpha.2\"\n")...)
			}
			// The launcher manifest names the crates by an exact alpha version;
			// select the version the chosen checkout declares so the path patches apply.
			if version := rustWorkspaceVersion(source); version != "" {
				manifest = []byte(strings.ReplaceAll(string(manifest), `"=0.1.0-alpha.2"`, strconv.Quote("="+version)))
			}
			manifest = append(manifest, []byte("\n[patch.crates-io]\n")...)
			names := []string{"aauth-rust-core", "aauth-rust-resource", "aauth-rust-agent", "aauth-rust-jose", "aauth-rust-budgets"}
			if _, e := os.Stat(filepath.Join(source, "crates", "aauth-rust-person-server")); e == nil || *role == conformance.PersonServerRole {
				names = append(names, "aauth-rust-person-server")
			}
			names = append(names, rustRoleCrates[*role]...)
			for _, name := range names {
				manifest = append(manifest, []byte(name+" = { path = "+strconv.Quote(filepath.ToSlash(filepath.Join(source, "crates", name)))+" }\n")...)
			}
			if err = os.WriteFile(filepath.Join(work, "Cargo.toml"), manifest, 0644); err != nil {
				return err
			}
			if _, err = os.Stat(filepath.Join(work, "Cargo.lock")); os.IsNotExist(err) {
				if err = copyFile(filepath.Join(source, "Cargo.lock"), filepath.Join(work, "Cargo.lock")); err != nil {
					return err
				}
			}
			if err = copyFile(filepath.Join(source, "rust-toolchain.toml"), filepath.Join(work, "rust-toolchain.toml")); err != nil {
				return err
			}
			buildArgs := []string{"build", "--target-dir", filepath.Join(root, "build", "rust-target-shared")}
			if feature := rustRoleFeatures[*role]; feature != "" {
				buildArgs = append(buildArgs, "--features", feature)
			}
			if err = command(work, "cargo", buildArgs...); err != nil {
				return err
			}
			if err = copyFile(filepath.Join(root, "build", "rust-target-shared", "debug", "aauth-conformance-rust-adapter"+suffix), binary); err != nil {
				return err
			}
		}
		fmt.Printf("Built %s at %s\n", item.id, rev)
		targets.Implementations = append(targets.Implementations, conformance.Target{ID: item.id, Revision: rev, Command: []string{binary}, Claims: append(offeredClaims(claims, unofferedClaims[*role][item.id]), adoptedClaims[*role][item.id]...)})
	}
	b, err := json.MarshalIndent(targets, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(directory, "targets.json"), append(b, '\n'), 0644)
}
func copyFile(from, to string) error {
	b, e := os.ReadFile(from)
	if e != nil {
		return e
	}
	return os.WriteFile(to, b, 0755)
}
func command(dir, name string, args ...string) error {
	c := exec.Command(name, args...)
	c.Dir = dir
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Env = append(os.Environ(), "GOWORK=off")
	if err := c.Run(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// Role-specific launcher sources, native Rust features and extra Rust crates.
// Earlier implementation checkouts can still build the roles that need none.
var goRoleSources = map[string][]string{
	conformance.DeferredRole: {"deferred.go"},
	conformance.SubagentRole: {"subagent.go"},
}
var rustRoleFeatures = map[string]string{
	conformance.FederatedRole: "federation",
	conformance.DeferredRole:  "deferred",
	conformance.SubagentRole:  "subagent",
}
var rustRoleCrates = map[string][]string{
	conformance.FederatedRole: {"aauth-rust-access-server"},
	conformance.DeferredRole:  {"aauth-rust-access-server"},
	conformance.SubagentRole:  {"aauth-rust-access-server"},
}

// unavailableRoles declares a role an implementation has no native API for.
// Its target carries the reason instead of a launcher and claims nothing.
var unavailableRoles = map[string]map[string]string{}

// generatedRoles are roles whose scenarios the built launchers generate, so
// their launchers can be built before the first scenario exists.
var generatedRoles = map[string]bool{}

// unofferedClaims lists clauses an implementation's native API assigns to
// host code, so a launcher-supplied component would decide them. They stay
// unclaimed for that implementation and are reported as not offered.
var unofferedClaims = map[string]map[string][]string{}

// adoptedClaims lists out-of-slice clauses an implementation's native API
// implements. The helper claims no out-of-slice clause by default, since the
// drafts leave each one optional or unsettled; an implementation listed here
// claims these, so their assertions are graded for it.
var adoptedClaims = map[string]map[string][]string{}

func offeredClaims(claims, unoffered []string) []string {
	offered := []string{}
	for _, claim := range claims {
		if !slices.Contains(unoffered, claim) {
			offered = append(offered, claim)
		}
	}
	return offered
}

// Remove role-specific sources when an output directory is reused for another
// profile. Earlier implementation revisions need only the common launcher.
func selectGoRoleSource(root, work, role string) error {
	for selectedRole, sources := range goRoleSources {
		for _, source := range sources {
			destination := filepath.Join(work, source)
			if role == selectedRole {
				if err := copyFile(filepath.Join(root, "adapters/go", source), destination); err != nil {
					return err
				}
				continue
			}
			if slices.Contains(goRoleSources[role], source) {
				continue
			}
			if err := os.Remove(destination); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}

// rustWorkspaceVersion returns [workspace.package] version from the checkout's
// root manifest, or "" when the checkout does not declare one.
func rustWorkspaceVersion(source string) string {
	b, err := os.ReadFile(filepath.Join(source, "Cargo.toml"))
	if err != nil {
		return ""
	}
	section := ""
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if section == "[workspace.package]" && ok && strings.TrimSpace(name) == "version" {
			version, err := strconv.Unquote(strings.TrimSpace(value))
			if err == nil {
				return version
			}
		}
	}
	return ""
}

// buildCommunity compiles adapters/community-go against the selected checkout
// of the community module. Every source file is included: role files register
// themselves, and the launcher refuses a role none registered.
func buildCommunity(root, work, source, binary string) error {
	files, err := filepath.Glob(filepath.Join(root, "adapters/community-go/*.go"))
	if err != nil {
		return err
	}
	files = append(files, filepath.Join(root, "adapters/community-go/go.mod"))
	for _, file := range files {
		if err := copyFile(file, filepath.Join(work, filepath.Base(file))); err != nil {
			return err
		}
	}
	if err := command(work, "go", "mod", "edit", "-replace=github.com/aauth-dev/aauth-go="+source); err != nil {
		return err
	}
	if err := command(work, "go", "mod", "tidy"); err != nil {
		return err
	}
	return command(work, "go", "build", "-buildvcs=false", "-o", binary, ".")
}
