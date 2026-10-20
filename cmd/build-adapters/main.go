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
	goSource := flag.String("go-source", "", "aauth-go checkout (optional)")
	rustSource := flag.String("rust-source", "", "aauth-rust checkout (optional)")
	out := flag.String("out", "build", "build output directory")
	role := flag.String("role", conformance.ResourceRole, "resource.agent-identity or agent.signing")
	flag.Parse()
	if *goSource == "" && *rustSource == "" {
		return fmt.Errorf("supply -go-source and/or -rust-source")
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
	if _, err = suite.ForRole(*role); err != nil {
		return err
	}
	claims := conformance.Claims(suite, *role)
	targets := conformance.Targets{Version: 1, Role: *role}
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	for _, item := range []struct{ id, source string }{{"aauth-go", *goSource}, {"aauth-rust", *rustSource}} {
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
		work := filepath.Join(directory, item.id+"-adapter")
		if err = os.MkdirAll(work, 0755); err != nil {
			return err
		}
		binary := filepath.Join(directory, item.id+"-launcher"+suffix)
		if item.id == "aauth-go" {
			if err = copyFile(filepath.Join(root, "adapters/go/main.go"), filepath.Join(work, "main.go")); err != nil {
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
			if err = copyFile(filepath.Join(root, "adapters/rust/src/main.rs"), filepath.Join(work, "src/main.rs")); err != nil {
				return err
			}
			manifest, err := os.ReadFile(filepath.Join(root, "adapters/rust/Cargo.toml"))
			if err != nil {
				return err
			}
			manifest = append(manifest, []byte("\n[patch.crates-io]\n")...)
			for _, name := range []string{"aauth-rust-core", "aauth-rust-resource", "aauth-rust-agent", "aauth-rust-jose"} {
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
			if err = command(work, "cargo", "build", "--target-dir", filepath.Join(directory, "rust-target")); err != nil {
				return err
			}
			if err = copyFile(filepath.Join(directory, "rust-target/debug/aauth-conformance-rust-adapter"+suffix), binary); err != nil {
				return err
			}
		}
		fmt.Printf("Built %s at %s\n", item.id, rev)
		targets.Implementations = append(targets.Implementations, conformance.Target{ID: item.id, Revision: rev, Command: []string{binary}, Claims: claims})
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
