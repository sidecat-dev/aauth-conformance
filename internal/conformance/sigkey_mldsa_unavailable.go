//go:build !go1.27

package conformance

import "fmt"

// sigkeyMLDSA44 needs crypto/mldsa, which Go 1.27 added. Earlier toolchains
// run every other scenario; the ML-DSA ones end in an execution error.
func sigkeyMLDSA44(string) (sigkeyKey, error) {
	return sigkeyKey{}, fmt.Errorf("ML-DSA-44 fixtures need a Go 1.27 or later toolchain (crypto/mldsa)")
}
