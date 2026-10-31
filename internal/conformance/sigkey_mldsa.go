//go:build go1.27

package conformance

import (
	"crypto/mldsa"
	"encoding/hex"
)

// sigkeyMLDSA44 derives the fixture ML-DSA-44 key (FIPS 204) from its seed and
// publishes it as an AKP JWK. Signatures use the deterministic variant with an
// empty context, so a rerun signs the same base with the same bytes.
func sigkeyMLDSA44(seed string) (sigkeyKey, error) {
	raw, err := hex.DecodeString(seed)
	if err != nil {
		return sigkeyKey{}, err
	}
	private, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), raw)
	if err != nil {
		return sigkeyKey{}, err
	}
	public := private.PublicKey()
	return sigkeyKey{
		alg:    "ML-DSA-44",
		public: map[string]any{"kty": "AKP", "alg": "ML-DSA-44", "pub": sigkeyB64.EncodeToString(public.Bytes())},
		sign: func(message []byte) ([]byte, error) {
			return private.SignDeterministic(message, &mldsa.Options{})
		},
		verify: func(message, signature []byte) bool {
			return mldsa.Verify(public, message, signature, &mldsa.Options{}) == nil
		},
	}, nil
}
