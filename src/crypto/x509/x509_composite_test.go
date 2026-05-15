package x509_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"crypto/x509"
)

// compile-time check that *CompositePrivateKey satisfies crypto.Signer.
var _ crypto.Signer = (*x509.CompositePrivateKey)(nil)

// ── round-trip ────────────────────────────────────────────────────────────────

func TestCompositeRoundTrip(t *testing.T) {
	msg := []byte("hello composite world")
	ctx := []byte("test-context")

	for _, alg := range x509.CompositeAlgorithms {
		alg := alg
		t.Run(alg.Name, func(t *testing.T) {
			t.Parallel()
			pk, sk, err := alg.GenerateCompositeKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateCompositeKey: %v", err)
			}

			sig, err := alg.CompositeSign(rand.Reader, sk, msg, ctx)
			if err != nil {
				t.Fatalf("CompositeSign: %v", err)
			}
			if !alg.CompositeVerify(pk, msg, ctx, sig) {
				t.Fatal("CompositeVerify returned false for valid signature")
			}

			badMsg := bytes.Clone(msg)
			badMsg[0] ^= 0x01
			if alg.CompositeVerify(pk, badMsg, ctx, sig) {
				t.Fatal("CompositeVerify returned true for wrong message")
			}
			if alg.CompositeVerify(pk, msg, []byte("other"), sig) {
				t.Fatal("CompositeVerify returned true for wrong context")
			}
		})
	}
}

func TestCompositeEmptyContext(t *testing.T) {
	alg := x509.MLDSA44_RSA2048_PSS_SHA256
	pk, sk, err := alg.GenerateCompositeKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("test message")

	sigNil, err := alg.CompositeSign(rand.Reader, sk, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	sigEmpty, err := alg.CompositeSign(rand.Reader, sk, msg, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	if !alg.CompositeVerify(pk, msg, nil, sigNil) {
		t.Fatal("nil ctx sig not verified with nil ctx")
	}
	if !alg.CompositeVerify(pk, msg, []byte{}, sigNil) {
		t.Fatal("nil ctx sig not verified with empty ctx")
	}
	if !alg.CompositeVerify(pk, msg, nil, sigEmpty) {
		t.Fatal("empty ctx sig not verified with nil ctx")
	}
	if !alg.CompositeVerify(pk, msg, []byte{}, sigEmpty) {
		t.Fatal("empty ctx sig not verified with empty ctx")
	}
}

// ── crypto.Signer ─────────────────────────────────────────────────────────────

func TestCompositeCryptoSigner(t *testing.T) {
	for _, alg := range x509.CompositeAlgorithms {
		alg := alg
		t.Run(alg.Name, func(t *testing.T) {
			t.Parallel()
			pk, sk, err := alg.GenerateCompositeKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateCompositeKey: %v", err)
			}

			msg := []byte("hello from crypto.Signer")

			sig, err := sk.Sign(rand.Reader, msg, x509.CompositeSignerOpts{})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !alg.CompositeVerify(pk, msg, nil, sig) {
				t.Fatal("CompositeVerify failed (empty context)")
			}

			ctx := []byte("my-ctx")
			sig2, err := sk.Sign(rand.Reader, msg, x509.CompositeSignerOpts{Context: ctx})
			if err != nil {
				t.Fatalf("Sign with context: %v", err)
			}
			if !alg.CompositeVerify(pk, msg, ctx, sig2) {
				t.Fatal("CompositeVerify failed (non-empty context)")
			}
			if alg.CompositeVerify(pk, msg, []byte("wrong"), sig2) {
				t.Fatal("CompositeVerify should fail for wrong context")
			}

			pub, ok := sk.Public().(*x509.CompositePublicKey)
			if !ok {
				t.Fatal("sk.Public() did not return *CompositePublicKey")
			}
			if pub.Algorithm() != alg {
				t.Fatal("Public() key has wrong algorithm")
			}
		})
	}
}

// ── SPKI (MarshalPKIXPublicKey / ParsePKIXPublicKey) ──────────────────────────

func TestCompositeSPKIRoundTrip(t *testing.T) {
	for _, alg := range x509.CompositeAlgorithms {
		alg := alg
		t.Run(alg.Name, func(t *testing.T) {
			t.Parallel()
			pk, _, err := alg.GenerateCompositeKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateCompositeKey: %v", err)
			}
			der, err := x509.MarshalPKIXPublicKey(pk)
			if err != nil {
				t.Fatalf("MarshalPKIXPublicKey: %v", err)
			}
			pub2, err := x509.ParsePKIXPublicKey(der)
			if err != nil {
				t.Fatalf("ParsePKIXPublicKey: %v", err)
			}
			pk2, ok := pub2.(*x509.CompositePublicKey)
			if !ok {
				t.Fatalf("parsed key is %T, want *x509.CompositePublicKey", pub2)
			}
			if pk2.Algorithm() != alg {
				t.Fatal("algorithm mismatch after SPKI round-trip")
			}
			der2, err := x509.MarshalPKIXPublicKey(pk2)
			if err != nil {
				t.Fatalf("MarshalPKIXPublicKey(pk2): %v", err)
			}
			if !bytes.Equal(der, der2) {
				t.Fatal("SPKI DER mismatch after round-trip")
			}
		})
	}
}

// ── PKCS #8 (MarshalPKCS8PrivateKey / ParsePKCS8PrivateKey) ───────────────────

func TestCompositePKCS8RoundTrip(t *testing.T) {
	for _, alg := range x509.CompositeAlgorithms {
		alg := alg
		t.Run(alg.Name, func(t *testing.T) {
			t.Parallel()
			_, sk, err := alg.GenerateCompositeKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateCompositeKey: %v", err)
			}
			der, err := x509.MarshalPKCS8PrivateKey(sk)
			if err != nil {
				t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
			}
			key2, err := x509.ParsePKCS8PrivateKey(der)
			if err != nil {
				t.Fatalf("ParsePKCS8PrivateKey: %v", err)
			}
			sk2, ok := key2.(*x509.CompositePrivateKey)
			if !ok {
				t.Fatalf("parsed key is %T, want *x509.CompositePrivateKey", key2)
			}
			if sk2.Algorithm() != alg {
				t.Fatal("algorithm mismatch after PKCS#8 round-trip")
			}
			der2, err := x509.MarshalPKCS8PrivateKey(sk2)
			if err != nil {
				t.Fatalf("MarshalPKCS8PrivateKey(sk2): %v", err)
			}
			if !bytes.Equal(der, der2) {
				t.Fatal("PKCS#8 DER mismatch after round-trip")
			}
		})
	}
}

func TestCompositeSPKIPKCS8CrossVerify(t *testing.T) {
	for _, alg := range x509.CompositeAlgorithms {
		alg := alg
		t.Run(alg.Name, func(t *testing.T) {
			t.Parallel()
			pk, sk, err := alg.GenerateCompositeKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateCompositeKey: %v", err)
			}

			pkDER, _ := x509.MarshalPKIXPublicKey(pk)
			skDER, _ := x509.MarshalPKCS8PrivateKey(sk)

			pub2, _ := x509.ParsePKIXPublicKey(pkDER)
			key2, _ := x509.ParsePKCS8PrivateKey(skDER)

			pk2 := pub2.(*x509.CompositePublicKey)
			sk2 := key2.(*x509.CompositePrivateKey)

			msg := []byte("cross-format sign/verify")
			sig, err := alg.CompositeSign(rand.Reader, sk2, msg, nil)
			if err != nil {
				t.Fatalf("CompositeSign: %v", err)
			}
			if !alg.CompositeVerify(pk2, msg, nil, sig) {
				t.Fatal("CompositeVerify with parsed keys failed")
			}
		})
	}
}

func TestCompositePEMRoundTrip(t *testing.T) {
	alg := x509.MLDSA44_RSA2048_PSS_SHA256
	pk, sk, err := alg.GenerateCompositeKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pkDER, _ := x509.MarshalPKIXPublicKey(pk)
	pkPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkDER})
	block, _ := pem.Decode(pkPEM)
	pub2, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey from PEM: %v", err)
	}
	if pub2.(*x509.CompositePublicKey).Algorithm() != alg {
		t.Fatal("algorithm mismatch after PEM public key round-trip")
	}

	skDER, _ := x509.MarshalPKCS8PrivateKey(sk)
	skPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: skDER})
	block2, _ := pem.Decode(skPEM)
	key2, err := x509.ParsePKCS8PrivateKey(block2.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey from PEM: %v", err)
	}
	if key2.(*x509.CompositePrivateKey).Algorithm() != alg {
		t.Fatal("algorithm mismatch after PEM private key round-trip")
	}
}

// ── IETF test vectors ─────────────────────────────────────────────────────────
//
// Test vectors sourced from:
//
//	https://github.com/lamps-wg/draft-composite-sigs/blob/main/src/testvectors.json
//
// Only RSA variants are included (8 total). Each tvCase provides a
// pre-generated key pair and signature; we verify that
// CompositeVerify accepts the signature and that a fresh signature
// produced with the given private key also verifies.

const tvMsg = "The quick brown fox jumps over the lazy dog."

type tvCase struct {
	alg     *x509.CompositeAlgorithm
	skBytes []byte // raw (non-PKCS#8) private key bytes
	pkBytes []byte // raw (non-SPKI) public key bytes
	sig     []byte
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func buildTVCases() []tvCase {
	return buildCompositeTVCases()
}

func TestCompositeIETFVectors(t *testing.T) {
	msg := []byte(tvMsg)
	cases := buildTVCases()
	for _, tc := range cases {
		tc := tc
		t.Run(tc.alg.Name, func(t *testing.T) {
			t.Parallel()

			pk, err := tc.alg.ParseCompositePublicKeyRaw(tc.pkBytes)
			if err != nil {
				t.Fatalf("ParseCompositePublicKeyRaw: %v", err)
			}
			sk, err := tc.alg.ParseCompositePrivateKeyRaw(tc.skBytes)
			if err != nil {
				t.Fatalf("ParseCompositePrivateKeyRaw: %v", err)
			}

			// Verify the IETF-provided signature.
			if !tc.alg.CompositeVerify(pk, msg, nil, tc.sig) {
				t.Fatal("CompositeVerify failed for IETF test vector signature")
			}

			// Sign with the IETF private key and verify the fresh signature.
			sig, err := tc.alg.CompositeSign(rand.Reader, sk, msg, nil)
			if err != nil {
				t.Fatalf("CompositeSign: %v", err)
			}
			if !tc.alg.CompositeVerify(pk, msg, nil, sig) {
				t.Fatal("CompositeVerify failed for freshly generated signature")
			}
		})
	}
}
