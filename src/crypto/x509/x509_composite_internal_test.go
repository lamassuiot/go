// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

// White-box tests for the composite adapter layer: InnerPrivateKey /
// InnerPublicKey, the ML-DSA and RSA adapters, and CompositeAlgorithm's
// prototype keys. x509_composite_test.go / x509_composite_tv_test.go
// cover the external contract.

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"testing"
)

var (
	_ InnerPrivateKey = (*mldsaInnerPrivateKey)(nil)
	_ InnerPublicKey  = (*mldsaInnerPublicKey)(nil)
	_ InnerPrivateKey = (*rsaInnerPrivateKey)(nil)
	_ InnerPublicKey  = (*rsaInnerPublicKey)(nil)
)

type innerKeyCase struct {
	name  string
	proto InnerPrivateKey
}

func innerKeyCases() []innerKeyCase {
	return []innerKeyCase{
		{"ML-DSA-44", newMLDSAInnerPrivateKey(mldsa.MLDSA44(), "test-label", nil)},
		{"RSA-2048-PSS", newRSAInnerPrivateKey(2048, crypto.SHA256, true, nil)},
		{"RSA-2048-PKCS15", newRSAInnerPrivateKey(2048, crypto.SHA256, false, nil)},
	}
}

// TestInnerPrivateKeyPrototypeGenerateKey checks that GenerateKey on a
// prototype produces a usable key, and that two calls produce different
// keys (i.e. nothing is cached on the prototype).
func TestInnerPrivateKeyPrototypeGenerateKey(t *testing.T) {
	for _, tc := range innerKeyCases() {
		t.Run(tc.name, func(t *testing.T) {
			sk1, err := tc.proto.GenerateKey(cryptorand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			sk2, err := tc.proto.GenerateKey(cryptorand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey (2nd): %v", err)
			}
			if bytes.Equal(sk1.Bytes(), sk2.Bytes()) {
				t.Fatal("two calls to GenerateKey on the same prototype produced identical key material")
			}

			msg := []byte("inner key sign/verify round trip")
			sig, err := sk1.Sign(cryptorand.Reader, msg)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !sk1.Public().Verify(msg, sig) {
				t.Fatal("Verify rejected a signature produced by the matching key")
			}
			if sk2.Public().Verify(msg, sig) {
				t.Fatal("Verify accepted a signature produced by a different key")
			}
		})
	}
}

// TestInnerPrivateKeyUnmarshallRoundTrip checks that a generated key
// survives a Bytes/Unmarshall round trip (private and public) with
// identical encoding and signing/verification behavior.
func TestInnerPrivateKeyUnmarshallRoundTrip(t *testing.T) {
	for _, tc := range innerKeyCases() {
		t.Run(tc.name, func(t *testing.T) {
			sk, err := tc.proto.GenerateKey(cryptorand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}

			skBytes := sk.Bytes()
			if len(skBytes) != sk.Size() {
				t.Fatalf("Bytes() length = %d, want Size() = %d", len(skBytes), sk.Size())
			}
			sk2, err := tc.proto.Unmarshall(skBytes)
			if err != nil {
				t.Fatalf("Unmarshall: %v", err)
			}
			if !bytes.Equal(skBytes, sk2.Bytes()) {
				t.Fatal("private key wire format mismatch after Unmarshall round trip")
			}

			pk := sk.Public()
			pkBytes := pk.Bytes()
			if len(pkBytes) != pk.Size() {
				t.Fatalf("public Bytes() length = %d, want Size() = %d", len(pkBytes), pk.Size())
			}
			pk2, err := pk.Unmarshall(pkBytes)
			if err != nil {
				t.Fatalf("public Unmarshall: %v", err)
			}
			if !bytes.Equal(pkBytes, pk2.Bytes()) {
				t.Fatal("public key wire format mismatch after Unmarshall round trip")
			}

			msg := []byte("post-unmarshal sign/verify")
			sig, err := sk2.Sign(cryptorand.Reader, msg)
			if err != nil {
				t.Fatalf("Sign after Unmarshall: %v", err)
			}
			if len(sig) != pk.SignatureSize() {
				t.Fatalf("signature length = %d, want SignatureSize() = %d", len(sig), pk.SignatureSize())
			}
			if !pk2.Verify(msg, sig) {
				t.Fatal("Verify rejected a signature from the key parsed via Unmarshall")
			}
		})
	}
}

// TestCompositeAlgorithmPrototypesNeverGenerateEagerly checks that a
// CompositeAlgorithm's prototype holds no cached real key: two calls to
// GenerateCompositeKey must produce different key material.
func TestCompositeAlgorithmPrototypesNeverGenerateEagerly(t *testing.T) {
	for _, alg := range CompositeAlgorithms {
		alg := alg
		t.Run(alg.Name, func(t *testing.T) {
			t.Parallel()
			_, sk1, err := alg.GenerateCompositeKey(cryptorand.Reader)
			if err != nil {
				t.Fatalf("GenerateCompositeKey: %v", err)
			}
			_, sk2, err := alg.GenerateCompositeKey(cryptorand.Reader)
			if err != nil {
				t.Fatalf("GenerateCompositeKey (2nd): %v", err)
			}
			if bytes.Equal(sk1.marshall(), sk2.marshall()) {
				t.Fatal("two calls to GenerateCompositeKey produced identical key material")
			}
		})
	}
}

// TestCompositeBuildMPrimeRejectsLongContext checks that a context over
// 255 bytes is rejected, surfaced through CompositeSign.
func TestCompositeBuildMPrimeRejectsLongContext(t *testing.T) {
	alg := MLDSA44_RSA2048_PSS_SHA256
	_, sk, err := alg.GenerateCompositeKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("GenerateCompositeKey: %v", err)
	}
	longCtx := bytes.Repeat([]byte{0x42}, 256)
	if _, err := alg.CompositeSign(cryptorand.Reader, sk, []byte("msg"), longCtx); err == nil {
		t.Fatal("CompositeSign accepted a context string longer than 255 bytes")
	}
}

// TestCompositePrivateKeyUnmarshallShortData checks that parsing
// truncated composite key data fails instead of panicking.
func TestCompositePrivateKeyUnmarshallShortData(t *testing.T) {
	alg := MLDSA44_RSA2048_PSS_SHA256
	if _, err := alg.parseCompositePrivateKey(nil); err == nil {
		t.Fatal("parseCompositePrivateKey accepted empty data")
	}
	if _, err := alg.parseCompositePublicKey(nil); err == nil {
		t.Fatal("parseCompositePublicKey accepted empty data")
	}

	_, sk, err := alg.GenerateCompositeKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("GenerateCompositeKey: %v", err)
	}
	full := sk.marshall()
	if _, err := alg.parseCompositePrivateKey(full[:mldsa.PrivateKeySize]); err == nil {
		t.Fatal("parseCompositePrivateKey accepted data truncated to exactly the ML-DSA component size")
	}
}

// TestBuildMPrimeShapes checks both M' shapes newBuildMPrime can produce:
// the ML-DSA shape used by all pre-declared algorithms today, and the
// non-ML-DSA shape (not yet exercised by any pre-declared algorithm).
func TestBuildMPrimeShapes(t *testing.T) {
	const label = "test-label"
	msg := []byte("some message")
	ctx := []byte("some context")
	sum := sha256.Sum256(msg)
	ph := sum[:]

	t.Run("MLDSA", func(t *testing.T) {
		build := newBuildMPrime(true, crypto.SHA256, label)
		got, err := build(msg, ctx)
		if err != nil {
			t.Fatalf("buildMPrime: %v", err)
		}
		want := append([]byte(compositeDomainPrefix), []byte(label)...)
		want = append(want, byte(len(ctx)))
		want = append(want, ctx...)
		want = append(want, ph...)
		if !bytes.Equal(got, want) {
			t.Fatalf("M' = %x, want %x", got, want)
		}
	})

	t.Run("non-MLDSA", func(t *testing.T) {
		build := newBuildMPrime(false, crypto.SHA256, label)
		got, err := build(msg, ctx)
		if err != nil {
			t.Fatalf("buildMPrime: %v", err)
		}
		want := append([]byte(compositeDomainPrefix), byte(len(label)))
		want = append(want, []byte(label)...)
		want = append(want, byte(len(ctx)))
		want = append(want, ctx...)
		want = append(want, ph...)
		if !bytes.Equal(got, want) {
			t.Fatalf("M' = %x, want %x", got, want)
		}
	})

	t.Run("MLDSA and non-MLDSA shapes differ", func(t *testing.T) {
		mldsaShape, err := newBuildMPrime(true, crypto.SHA256, label)(msg, ctx)
		if err != nil {
			t.Fatalf("buildMPrime: %v", err)
		}
		otherShape, err := newBuildMPrime(false, crypto.SHA256, label)(msg, ctx)
		if err != nil {
			t.Fatalf("buildMPrime: %v", err)
		}
		if bytes.Equal(mldsaShape, otherShape) {
			t.Fatal("ML-DSA and non-ML-DSA M' shapes produced identical output")
		}
	})
}
