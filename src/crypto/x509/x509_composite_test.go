package x509_test

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

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
//	https://github.com/lamps-wg/draft-composite-sigs/blob/draft-ietf-lamps-pq-composite-sigs-19/src/testvectors.json
//
// RSA, ECDSA and Ed25519 variants are included (15 total). Each tvCase
// provides a pre-generated key pair and signature; we verify that
// CompositeVerify accepts the signature, that the private key re-encodes
// to the same bytes, and that a fresh signature produced with it verifies.

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
	return append(buildCompositeTVCases(), buildCompositeECDSAEd25519TVCases()...)
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

			// Verify the IETF-provided signature.
			if !tc.alg.CompositeVerify(pk, msg, nil, tc.sig) {
				t.Fatal("CompositeVerify failed for IETF test vector signature")
			}

			if tc.skBytes == nil {
				return
			}
			sk, err := tc.alg.ParseCompositePrivateKeyRaw(tc.skBytes)
			if err != nil {
				t.Fatalf("ParseCompositePrivateKeyRaw: %v", err)
			}

			// The private key must re-encode to the IETF wire format.
			der, err := x509.MarshalPKCS8PrivateKey(sk)
			if err != nil {
				t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
			}
			if !bytes.Equal(pkcs8PrivateKeyBytes(t, der), tc.skBytes) {
				t.Fatal("private key encoding differs from the IETF test vector")
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

// pkcs8PrivateKeyBytes returns the privateKey field of the PKCS #8 encoding der.
func pkcs8PrivateKeyBytes(t *testing.T, der []byte) []byte {
	t.Helper()
	var p struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	if _, err := asn1.Unmarshal(der, &p); err != nil {
		t.Fatalf("parsing PKCS #8: %v", err)
	}
	return p.PrivateKey
}

// ecdsaTVCases returns the IETF test vectors for the ML-DSA+ECDSA composites.
func ecdsaTVCases() []tvCase {
	var cases []tvCase
	for _, tc := range buildCompositeECDSAEd25519TVCases() {
		if strings.Contains(tc.alg.Name, "-ECDSA-") {
			cases = append(cases, tc)
		}
	}
	return cases
}

// TestCompositeECDSALegacyPrivateKey checks that ML-DSA+ECDSA private keys
// written by earlier versions of this package, which encoded the ECDSA
// component as a raw scalar instead of an RFC 5915 ECPrivateKey, can still
// be parsed, and that they are re-encoded in the RFC 5915 form.
func TestCompositeECDSALegacyPrivateKey(t *testing.T) {
	msg := []byte(tvMsg)
	for _, tc := range ecdsaTVCases() {
		t.Run(tc.alg.Name, func(t *testing.T) {
			seed, tradSK := tc.skBytes[:mldsa.PrivateKeySize], tc.skBytes[mldsa.PrivateKeySize:]
			ec, err := x509.ParseECPrivateKey(tradSK)
			if err != nil {
				t.Fatalf("ParseECPrivateKey: %v", err)
			}
			scalar, err := ec.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			legacy := append(bytes.Clone(seed), scalar...)

			sk, err := tc.alg.ParseCompositePrivateKeyRaw(legacy)
			if err != nil {
				t.Fatalf("ParseCompositePrivateKeyRaw(legacy): %v", err)
			}
			der, err := x509.MarshalPKCS8PrivateKey(sk)
			if err != nil {
				t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
			}
			if !bytes.Equal(pkcs8PrivateKeyBytes(t, der), tc.skBytes) {
				t.Fatal("legacy private key was not re-encoded in the IETF wire format")
			}

			pk, err := tc.alg.ParseCompositePublicKeyRaw(tc.pkBytes)
			if err != nil {
				t.Fatalf("ParseCompositePublicKeyRaw: %v", err)
			}
			sig, err := tc.alg.CompositeSign(rand.Reader, sk, msg, nil)
			if err != nil {
				t.Fatalf("CompositeSign: %v", err)
			}
			if !tc.alg.CompositeVerify(pk, msg, nil, sig) {
				t.Fatal("CompositeVerify failed for a signature from the legacy private key")
			}
		})
	}
}

// TestCompositeECDSAPrivateKeyCurveMismatch checks that an ML-DSA+ECDSA
// private key whose ECPrivateKey names a curve other than the algorithm's
// is rejected.
func TestCompositeECDSAPrivateKeyCurveMismatch(t *testing.T) {
	oidP256 := asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidP384 := asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	for _, tc := range ecdsaTVCases() {
		t.Run(tc.alg.Name, func(t *testing.T) {
			seed, tradSK := tc.skBytes[:mldsa.PrivateKeySize], tc.skBytes[mldsa.PrivateKeySize:]
			ec, err := x509.ParseECPrivateKey(tradSK)
			if err != nil {
				t.Fatalf("ParseECPrivateKey: %v", err)
			}
			scalar, err := ec.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			wrongOID := oidP384
			if ec.Curve.Params().Name == "P-384" {
				wrongOID = oidP256
			}
			wrong, err := asn1.Marshal(struct {
				Version       int
				PrivateKey    []byte
				NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
			}{1, scalar, wrongOID})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tc.alg.ParseCompositePrivateKeyRaw(append(bytes.Clone(seed), wrong...)); err == nil {
				t.Fatal("ParseCompositePrivateKeyRaw accepted an ECPrivateKey for the wrong curve")
			}
		})
	}
}

// TestCompositeParseErrorReturnsNilKey checks that when parsing a composite
// key fails, the returned key is a nil interface rather than a nil
// *CompositePrivateKey or *CompositePublicKey wrapped in a non-nil one.
func TestCompositeParseErrorReturnsNilKey(t *testing.T) {
	alg := x509.MLDSA44_ECDSA_P256_SHA256
	short := []byte{0x01, 0x02, 0x03}

	pkcs8DER, err := asn1.Marshal(struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{0, pkix.AlgorithmIdentifier{Algorithm: alg.OID}, short})
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(pkcs8DER)
	if err == nil {
		t.Fatal("ParsePKCS8PrivateKey accepted a truncated composite private key")
	}
	if key != nil {
		t.Errorf("ParsePKCS8PrivateKey returned non-nil key %#v with error", key)
	}

	spkiDER, err := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{pkix.AlgorithmIdentifier{Algorithm: alg.OID}, asn1.BitString{Bytes: short, BitLength: 8 * len(short)}})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(spkiDER)
	if err == nil {
		t.Fatal("ParsePKIXPublicKey accepted a truncated composite public key")
	}
	if pub != nil {
		t.Errorf("ParsePKIXPublicKey returned non-nil key %#v with error", pub)
	}
}

// TestCompositeSignatureAlgorithmMismatch checks that a composite key is only
// accepted under its own composite algorithm, not under another one of the
// same or a different family, both when verifying and when signing.
func TestCompositeSignatureAlgorithmMismatch(t *testing.T) {
	keyAlg := x509.MLDSA44_RSA2048_PSS_SHA256
	pub, priv, err := keyAlg.GenerateCompositeKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateCompositeKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "composite mismatch"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	msg := []byte("composite signature algorithm mismatch")
	sig, err := keyAlg.CompositeSign(rand.Reader, priv, msg, nil)
	if err != nil {
		t.Fatalf("CompositeSign: %v", err)
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, msg, sig); err != nil {
		t.Fatalf("CheckSignature rejected the key's own algorithm: %v", err)
	}

	for _, tc := range []struct {
		alg     *x509.CompositeAlgorithm
		sigAlgo x509.SignatureAlgorithm
	}{
		{x509.MLDSA44_RSA2048_PKCS15_SHA256, x509.CompositeMLDSA44RSA2048PKCS15SHA256}, // same family
		{x509.MLDSA44_ECDSA_P256_SHA256, x509.CompositeMLDSA44ECDSAP256SHA256},         // different family
	} {
		t.Run(tc.alg.Name, func(t *testing.T) {
			// Signed with keyAlg's components, but over tc.alg's M'.
			sig, err := tc.alg.CompositeSign(rand.Reader, priv, msg, nil)
			if err != nil {
				t.Fatalf("CompositeSign: %v", err)
			}
			if err := cert.CheckSignature(tc.sigAlgo, msg, sig); err == nil {
				t.Errorf("CheckSignature accepted a %s key signing as %s", keyAlg.Name, tc.alg.Name)
			}

			tmpl := *template
			tmpl.SignatureAlgorithm = tc.sigAlgo
			_, err = x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, pub, priv)
			if err == nil || !strings.Contains(err.Error(), "does not match") {
				t.Errorf("CreateCertificate with %s for a %s key: got %v, want algorithm mismatch error", tc.alg.Name, keyAlg.Name, err)
			}
		})
	}
}

// TestCompositeRejectsParameters checks that composite public keys,
// private keys and signature algorithm identifiers are rejected when their
// AlgorithmIdentifier carries parameters, which must be absent.
func TestCompositeRejectsParameters(t *testing.T) {
	alg := x509.MLDSA44_ECDSA_P256_SHA256
	pub, priv, err := alg.GenerateCompositeKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateCompositeKey: %v", err)
	}

	t.Run("PublicKey", func(t *testing.T) {
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatalf("MarshalPKIXPublicKey: %v", err)
		}
		var spki struct {
			Algorithm pkix.AlgorithmIdentifier
			PublicKey asn1.BitString
		}
		if _, err := asn1.Unmarshal(der, &spki); err != nil {
			t.Fatal(err)
		}
		spki.Algorithm.Parameters = asn1.NullRawValue
		der, err = asn1.Marshal(spki)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := x509.ParsePKIXPublicKey(der); err == nil {
			t.Error("ParsePKIXPublicKey accepted a composite public key with parameters")
		}
	})

	t.Run("PrivateKey", func(t *testing.T) {
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
		}
		var p8 struct {
			Version    int
			Algo       pkix.AlgorithmIdentifier
			PrivateKey []byte
		}
		if _, err := asn1.Unmarshal(der, &p8); err != nil {
			t.Fatal(err)
		}
		p8.Algo.Parameters = asn1.NullRawValue
		der, err = asn1.Marshal(p8)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := x509.ParsePKCS8PrivateKey(der); err == nil {
			t.Error("ParsePKCS8PrivateKey accepted a composite private key with parameters")
		}
	})

	t.Run("SignatureAlgorithm", func(t *testing.T) {
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "composite parameters"},
		}, priv)
		if err != nil {
			t.Fatalf("CreateCertificateRequest: %v", err)
		}
		var csr struct {
			TBS                asn1.RawValue
			SignatureAlgorithm pkix.AlgorithmIdentifier
			SignatureValue     asn1.BitString
		}
		if _, err := asn1.Unmarshal(der, &csr); err != nil {
			t.Fatal(err)
		}
		csr.SignatureAlgorithm.Parameters = asn1.NullRawValue
		der, err = asn1.Marshal(csr)
		if err != nil {
			t.Fatal(err)
		}
		req, err := x509.ParseCertificateRequest(der)
		if err != nil {
			return
		}
		if err := req.CheckSignature(); err == nil {
			t.Error("CheckSignature accepted a composite signature algorithm with parameters")
		}
	})
}

// TestCompositeSelfSignedCert verifies that a self-signed X.509 certificate
// can be created and verified for every composite ML-DSA+RSA algorithm.
func TestCompositeSelfSignedCert(t *testing.T) {
	for _, alg := range x509.CompositeAlgorithms {
		alg := alg
		t.Run(alg.Name, func(t *testing.T) {
			t.Parallel()

			pk, sk, err := alg.GenerateCompositeKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateCompositeKey: %v", err)
			}

			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject: pkix.Name{
					CommonName:   "composite-test",
					Organization: []string{"Test Org"},
				},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
				BasicConstraintsValid: true,
				IsCA:                  true,
			}

			der, err := x509.CreateCertificate(rand.Reader, template, template, pk, sk)
			if err != nil {
				t.Fatalf("CreateCertificate: %v", err)
			}

			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatalf("ParseCertificate: %v", err)
			}

			wantAlgo := x509.CompositeMLDSARSA
			switch {
			case strings.Contains(alg.Name, "ECDSA"):
				wantAlgo = x509.CompositeMLDSAECDSA
			case strings.Contains(alg.Name, "Ed25519"):
				wantAlgo = x509.CompositeMLDSAEd25519
			}
			if cert.PublicKeyAlgorithm != wantAlgo {
				t.Fatalf("PublicKeyAlgorithm: got %v, want %v", cert.PublicKeyAlgorithm, wantAlgo)
			}

			if err := cert.CheckSignatureFrom(cert); err != nil {
				t.Fatalf("CheckSignatureFrom: %v", err)
			}

			// Verify the algorithm OID round-trips through the certificate.
			parsedPub, ok := cert.PublicKey.(*x509.CompositePublicKey)
			if !ok {
				t.Fatalf("cert.PublicKey is %T, want *CompositePublicKey", cert.PublicKey)
			}
			if parsedPub.Algorithm() != alg {
				t.Fatalf("parsed public key algorithm mismatch: got %v, want %v",
					parsedPub.Algorithm().Name, alg.Name)
			}
		})
	}
}
