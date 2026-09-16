// Package x509 — composite signature algorithms
//
// Implements the composite algorithms from draft-ietf-lamps-pq-composite-sigs
// (ML-DSA+RSA, ML-DSA+ECDSA and ML-DSA+Ed25519). CompositeAlgorithm only holds an algorithm's
// identity and its buildMPrime closure; the concrete inner algorithms are
// fixed once, in the prototype keys built by newCompositeAlgorithm.
//
// x509.go / parser.go / pkcs8.go integrate this via compositeAlgorithmByOID,
// compositeAlgorithmBySigAlgo, parseCompositePublicKey, parseCompositePrivateKey
// and CompositeVerify.

package x509

import (
	"crypto"
	"crypto/elliptic"
	"crypto/mldsa"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"io"
)

const compositeDomainPrefix = "CompositeAlgorithmSignatures2025"

// CompositeAlgorithm describes one composite signature algorithm as
// defined in draft-ietf-lamps-pq-composite-sigs.
type CompositeAlgorithm struct {
	Name  string
	Label string
	OID   asn1.ObjectIdentifier

	buildMPrime func(msg, ctx []byte) ([]byte, error)

	// privateKey and publicKey are prototypes: their inner keys hold no
	// real key material and are only ever asked to GenerateKey/Unmarshall.
	privateKey *CompositePrivateKey
	publicKey  *CompositePublicKey

	sigAlgo    SignatureAlgorithm
	pubKeyAlgo PublicKeyAlgorithm
}

// newBuildMPrime returns the buildMPrime closure for an algorithm using
// hash as PH and label as the domain-separation label. M' has two shapes
// (doc/composite/build_m_prime_activity.puml), chosen once here rather
// than branched on every call:
//
//	M' = Prefix || Label || len(ctx) || ctx || PH(msg)                 (ML-DSA)
//	M' = Prefix || len(Label) || Label || len(ctx) || ctx || PH(msg)   (otherwise)
func newBuildMPrime(isMLDSA bool, hash crypto.Hash, label string) func(msg, ctx []byte) ([]byte, error) {
	labelBytes := []byte(label)
	ph := func(msg []byte) []byte {
		if hash == crypto.SHA256 {
			d := sha256.Sum256(msg)
			return d[:]
		}
		d := sha512.Sum512(msg)
		return d[:]
	}
	if isMLDSA {
		return func(msg, ctx []byte) ([]byte, error) {
			if len(ctx) > 255 {
				return nil, errors.New("x509: composite context string too long (max 255 bytes)")
			}
			phMsg := ph(msg)
			mPrime := make([]byte, 0, len(compositeDomainPrefix)+len(labelBytes)+1+len(ctx)+len(phMsg))
			mPrime = append(mPrime, []byte(compositeDomainPrefix)...)
			mPrime = append(mPrime, labelBytes...)
			mPrime = append(mPrime, byte(len(ctx)))
			mPrime = append(mPrime, ctx...)
			mPrime = append(mPrime, phMsg...)
			return mPrime, nil
		}
	}
	return func(msg, ctx []byte) ([]byte, error) {
		if len(ctx) > 255 {
			return nil, errors.New("x509: composite context string too long (max 255 bytes)")
		}
		if len(labelBytes) > 255 {
			return nil, errors.New("x509: composite label too long (max 255 bytes)")
		}
		phMsg := ph(msg)
		mPrime := make([]byte, 0, len(compositeDomainPrefix)+1+len(labelBytes)+1+len(ctx)+len(phMsg))
		mPrime = append(mPrime, []byte(compositeDomainPrefix)...)
		mPrime = append(mPrime, byte(len(labelBytes)))
		mPrime = append(mPrime, labelBytes...)
		mPrime = append(mPrime, byte(len(ctx)))
		mPrime = append(mPrime, ctx...)
		mPrime = append(mPrime, phMsg...)
		return mPrime, nil
	}
}

// newCompositeAlgorithm builds one CompositeAlgorithm descriptor. protoN
// are prototype inner keys (real adapters constructed with a nil key —
// see x509_composite_mldsa.go / x509_composite_rsa.go); isMLDSA must
// reflect privProto1's algorithm. Adding a new algorithm never requires
// changing anything else in this file.
func newCompositeAlgorithm(
	name, label string, oid asn1.ObjectIdentifier, sigAlgo SignatureAlgorithm, pubKeyAlgo PublicKeyAlgorithm, isMLDSA bool, phHash crypto.Hash,
	privProto1, privProto2 InnerPrivateKey, pubProto1, pubProto2 InnerPublicKey,
) *CompositeAlgorithm {
	a := &CompositeAlgorithm{
		Name:        name,
		Label:       label,
		OID:         oid,
		buildMPrime: newBuildMPrime(isMLDSA, phHash, label),
		sigAlgo:     sigAlgo,
		pubKeyAlgo:  pubKeyAlgo,
	}
	a.privateKey = &CompositePrivateKey{innerSk1: privProto1, innerSk2: privProto2, oid: oid}
	a.publicKey = &CompositePublicKey{innerPk1: pubProto1, innerPk2: pubProto2, oid: oid}
	return a
}

// Pre-declared algorithm instances (spec Section 6 / Table 1).
var (
	MLDSA44_RSA2048_PSS_SHA256 = newCompositeAlgorithm(
		"MLDSA44-RSA2048-PSS-SHA256", "COMPSIG-MLDSA44-RSA2048-PSS-SHA256",
		asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 37}, CompositeMLDSA44RSA2048PSSHA256, CompositeMLDSARSA, true, crypto.SHA256,
		newMLDSAInnerPrivateKey(mldsa.MLDSA44(), "COMPSIG-MLDSA44-RSA2048-PSS-SHA256", nil),
		newRSAInnerPrivateKey(2048, crypto.SHA256, true, nil),
		newMLDSAInnerPublicKey(mldsa.MLDSA44(), "COMPSIG-MLDSA44-RSA2048-PSS-SHA256", nil),
		newRSAInnerPublicKey(2048, crypto.SHA256, true, nil),
	)
	MLDSA44_RSA2048_PKCS15_SHA256 = newCompositeAlgorithm(
		"MLDSA44-RSA2048-PKCS15-SHA256", "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256",
		asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 38}, CompositeMLDSA44RSA2048PKCS15SHA256, CompositeMLDSARSA, true, crypto.SHA256,
		newMLDSAInnerPrivateKey(mldsa.MLDSA44(), "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256", nil),
		newRSAInnerPrivateKey(2048, crypto.SHA256, false, nil),
		newMLDSAInnerPublicKey(mldsa.MLDSA44(), "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256", nil),
		newRSAInnerPublicKey(2048, crypto.SHA256, false, nil),
	)
	MLDSA65_RSA3072_PSS_SHA512 = newCompositeAlgorithm(
		"MLDSA65-RSA3072-PSS-SHA512", "COMPSIG-MLDSA65-RSA3072-PSS-SHA512",
		asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 41}, CompositeMLDSA65RSA3072PSSHA512, CompositeMLDSARSA, true, crypto.SHA512,
		newMLDSAInnerPrivateKey(mldsa.MLDSA65(), "COMPSIG-MLDSA65-RSA3072-PSS-SHA512", nil),
		newRSAInnerPrivateKey(3072, crypto.SHA256, true, nil),
		newMLDSAInnerPublicKey(mldsa.MLDSA65(), "COMPSIG-MLDSA65-RSA3072-PSS-SHA512", nil),
		newRSAInnerPublicKey(3072, crypto.SHA256, true, nil),
	)
	MLDSA65_RSA3072_PKCS15_SHA512 = newCompositeAlgorithm(
		"MLDSA65-RSA3072-PKCS15-SHA512", "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512",
		asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 42}, CompositeMLDSA65RSA3072PKCS15SHA512, CompositeMLDSARSA, true, crypto.SHA512,
		newMLDSAInnerPrivateKey(mldsa.MLDSA65(), "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512", nil),
		newRSAInnerPrivateKey(3072, crypto.SHA256, false, nil),
		newMLDSAInnerPublicKey(mldsa.MLDSA65(), "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512", nil),
		newRSAInnerPublicKey(3072, crypto.SHA256, false, nil),
	)
	MLDSA65_RSA4096_PSS_SHA512 = newCompositeAlgorithm(
		"MLDSA65-RSA4096-PSS-SHA512", "COMPSIG-MLDSA65-RSA4096-PSS-SHA512",
		asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 43}, CompositeMLDSA65RSA4096PSSHA512, CompositeMLDSARSA, true, crypto.SHA512,
		newMLDSAInnerPrivateKey(mldsa.MLDSA65(), "COMPSIG-MLDSA65-RSA4096-PSS-SHA512", nil),
		newRSAInnerPrivateKey(4096, crypto.SHA384, true, nil),
		newMLDSAInnerPublicKey(mldsa.MLDSA65(), "COMPSIG-MLDSA65-RSA4096-PSS-SHA512", nil),
		newRSAInnerPublicKey(4096, crypto.SHA384, true, nil),
	)
	MLDSA65_RSA4096_PKCS15_SHA512 = newCompositeAlgorithm(
		"MLDSA65-RSA4096-PKCS15-SHA512", "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512",
		asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 44}, CompositeMLDSA65RSA4096PKCS15SHA512, CompositeMLDSARSA, true, crypto.SHA512,
		newMLDSAInnerPrivateKey(mldsa.MLDSA65(), "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512", nil),
		newRSAInnerPrivateKey(4096, crypto.SHA384, false, nil),
		newMLDSAInnerPublicKey(mldsa.MLDSA65(), "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512", nil),
		newRSAInnerPublicKey(4096, crypto.SHA384, false, nil),
	)
	MLDSA87_RSA3072_PSS_SHA512 = newCompositeAlgorithm(
		"MLDSA87-RSA3072-PSS-SHA512", "COMPSIG-MLDSA87-RSA3072-PSS-SHA512",
		asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 52}, CompositeMLDSA87RSA3072PSSHA512, CompositeMLDSARSA, true, crypto.SHA512,
		newMLDSAInnerPrivateKey(mldsa.MLDSA87(), "COMPSIG-MLDSA87-RSA3072-PSS-SHA512", nil),
		newRSAInnerPrivateKey(3072, crypto.SHA256, true, nil),
		newMLDSAInnerPublicKey(mldsa.MLDSA87(), "COMPSIG-MLDSA87-RSA3072-PSS-SHA512", nil),
		newRSAInnerPublicKey(3072, crypto.SHA256, true, nil),
	)
	MLDSA87_RSA4096_PSS_SHA512 = newCompositeAlgorithm(
		"MLDSA87-RSA4096-PSS-SHA512", "COMPSIG-MLDSA87-RSA4096-PSS-SHA512",
		asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 53}, CompositeMLDSA87RSA4096PSSHA512, CompositeMLDSARSA, true, crypto.SHA512,
		newMLDSAInnerPrivateKey(mldsa.MLDSA87(), "COMPSIG-MLDSA87-RSA4096-PSS-SHA512", nil),
		newRSAInnerPrivateKey(4096, crypto.SHA384, true, nil),
		newMLDSAInnerPublicKey(mldsa.MLDSA87(), "COMPSIG-MLDSA87-RSA4096-PSS-SHA512", nil),
		newRSAInnerPublicKey(4096, crypto.SHA384, true, nil),
	)

	// Composite ML-DSA+ECDSA algorithms (draft-ietf-lamps-pq-composite-sigs-19,
	// Section 6 / Table 1). Only the NIST-curve combinations are supported:
	// the brainpool-curve entries (id-MLDSA65-ECDSA-brainpoolP256r1-SHA512,
	// id-MLDSA87-ECDSA-brainpoolP384r1-SHA512) have no Go standard library
	// curve implementation and are intentionally omitted.
	MLDSA44_ECDSA_P256_SHA256 = newCompositeAlgorithm(
		"MLDSA44-ECDSA-P256-SHA256", "COMPSIG-MLDSA44-ECDSA-P256-SHA256",
		asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 40}, CompositeMLDSA44ECDSAP256SHA256, CompositeMLDSAECDSA, true, crypto.SHA256,
		newMLDSAInnerPrivateKey(mldsa.MLDSA44(), "COMPSIG-MLDSA44-ECDSA-P256-SHA256", nil),
		newECDSAInnerPrivateKey(elliptic.P256(), crypto.SHA256, nil),
		newMLDSAInnerPublicKey(mldsa.MLDSA44(), "COMPSIG-MLDSA44-ECDSA-P256-SHA256", nil),
		newECDSAInnerPublicKey(elliptic.P256(), crypto.SHA256, nil),
	)
	MLDSA65_ECDSA_P256_SHA512 = newCompositeAlgorithm(
		"MLDSA65-ECDSA-P256-SHA512", "COMPSIG-MLDSA65-ECDSA-P256-SHA512",
		asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 45}, CompositeMLDSA65ECDSAP256SHA512, CompositeMLDSAECDSA, true, crypto.SHA512,
		newMLDSAInnerPrivateKey(mldsa.MLDSA65(), "COMPSIG-MLDSA65-ECDSA-P256-SHA512", nil),
		newECDSAInnerPrivateKey(elliptic.P256(), crypto.SHA512, nil),
		newMLDSAInnerPublicKey(mldsa.MLDSA65(), "COMPSIG-MLDSA65-ECDSA-P256-SHA512", nil),
		newECDSAInnerPublicKey(elliptic.P256(), crypto.SHA512, nil),
	)
	MLDSA65_ECDSA_P384_SHA512 = newCompositeAlgorithm(
		"MLDSA65-ECDSA-P384-SHA512", "COMPSIG-MLDSA65-ECDSA-P384-SHA512",
		asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 46}, CompositeMLDSA65ECDSAP384SHA512, CompositeMLDSAECDSA, true, crypto.SHA512,
		newMLDSAInnerPrivateKey(mldsa.MLDSA65(), "COMPSIG-MLDSA65-ECDSA-P384-SHA512", nil),
		newECDSAInnerPrivateKey(elliptic.P384(), crypto.SHA512, nil),
		newMLDSAInnerPublicKey(mldsa.MLDSA65(), "COMPSIG-MLDSA65-ECDSA-P384-SHA512", nil),
		newECDSAInnerPublicKey(elliptic.P384(), crypto.SHA512, nil),
	)
	MLDSA87_ECDSA_P384_SHA512 = newCompositeAlgorithm(
		"MLDSA87-ECDSA-P384-SHA512", "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
		asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 49}, CompositeMLDSA87ECDSAP384SHA512, CompositeMLDSAECDSA, true, crypto.SHA512,
		newMLDSAInnerPrivateKey(mldsa.MLDSA87(), "COMPSIG-MLDSA87-ECDSA-P384-SHA512", nil),
		newECDSAInnerPrivateKey(elliptic.P384(), crypto.SHA512, nil),
		newMLDSAInnerPublicKey(mldsa.MLDSA87(), "COMPSIG-MLDSA87-ECDSA-P384-SHA512", nil),
		newECDSAInnerPublicKey(elliptic.P384(), crypto.SHA512, nil),
	)
	MLDSA87_ECDSA_P521_SHA512 = newCompositeAlgorithm(
		"MLDSA87-ECDSA-P521-SHA512", "COMPSIG-MLDSA87-ECDSA-P521-SHA512",
		asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 54}, CompositeMLDSA87ECDSAP521SHA512, CompositeMLDSAECDSA, true, crypto.SHA512,
		newMLDSAInnerPrivateKey(mldsa.MLDSA87(), "COMPSIG-MLDSA87-ECDSA-P521-SHA512", nil),
		newECDSAInnerPrivateKey(elliptic.P521(), crypto.SHA512, nil),
		newMLDSAInnerPublicKey(mldsa.MLDSA87(), "COMPSIG-MLDSA87-ECDSA-P521-SHA512", nil),
		newECDSAInnerPublicKey(elliptic.P521(), crypto.SHA512, nil),
	)

	// Composite ML-DSA+Ed25519 algorithms (draft-ietf-lamps-pq-composite-sigs-19,
	// Section 6 / Table 1). The draft defines no ML-DSA87+Ed25519 combination
	// (ML-DSA-87 pairs with Ed448 instead, which isn't implemented here).
	MLDSA44_Ed25519_SHA512 = newCompositeAlgorithm(
		"MLDSA44-Ed25519-SHA512", "COMPSIG-MLDSA44-Ed25519-SHA512",
		asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 39}, CompositeMLDSA44Ed25519SHA512, CompositeMLDSAEd25519, true, crypto.SHA512,
		newMLDSAInnerPrivateKey(mldsa.MLDSA44(), "COMPSIG-MLDSA44-Ed25519-SHA512", nil),
		newEd25519InnerPrivateKey(nil),
		newMLDSAInnerPublicKey(mldsa.MLDSA44(), "COMPSIG-MLDSA44-Ed25519-SHA512", nil),
		newEd25519InnerPublicKey(nil),
	)
	MLDSA65_Ed25519_SHA512 = newCompositeAlgorithm(
		"MLDSA65-Ed25519-SHA512", "COMPSIG-MLDSA65-Ed25519-SHA512",
		asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 48}, CompositeMLDSA65Ed25519SHA512, CompositeMLDSAEd25519, true, crypto.SHA512,
		newMLDSAInnerPrivateKey(mldsa.MLDSA65(), "COMPSIG-MLDSA65-Ed25519-SHA512", nil),
		newEd25519InnerPrivateKey(nil),
		newMLDSAInnerPublicKey(mldsa.MLDSA65(), "COMPSIG-MLDSA65-Ed25519-SHA512", nil),
		newEd25519InnerPublicKey(nil),
	)

	// CompositeAlgorithms is the ordered list of all supported composite
	// algorithm descriptors.
	CompositeAlgorithms = []*CompositeAlgorithm{
		MLDSA44_RSA2048_PSS_SHA256,
		MLDSA44_RSA2048_PKCS15_SHA256,
		MLDSA65_RSA3072_PSS_SHA512,
		MLDSA65_RSA3072_PKCS15_SHA512,
		MLDSA65_RSA4096_PSS_SHA512,
		MLDSA65_RSA4096_PKCS15_SHA512,
		MLDSA87_RSA3072_PSS_SHA512,
		MLDSA87_RSA4096_PSS_SHA512,
		MLDSA44_ECDSA_P256_SHA256,
		MLDSA65_ECDSA_P256_SHA512,
		MLDSA65_ECDSA_P384_SHA512,
		MLDSA87_ECDSA_P384_SHA512,
		MLDSA87_ECDSA_P521_SHA512,
		MLDSA44_Ed25519_SHA512,
		MLDSA65_Ed25519_SHA512,
	}
)

var (
	compositeAlgsByOID     map[string]*CompositeAlgorithm
	compositeAlgsBySigAlgo map[SignatureAlgorithm]*CompositeAlgorithm
)

func init() {
	compositeAlgsByOID = make(map[string]*CompositeAlgorithm, len(CompositeAlgorithms))
	compositeAlgsBySigAlgo = make(map[SignatureAlgorithm]*CompositeAlgorithm, len(CompositeAlgorithms))
	for _, a := range CompositeAlgorithms {
		compositeAlgsByOID[a.OID.String()] = a
		compositeAlgsBySigAlgo[a.sigAlgo] = a

		// So isRSAPSS/hashFunc/String and checkSignature work for composite algos too.
		signatureAlgorithmDetails = append(signatureAlgorithmDetails, struct {
			algo       SignatureAlgorithm
			name       string
			oid        asn1.ObjectIdentifier
			params     asn1.RawValue
			pubKeyAlgo PublicKeyAlgorithm
			hash       crypto.Hash
			isRSAPSS   bool
		}{
			a.sigAlgo,
			a.Name,
			a.OID,
			emptyRawValue,
			a.pubKeyAlgo,
			crypto.Hash(0), // composite does its own internal PH
			false,
		})
	}
}

func compositeAlgorithmByOID(oid asn1.ObjectIdentifier) *CompositeAlgorithm {
	return compositeAlgsByOID[oid.String()]
}

func compositeAlgorithmBySigAlgo(algo SignatureAlgorithm) *CompositeAlgorithm {
	return compositeAlgsBySigAlgo[algo]
}

// GenerateCompositeKey generates a fresh composite key pair for algorithm a.
// If rnd is nil, [crypto/rand.Reader] is used.
func (a *CompositeAlgorithm) GenerateCompositeKey(rnd io.Reader) (*CompositePublicKey, *CompositePrivateKey, error) {
	if rnd == nil {
		rnd = cryptorand.Reader
	}
	sk, err := a.privateKey.generateKey(rnd)
	if err != nil {
		return nil, nil, err
	}
	return sk.Public().(*CompositePublicKey), sk, nil
}

// CompositeSign produces a composite signature over msg using sk.
// ctx is the optional context string (max 255 bytes; nil is treated as empty).
// If rnd is nil, [crypto/rand.Reader] is used.
func (a *CompositeAlgorithm) CompositeSign(rnd io.Reader, sk *CompositePrivateKey, msg, ctx []byte) ([]byte, error) {
	if rnd == nil {
		rnd = cryptorand.Reader
	}
	mPrime, err := a.buildMPrime(msg, ctx)
	if err != nil {
		return nil, err
	}
	return sk.sign(rnd, mPrime)
}

// CompositeVerify checks that sig is a valid composite signature over msg by pk.
// ctx must match the context string used during signing.
func (a *CompositeAlgorithm) CompositeVerify(pk *CompositePublicKey, msg, ctx, sig []byte) bool {
	mPrime, err := a.buildMPrime(msg, ctx)
	if err != nil {
		return false
	}
	return pk.verify(mPrime, sig)
}

// parseCompositePublicKey deserializes a raw (non-SPKI) composite public key.
func (a *CompositeAlgorithm) parseCompositePublicKey(data []byte) (*CompositePublicKey, error) {
	return a.publicKey.unmarshall(data)
}

// ParseCompositePublicKeyRaw parses a raw (non-SPKI) composite public key.
// For standard SPKI encoding use [ParsePKIXPublicKey].
func (a *CompositeAlgorithm) ParseCompositePublicKeyRaw(data []byte) (*CompositePublicKey, error) {
	return a.parseCompositePublicKey(data)
}

// parseCompositePrivateKey deserializes a raw (non-PKCS#8) composite private key.
func (a *CompositeAlgorithm) parseCompositePrivateKey(data []byte) (*CompositePrivateKey, error) {
	return a.privateKey.unmarshall(data)
}

// ParseCompositePrivateKeyRaw parses a raw (non-PKCS#8) composite private key.
// For standard PKCS #8 encoding use [ParsePKCS8PrivateKey].
func (a *CompositeAlgorithm) ParseCompositePrivateKeyRaw(data []byte) (*CompositePrivateKey, error) {
	return a.parseCompositePrivateKey(data)
}
