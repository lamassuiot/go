// Package x509 — composite ML-DSA+RSA signature schemes
//
// This file implements the composite ML-DSA+RSA algorithms defined in
// draft-ietf-lamps-pq-composite-sigs-19. Because the implementation lives
// directly inside package x509 it can use the existing PKCS #1 helpers
// (MarshalPKCS1PublicKey, ParsePKCS1PublicKey, MarshalPKCS1PrivateKey,
// ParsePKCS1PrivateKey) without any import-cycle concerns.
//
// The package-level integration points (marshalPublicKey, parsePublicKey,
// MarshalPKCS8PrivateKey, ParsePKCS8PrivateKey, checkSignature,
// signingParamsForPublicKey, getPublicKeyAlgorithmFromOID) are extended via
// case branches in x509.go / parser.go / pkcs8.go.  The
// SignatureAlgorithm / PublicKeyAlgorithm constants are also in x509.go.

package x509

import (
	"crypto"
	"crypto/mldsa"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"io"
)

// ── domain-separation constant ────────────────────────────────────────────────

const compositeDomainPrefix = "CompositeAlgorithmSignatures2025"

// ── CompositeAlgorithm ────────────────────────────────────────────────────────

// CompositeAlgorithm describes one composite ML-DSA+RSA parameter set as
// defined in draft-ietf-lamps-pq-composite-sigs-19.
type CompositeAlgorithm struct {
	// Name is the short human-readable identifier.
	Name string
	// Label is the domain-separation string used in M' and as the ML-DSA ctx.
	Label string
	// OID is the ASN.1 object identifier assigned to this algorithm.
	OID asn1.ObjectIdentifier

	params  mldsa.Parameters
	rsaBits int
	hash    crypto.Hash // PH hash applied to msg in M' (SHA-256 or SHA-512)
	rsaHash crypto.Hash // hash used for RSA signing/verification of M'
	pss     bool        // true → RSA-PSS, false → PKCS #1 v1.5
	sigAlgo SignatureAlgorithm
}

// Pre-declared algorithm instances (spec Section 6 / Table 1).
var (
	MLDSA44_RSA2048_PSS_SHA256 = &CompositeAlgorithm{
		Name:    "MLDSA44-RSA2048-PSS-SHA256",
		Label:   "COMPSIG-MLDSA44-RSA2048-PSS-SHA256",
		OID:     asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 37},
		params:  mldsa.MLDSA44(),
		rsaBits: 2048,
		hash:    crypto.SHA256,
		rsaHash: crypto.SHA256,
		pss:     true,
		sigAlgo: CompositeMLDSA44RSA2048PSSHA256,
	}
	MLDSA44_RSA2048_PKCS15_SHA256 = &CompositeAlgorithm{
		Name:    "MLDSA44-RSA2048-PKCS15-SHA256",
		Label:   "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256",
		OID:     asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 38},
		params:  mldsa.MLDSA44(),
		rsaBits: 2048,
		hash:    crypto.SHA256,
		rsaHash: crypto.SHA256,
		pss:     false,
		sigAlgo: CompositeMLDSA44RSA2048PKCS15SHA256,
	}
	MLDSA65_RSA3072_PSS_SHA512 = &CompositeAlgorithm{
		Name:    "MLDSA65-RSA3072-PSS-SHA512",
		Label:   "COMPSIG-MLDSA65-RSA3072-PSS-SHA512",
		OID:     asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 41},
		params:  mldsa.MLDSA65(),
		rsaBits: 3072,
		hash:    crypto.SHA512,
		rsaHash: crypto.SHA256,
		pss:     true,
		sigAlgo: CompositeMLDSA65RSA3072PSSHA512,
	}
	MLDSA65_RSA3072_PKCS15_SHA512 = &CompositeAlgorithm{
		Name:    "MLDSA65-RSA3072-PKCS15-SHA512",
		Label:   "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512",
		OID:     asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 42},
		params:  mldsa.MLDSA65(),
		rsaBits: 3072,
		hash:    crypto.SHA512,
		rsaHash: crypto.SHA256,
		pss:     false,
		sigAlgo: CompositeMLDSA65RSA3072PKCS15SHA512,
	}
	MLDSA65_RSA4096_PSS_SHA512 = &CompositeAlgorithm{
		Name:    "MLDSA65-RSA4096-PSS-SHA512",
		Label:   "COMPSIG-MLDSA65-RSA4096-PSS-SHA512",
		OID:     asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 43},
		params:  mldsa.MLDSA65(),
		rsaBits: 4096,
		hash:    crypto.SHA512,
		rsaHash: crypto.SHA384,
		pss:     true,
		sigAlgo: CompositeMLDSA65RSA4096PSSHA512,
	}
	MLDSA65_RSA4096_PKCS15_SHA512 = &CompositeAlgorithm{
		Name:    "MLDSA65-RSA4096-PKCS15-SHA512",
		Label:   "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512",
		OID:     asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 44},
		params:  mldsa.MLDSA65(),
		rsaBits: 4096,
		hash:    crypto.SHA512,
		rsaHash: crypto.SHA384,
		pss:     false,
		sigAlgo: CompositeMLDSA65RSA4096PKCS15SHA512,
	}
	MLDSA87_RSA3072_PSS_SHA512 = &CompositeAlgorithm{
		Name:    "MLDSA87-RSA3072-PSS-SHA512",
		Label:   "COMPSIG-MLDSA87-RSA3072-PSS-SHA512",
		OID:     asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 52},
		params:  mldsa.MLDSA87(),
		rsaBits: 3072,
		hash:    crypto.SHA512,
		rsaHash: crypto.SHA256,
		pss:     true,
		sigAlgo: CompositeMLDSA87RSA3072PSSHA512,
	}
	MLDSA87_RSA4096_PSS_SHA512 = &CompositeAlgorithm{
		Name:    "MLDSA87-RSA4096-PSS-SHA512",
		Label:   "COMPSIG-MLDSA87-RSA4096-PSS-SHA512",
		OID:     asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 53},
		params:  mldsa.MLDSA87(),
		rsaBits: 4096,
		hash:    crypto.SHA512,
		rsaHash: crypto.SHA384,
		pss:     true,
		sigAlgo: CompositeMLDSA87RSA4096PSSHA512,
	}

	// CompositeAlgorithms is the ordered list of all supported composite
	// ML-DSA+RSA algorithm descriptors.
	CompositeAlgorithms = []*CompositeAlgorithm{
		MLDSA44_RSA2048_PSS_SHA256,
		MLDSA44_RSA2048_PKCS15_SHA256,
		MLDSA65_RSA3072_PSS_SHA512,
		MLDSA65_RSA3072_PKCS15_SHA512,
		MLDSA65_RSA4096_PSS_SHA512,
		MLDSA65_RSA4096_PKCS15_SHA512,
		MLDSA87_RSA3072_PSS_SHA512,
		MLDSA87_RSA4096_PSS_SHA512,
	}
)

// compositeAlgsByOID is keyed by OID dotted-decimal string.
var compositeAlgsByOID map[string]*CompositeAlgorithm

// compositeAlgsBySigAlgo is keyed by SignatureAlgorithm constant.
var compositeAlgsBySigAlgo map[SignatureAlgorithm]*CompositeAlgorithm

func init() {
	compositeAlgsByOID = make(map[string]*CompositeAlgorithm, len(CompositeAlgorithms))
	compositeAlgsBySigAlgo = make(map[SignatureAlgorithm]*CompositeAlgorithm, len(CompositeAlgorithms))
	for _, a := range CompositeAlgorithms {
		compositeAlgsByOID[a.OID.String()] = a
		compositeAlgsBySigAlgo[a.sigAlgo] = a

		// Register in signatureAlgorithmDetails so that
		// getSignatureAlgorithmFromAI and String() work automatically.
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
			CompositeMLDSARSA,
			crypto.Hash(0), // composite does its own internal PH
			false,
		})
	}
}

// compositeAlgorithmByOID returns the CompositeAlgorithm for oid, or nil.
func compositeAlgorithmByOID(oid asn1.ObjectIdentifier) *CompositeAlgorithm {
	return compositeAlgsByOID[oid.String()]
}

// compositeAlgorithmBySigAlgo returns the CompositeAlgorithm for algo, or nil.
func compositeAlgorithmBySigAlgo(algo SignatureAlgorithm) *CompositeAlgorithm {
	return compositeAlgsBySigAlgo[algo]
}

// ── Key types ──────────────────────────────────────────────────────────────────

// CompositePublicKey holds the ML-DSA and RSA public key components for a
// composite algorithm.
type CompositePublicKey struct {
	mldsaPK *mldsa.PublicKey
	rsaPK   *rsa.PublicKey
	alg     *CompositeAlgorithm
}

// Algorithm returns the composite algorithm this key belongs to.
func (pk *CompositePublicKey) Algorithm() *CompositeAlgorithm { return pk.alg }

// Equal reports whether pk and x have the same algorithm and key material.
// It implements the interface checked by [crypto/x509.CreateCertificate].
func (pk *CompositePublicKey) Equal(x crypto.PublicKey) bool {
	other, ok := x.(*CompositePublicKey)
	if !ok || pk.alg != other.alg {
		return false
	}
	return pk.mldsaPK.Equal(other.mldsaPK) && pk.rsaPK.Equal(other.rsaPK)
}

// CompositePrivateKey holds the ML-DSA and RSA private key components for a
// composite algorithm.
type CompositePrivateKey struct {
	mldsaSK *mldsa.PrivateKey
	rsaSK   *rsa.PrivateKey
	alg     *CompositeAlgorithm
}

// Algorithm returns the composite algorithm this key belongs to.
func (sk *CompositePrivateKey) Algorithm() *CompositeAlgorithm { return sk.alg }

// Public implements [crypto.Signer]. It returns the corresponding
// [*CompositePublicKey] as a [crypto.PublicKey]; use a type assertion to
// recover the concrete type.
func (sk *CompositePrivateKey) Public() crypto.PublicKey {
	return &CompositePublicKey{
		mldsaPK: sk.mldsaSK.PublicKey(),
		rsaPK:   &sk.rsaSK.PublicKey,
		alg:     sk.alg,
	}
}

// ── crypto.Signer ──────────────────────────────────────────────────────────────

// CompositeSignerOpts implements [crypto.SignerOpts] for composite algorithms.
//
// [HashFunc] returns [crypto.Hash](0), indicating that no external pre-hashing
// is performed; callers MUST pass the raw, un-hashed message as the digest
// argument to [CompositePrivateKey.Sign].
//
// Use CompositeSignerOpts{Context: ctx} to attach a context string (max 255
// bytes).  When used with [CreateCertificate] / [signTBS] the options will be
// a plain [crypto.Hash] value (0), which is interpreted as an empty context.
type CompositeSignerOpts struct {
	// Context is the optional context string (max 255 bytes). nil ≡ empty.
	Context []byte
}

// HashFunc returns [crypto.Hash](0) — composite algorithms perform their own
// internal pre-hashing.
func (CompositeSignerOpts) HashFunc() crypto.Hash { return 0 }

// Sign implements [crypto.Signer].
//
// msg must be the full, un-hashed message.  PH is applied internally.
// Pass [CompositeSignerOpts] to carry a context string; any other
// [crypto.SignerOpts] value is treated as an empty context.
func (sk *CompositePrivateKey) Sign(rnd io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	var ctx []byte
	if so, ok := opts.(CompositeSignerOpts); ok {
		ctx = so.Context
	}
	return sk.alg.CompositeSign(rnd, sk, msg, ctx)
}

// ── Key generation ─────────────────────────────────────────────────────────────

// GenerateCompositeKey generates a fresh composite key pair for algorithm a.
// If rnd is nil, [crypto/rand.Reader] is used.
func (a *CompositeAlgorithm) GenerateCompositeKey(rnd io.Reader) (*CompositePublicKey, *CompositePrivateKey, error) {
	if rnd == nil {
		rnd = cryptorand.Reader
	}
	var seed [mldsa.PrivateKeySize]byte
	if _, err := io.ReadFull(rnd, seed[:]); err != nil {
		return nil, nil, err
	}
	mldsaSK, err := mldsa.NewPrivateKey(a.params, seed[:])
	if err != nil {
		return nil, nil, err
	}
	rsaSK, err := rsa.GenerateKey(rnd, a.rsaBits)
	if err != nil {
		return nil, nil, err
	}
	pk := &CompositePublicKey{mldsaPK: mldsaSK.PublicKey(), rsaPK: &rsaSK.PublicKey, alg: a}
	sk := &CompositePrivateKey{mldsaSK: mldsaSK, rsaSK: rsaSK, alg: a}
	return pk, sk, nil
}

// ── Core sign / verify ─────────────────────────────────────────────────────────

// compositeBuildMPrime constructs the message representative M' per
// draft-ietf-lamps-pq-composite-sigs-19 Section 2.2:
//
//	M' = Prefix || Label || len(ctx) as 1 byte || ctx || PH(msg)
func (a *CompositeAlgorithm) compositeBuildMPrime(msg, ctx []byte) []byte {
	var phMsg []byte
	if a.hash == crypto.SHA256 {
		d := sha256.Sum256(msg)
		phMsg = d[:]
	} else {
		d := sha512.Sum512(msg)
		phMsg = d[:]
	}
	labelBytes := []byte(a.Label)
	mPrime := make([]byte, 0, len(compositeDomainPrefix)+len(labelBytes)+1+len(ctx)+len(phMsg))
	mPrime = append(mPrime, []byte(compositeDomainPrefix)...)
	mPrime = append(mPrime, labelBytes...)
	mPrime = append(mPrime, byte(len(ctx)))
	mPrime = append(mPrime, ctx...)
	mPrime = append(mPrime, phMsg...)
	return mPrime
}

// compositeHashMPrime hashes mPrime with the RSA signing hash (a.rsaHash).
func (a *CompositeAlgorithm) compositeHashMPrime(mPrime []byte) []byte {
	switch a.rsaHash {
	case crypto.SHA256:
		d := sha256.Sum256(mPrime)
		return d[:]
	case crypto.SHA384:
		d := sha512.Sum384(mPrime)
		return d[:]
	default:
		d := sha512.Sum512(mPrime)
		return d[:]
	}
}

// CompositeSign produces a composite signature over msg using sk.
// ctx is the optional context string (max 255 bytes; nil is treated as empty).
// If rnd is nil, [crypto/rand.Reader] is used.
func (a *CompositeAlgorithm) CompositeSign(rnd io.Reader, sk *CompositePrivateKey, msg, ctx []byte) ([]byte, error) {
	if sk.alg != a {
		return nil, errors.New("x509: composite key belongs to a different algorithm")
	}
	if len(ctx) > 255 {
		return nil, errors.New("x509: composite context string too long (max 255 bytes)")
	}
	if rnd == nil {
		rnd = cryptorand.Reader
	}

	mPrime := a.compositeBuildMPrime(msg, ctx)

	mldsaSig, err := sk.mldsaSK.Sign(nil, mPrime, &mldsa.Options{Context: a.Label})
	if err != nil {
		return nil, err
	}

	digest := a.compositeHashMPrime(mPrime)
	var rsaSig []byte
	if a.pss {
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
		rsaSig, err = rsa.SignPSS(rnd, sk.rsaSK, a.rsaHash, digest, opts)
	} else {
		rsaSig, err = rsa.SignPKCS1v15(rnd, sk.rsaSK, a.rsaHash, digest)
	}
	if err != nil {
		return nil, err
	}
	return append(mldsaSig, rsaSig...), nil
}

// CompositeVerify checks that sig is a valid composite signature over msg by pk.
// ctx must match the context string used during signing.
func (a *CompositeAlgorithm) CompositeVerify(pk *CompositePublicKey, msg, ctx, sig []byte) bool {
	if pk.alg != a {
		return false
	}
	if len(ctx) > 255 {
		return false
	}
	mldsaSigSize := a.params.SignatureSize()
	if len(sig) <= mldsaSigSize {
		return false
	}
	mldsaSig := sig[:mldsaSigSize]
	rsaSig := sig[mldsaSigSize:]

	mPrime := a.compositeBuildMPrime(msg, ctx)
	if mldsa.Verify(pk.mldsaPK, mPrime, mldsaSig, &mldsa.Options{Context: a.Label}) != nil {
		return false
	}

	digest := a.compositeHashMPrime(mPrime)
	if a.pss {
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
		return rsa.VerifyPSS(pk.rsaPK, a.rsaHash, digest, rsaSig, opts) == nil
	}
	return rsa.VerifyPKCS1v15(pk.rsaPK, a.rsaHash, digest, rsaSig) == nil
}

// ── Key serialization ──────────────────────────────────────────────────────────
//
// Raw (non-PKIX) key encoding for the composite algorithms:
//
//   PublicKey  = mldsaPublicKey (fixed size) || rsaPublicKey (PKCS #1 RSAPublicKey DER)
//   PrivateKey = mldsaPrivateKey (fixed size) || rsaPrivateKey (PKCS #1 RSAPrivateKey DER)
//
// For SPKI / PKCS #8 use the standard x509.MarshalPKIXPublicKey /
// x509.MarshalPKCS8PrivateKey and x509.ParsePKIXPublicKey /
// x509.ParsePKCS8PrivateKey functions.

// marshalCompositePublicKey serializes pk into its raw wire format.
func (a *CompositeAlgorithm) marshalCompositePublicKey(pk *CompositePublicKey) ([]byte, error) {
	if pk.alg != a {
		return nil, errors.New("x509: composite key belongs to a different algorithm")
	}
	mldsaBytes := pk.mldsaPK.Bytes()
	rsaDER := MarshalPKCS1PublicKey(pk.rsaPK)
	return append(mldsaBytes, rsaDER...), nil
}

// parseCompositePublicKey deserializes a raw composite public key.
func (a *CompositeAlgorithm) parseCompositePublicKey(data []byte) (*CompositePublicKey, error) {
	mldsaSize := a.params.PublicKeySize()
	if len(data) <= mldsaSize {
		return nil, errors.New("x509: composite public key data too short")
	}
	mldsaPK, err := mldsa.NewPublicKey(a.params, data[:mldsaSize])
	if err != nil {
		return nil, err
	}
	rsaPK, err := ParsePKCS1PublicKey(data[mldsaSize:])
	if err != nil {
		return nil, err
	}
	return &CompositePublicKey{mldsaPK: mldsaPK, rsaPK: rsaPK, alg: a}, nil
}

// marshalCompositePrivateKey serializes sk into its raw wire format.
func (a *CompositeAlgorithm) marshalCompositePrivateKey(sk *CompositePrivateKey) ([]byte, error) {
	if sk.alg != a {
		return nil, errors.New("x509: composite key belongs to a different algorithm")
	}
	mldsaBytes := sk.mldsaSK.Bytes()
	rsaDER := MarshalPKCS1PrivateKey(sk.rsaSK)
	return append(mldsaBytes, rsaDER...), nil
}

// ParseCompositePublicKeyRaw parses a raw (non-SPKI) composite public key as
// produced by the IETF test vectors or by an earlier call to the internal
// marshaling functions.  For standard SPKI encoding use [ParsePKIXPublicKey].
func (a *CompositeAlgorithm) ParseCompositePublicKeyRaw(data []byte) (*CompositePublicKey, error) {
	return a.parseCompositePublicKey(data)
}

// parseCompositePrivateKey deserializes a raw composite private key.
func (a *CompositeAlgorithm) parseCompositePrivateKey(data []byte) (*CompositePrivateKey, error) {
	mldsaSize := mldsa.PrivateKeySize
	if len(data) <= mldsaSize {
		return nil, errors.New("x509: composite private key data too short")
	}
	mldsaSK, err := mldsa.NewPrivateKey(a.params, data[:mldsaSize])
	if err != nil {
		return nil, err
	}
	rsaSK, err := ParsePKCS1PrivateKey(data[mldsaSize:])
	if err != nil {
		return nil, err
	}
	return &CompositePrivateKey{mldsaSK: mldsaSK, rsaSK: rsaSK, alg: a}, nil
}

// ParseCompositePrivateKeyRaw parses a raw (non-PKCS#8) composite private key.
// For standard PKCS #8 encoding use [ParsePKCS8PrivateKey].
func (a *CompositeAlgorithm) ParseCompositePrivateKeyRaw(data []byte) (*CompositePrivateKey, error) {
	return a.parseCompositePrivateKey(data)
}
