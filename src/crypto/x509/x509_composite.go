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
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"io"

	"cloudflare/circl/sign/mldsa/mldsa44"
	"cloudflare/circl/sign/mldsa/mldsa65"
	"cloudflare/circl/sign/mldsa/mldsa87"
)

// ── domain-separation constant ────────────────────────────────────────────────

const compositeDomainPrefix = "CompositeAlgorithmSignatures2025"

// ── mldsaImpl ─────────────────────────────────────────────────────────────────

// mldsaImpl abstracts over the three ML-DSA parameter sets so that
// CompositeAlgorithm can hold a single implementation value.
type mldsaImpl interface {
	generateKey(rnd io.Reader) (mldsaPK interface{}, mldsaSK interface{}, err error)
	signTo(sk interface{}, msg, ctx []byte, sig []byte) error
	verify(pk interface{}, msg, ctx, sig []byte) bool
	publicKeyFromPrivate(sk interface{}) interface{}
	publicKeyBytes(pk interface{}) []byte
	privateKeyBytes(sk interface{}) []byte
	unmarshalPublicKey(data []byte) (interface{}, error)
	unmarshalPrivateKey(data []byte) (interface{}, error)
	publicKeySize() int
	privateKeySize() int // always 32 (seed size) for wire format
	signatureSize() int
}

// mldsaSeedKey44/65/87 bundles a 32-byte seed with its expanded private key so
// that serialization can return the seed and signing can use the cached key.
type mldsaSeedKey44 struct {
	seed [mldsa44.SeedSize]byte
	sk   *mldsa44.PrivateKey
}
type mldsaSeedKey65 struct {
	seed [mldsa65.SeedSize]byte
	sk   *mldsa65.PrivateKey
}
type mldsaSeedKey87 struct {
	seed [mldsa87.SeedSize]byte
	sk   *mldsa87.PrivateKey
}

// ── mldsa44 adapter ───────────────────────────────────────────────────────────

type compositeImpl44 struct{}

func (compositeImpl44) generateKey(rnd io.Reader) (interface{}, interface{}, error) {
	var seed [mldsa44.SeedSize]byte
	if _, err := io.ReadFull(rnd, seed[:]); err != nil {
		return nil, nil, err
	}
	pk, sk := mldsa44.NewKeyFromSeed(&seed)
	return pk, &mldsaSeedKey44{seed: seed, sk: sk}, nil
}
func (compositeImpl44) signTo(sk interface{}, msg, ctx []byte, sig []byte) error {
	return mldsa44.SignTo(sk.(*mldsaSeedKey44).sk, msg, ctx, false, sig)
}
func (compositeImpl44) verify(pk interface{}, msg, ctx, sig []byte) bool {
	return mldsa44.Verify(pk.(*mldsa44.PublicKey), msg, ctx, sig)
}
func (compositeImpl44) publicKeyFromPrivate(sk interface{}) interface{} {
	return sk.(*mldsaSeedKey44).sk.Public().(*mldsa44.PublicKey)
}
func (compositeImpl44) publicKeyBytes(pk interface{}) []byte { return pk.(*mldsa44.PublicKey).Bytes() }
func (compositeImpl44) privateKeyBytes(sk interface{}) []byte {
	s := sk.(*mldsaSeedKey44).seed
	return s[:]
}
func (compositeImpl44) unmarshalPublicKey(data []byte) (interface{}, error) {
	var pk mldsa44.PublicKey
	if err := pk.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return &pk, nil
}
func (compositeImpl44) unmarshalPrivateKey(data []byte) (interface{}, error) {
	if len(data) != mldsa44.SeedSize {
		return nil, errors.New("x509: invalid ML-DSA-44 seed length")
	}
	var seed [mldsa44.SeedSize]byte
	copy(seed[:], data)
	_, expandedSK := mldsa44.NewKeyFromSeed(&seed)
	return &mldsaSeedKey44{seed: seed, sk: expandedSK}, nil
}
func (compositeImpl44) publicKeySize() int  { return mldsa44.PublicKeySize }
func (compositeImpl44) privateKeySize() int { return mldsa44.SeedSize }
func (compositeImpl44) signatureSize() int  { return mldsa44.SignatureSize }

// ── mldsa65 adapter ───────────────────────────────────────────────────────────

type compositeImpl65 struct{}

func (compositeImpl65) generateKey(rnd io.Reader) (interface{}, interface{}, error) {
	var seed [mldsa65.SeedSize]byte
	if _, err := io.ReadFull(rnd, seed[:]); err != nil {
		return nil, nil, err
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	return pk, &mldsaSeedKey65{seed: seed, sk: sk}, nil
}
func (compositeImpl65) signTo(sk interface{}, msg, ctx []byte, sig []byte) error {
	return mldsa65.SignTo(sk.(*mldsaSeedKey65).sk, msg, ctx, false, sig)
}
func (compositeImpl65) verify(pk interface{}, msg, ctx, sig []byte) bool {
	return mldsa65.Verify(pk.(*mldsa65.PublicKey), msg, ctx, sig)
}
func (compositeImpl65) publicKeyFromPrivate(sk interface{}) interface{} {
	return sk.(*mldsaSeedKey65).sk.Public().(*mldsa65.PublicKey)
}
func (compositeImpl65) publicKeyBytes(pk interface{}) []byte { return pk.(*mldsa65.PublicKey).Bytes() }
func (compositeImpl65) privateKeyBytes(sk interface{}) []byte {
	s := sk.(*mldsaSeedKey65).seed
	return s[:]
}
func (compositeImpl65) unmarshalPublicKey(data []byte) (interface{}, error) {
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return &pk, nil
}
func (compositeImpl65) unmarshalPrivateKey(data []byte) (interface{}, error) {
	if len(data) != mldsa65.SeedSize {
		return nil, errors.New("x509: invalid ML-DSA-65 seed length")
	}
	var seed [mldsa65.SeedSize]byte
	copy(seed[:], data)
	_, expandedSK := mldsa65.NewKeyFromSeed(&seed)
	return &mldsaSeedKey65{seed: seed, sk: expandedSK}, nil
}
func (compositeImpl65) publicKeySize() int  { return mldsa65.PublicKeySize }
func (compositeImpl65) privateKeySize() int { return mldsa65.SeedSize }
func (compositeImpl65) signatureSize() int  { return mldsa65.SignatureSize }

// ── mldsa87 adapter ───────────────────────────────────────────────────────────

type compositeImpl87 struct{}

func (compositeImpl87) generateKey(rnd io.Reader) (interface{}, interface{}, error) {
	var seed [mldsa87.SeedSize]byte
	if _, err := io.ReadFull(rnd, seed[:]); err != nil {
		return nil, nil, err
	}
	pk, sk := mldsa87.NewKeyFromSeed(&seed)
	return pk, &mldsaSeedKey87{seed: seed, sk: sk}, nil
}
func (compositeImpl87) signTo(sk interface{}, msg, ctx []byte, sig []byte) error {
	return mldsa87.SignTo(sk.(*mldsaSeedKey87).sk, msg, ctx, false, sig)
}
func (compositeImpl87) verify(pk interface{}, msg, ctx, sig []byte) bool {
	return mldsa87.Verify(pk.(*mldsa87.PublicKey), msg, ctx, sig)
}
func (compositeImpl87) publicKeyFromPrivate(sk interface{}) interface{} {
	return sk.(*mldsaSeedKey87).sk.Public().(*mldsa87.PublicKey)
}
func (compositeImpl87) publicKeyBytes(pk interface{}) []byte { return pk.(*mldsa87.PublicKey).Bytes() }
func (compositeImpl87) privateKeyBytes(sk interface{}) []byte {
	s := sk.(*mldsaSeedKey87).seed
	return s[:]
}
func (compositeImpl87) unmarshalPublicKey(data []byte) (interface{}, error) {
	var pk mldsa87.PublicKey
	if err := pk.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return &pk, nil
}
func (compositeImpl87) unmarshalPrivateKey(data []byte) (interface{}, error) {
	if len(data) != mldsa87.SeedSize {
		return nil, errors.New("x509: invalid ML-DSA-87 seed length")
	}
	var seed [mldsa87.SeedSize]byte
	copy(seed[:], data)
	_, expandedSK := mldsa87.NewKeyFromSeed(&seed)
	return &mldsaSeedKey87{seed: seed, sk: expandedSK}, nil
}
func (compositeImpl87) publicKeySize() int  { return mldsa87.PublicKeySize }
func (compositeImpl87) privateKeySize() int { return mldsa87.SeedSize }
func (compositeImpl87) signatureSize() int  { return mldsa87.SignatureSize }

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

	impl    mldsaImpl
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
		impl:    compositeImpl44{},
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
		impl:    compositeImpl44{},
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
		impl:    compositeImpl65{},
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
		impl:    compositeImpl65{},
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
		impl:    compositeImpl65{},
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
		impl:    compositeImpl65{},
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
		impl:    compositeImpl87{},
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
		impl:    compositeImpl87{},
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
	mldsaPK interface{}
	rsaPK   *rsa.PublicKey
	alg     *CompositeAlgorithm
}

// Algorithm returns the composite algorithm this key belongs to.
func (pk *CompositePublicKey) Algorithm() *CompositeAlgorithm { return pk.alg }

// CompositePrivateKey holds the ML-DSA and RSA private key components for a
// composite algorithm.
type CompositePrivateKey struct {
	mldsaSK interface{}
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
		mldsaPK: sk.alg.impl.publicKeyFromPrivate(sk.mldsaSK),
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
	mldsaPK, mldsaSK, err := a.impl.generateKey(rnd)
	if err != nil {
		return nil, nil, err
	}
	rsaSK, err := rsa.GenerateKey(rnd, a.rsaBits)
	if err != nil {
		return nil, nil, err
	}
	pk := &CompositePublicKey{mldsaPK: mldsaPK, rsaPK: &rsaSK.PublicKey, alg: a}
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

	mldsaSig := make([]byte, a.impl.signatureSize())
	if err := a.impl.signTo(sk.mldsaSK, mPrime, []byte(a.Label), mldsaSig); err != nil {
		return nil, err
	}

	digest := a.compositeHashMPrime(mPrime)
	var rsaSig []byte
	var err error
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
	mldsaSigSize := a.impl.signatureSize()
	if len(sig) <= mldsaSigSize {
		return false
	}
	mldsaSig := sig[:mldsaSigSize]
	rsaSig := sig[mldsaSigSize:]

	mPrime := a.compositeBuildMPrime(msg, ctx)
	if !a.impl.verify(pk.mldsaPK, mPrime, []byte(a.Label), mldsaSig) {
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
	mldsaBytes := a.impl.publicKeyBytes(pk.mldsaPK)
	rsaDER := MarshalPKCS1PublicKey(pk.rsaPK)
	return append(mldsaBytes, rsaDER...), nil
}

// parseCompositePublicKey deserializes a raw composite public key.
func (a *CompositeAlgorithm) parseCompositePublicKey(data []byte) (*CompositePublicKey, error) {
	mldsaSize := a.impl.publicKeySize()
	if len(data) <= mldsaSize {
		return nil, errors.New("x509: composite public key data too short")
	}
	mldsaPK, err := a.impl.unmarshalPublicKey(data[:mldsaSize])
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
	mldsaBytes := a.impl.privateKeyBytes(sk.mldsaSK)
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
	mldsaSize := a.impl.privateKeySize()
	if len(data) <= mldsaSize {
		return nil, errors.New("x509: composite private key data too short")
	}
	mldsaSK, err := a.impl.unmarshalPrivateKey(data[:mldsaSize])
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
