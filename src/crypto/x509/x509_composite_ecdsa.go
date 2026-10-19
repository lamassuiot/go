// Package x509 — ECDSA adapter for the composite key types
//
// Mirrors x509_composite_rsa.go. Unlike RSA, both the raw private key (a
// fixed-length big-endian scalar) and the raw public key (an uncompressed
// SEC 1 point) have a size that depends only on the curve, so Size() is
// exact even for a prototype with no real key. ECDSA is always the second
// (traditional, self-delimiting) slot of a composite key, so — as with
// RSA's Size() — none of this is ever relied on to locate a component
// boundary; ECDSA's ASN.1 (r, s) signature is variable length, which is
// fine because the traditional component always consumes whatever bytes
// remain after ML-DSA's fixed-size signature.

package x509

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"io"
)

// ecdsaInnerPrivateKey is the innerPrivateKey adapter for ECDSA.
type ecdsaInnerPrivateKey struct {
	generateFn  func(io.Reader) (innerPrivateKey, error)
	unmarshalFn func([]byte) (innerPrivateKey, error)
	signFn      func(io.Reader, []byte) ([]byte, error)
	bytesFn     func() []byte
	publicFn    func() innerPublicKey
	size        int
}

func (k *ecdsaInnerPrivateKey) GenerateKey(rnd io.Reader) (innerPrivateKey, error) {
	return k.generateFn(rnd)
}
func (k *ecdsaInnerPrivateKey) unmarshal(data []byte) (innerPrivateKey, error) {
	return k.unmarshalFn(data)
}
func (k *ecdsaInnerPrivateKey) Sign(rnd io.Reader, msg []byte) ([]byte, error) {
	return k.signFn(rnd, msg)
}
func (k *ecdsaInnerPrivateKey) Bytes() []byte          { return k.bytesFn() }
func (k *ecdsaInnerPrivateKey) Public() innerPublicKey { return k.publicFn() }
func (k *ecdsaInnerPrivateKey) Size() int              { return k.size }

// ecdsaHashMPrime hashes mPrime with hash, as required before ECDSA
// signing or verification.
func ecdsaHashMPrime(hash crypto.Hash, mPrime []byte) []byte {
	h := hash.New()
	h.Write(mPrime)
	return h.Sum(nil)
}

// ecPointSize returns the exact size of curve's uncompressed SEC 1 point
// encoding (as produced by (*ecdsa.PublicKey).Bytes()).
func ecPointSize(curve elliptic.Curve) int {
	return 1 + 2*((curve.Params().BitSize+7)/8)
}

// ecScalarSize returns the exact size of curve's raw private key encoding
// (as produced by (*ecdsa.PrivateKey).Bytes()).
func ecScalarSize(curve elliptic.Curve) int {
	return (curve.Params().BitSize + 7) / 8
}

// newECDSAInnerPrivateKey builds the adapter around sk. sk may be nil
// (prototype use); signFn/bytesFn/publicFn close over it lazily and are
// only evaluated when called, which never happens for a prototype.
func newECDSAInnerPrivateKey(curve elliptic.Curve, hash crypto.Hash, sk *ecdsa.PrivateKey) innerPrivateKey {
	return &ecdsaInnerPrivateKey{
		generateFn: func(rnd io.Reader) (innerPrivateKey, error) {
			return newECDSAPrivateKey(rnd, curve, hash)
		},
		unmarshalFn: func(data []byte) (innerPrivateKey, error) {
			return newECDSAPrivateKeyFromBytes(curve, hash, data)
		},
		signFn: func(rnd io.Reader, mPrime []byte) ([]byte, error) {
			if rnd == nil {
				rnd = cryptorand.Reader
			}
			digest := ecdsaHashMPrime(hash, mPrime)
			return ecdsa.SignASN1(rnd, sk, digest)
		},
		bytesFn: func() []byte {
			b, _ := sk.Bytes() // curve is always one we registered; never errors
			return b
		},
		publicFn: func() innerPublicKey { return newECDSAInnerPublicKey(curve, hash, &sk.PublicKey) },
		size:     ecScalarSize(curve),
	}
}

// newECDSAPrivateKey generates a fresh ECDSA inner private key on curve.
// rnd is typically [crypto/rand.Reader].
func newECDSAPrivateKey(rnd io.Reader, curve elliptic.Curve, hash crypto.Hash) (innerPrivateKey, error) {
	if rnd == nil {
		rnd = cryptorand.Reader
	}
	sk, err := ecdsa.GenerateKey(curve, rnd)
	if err != nil {
		return nil, err
	}
	return newECDSAInnerPrivateKey(curve, hash, sk), nil
}

// newECDSAPrivateKeyFromBytes parses a raw (fixed-length big-endian scalar)
// ECDSA private key.
func newECDSAPrivateKeyFromBytes(curve elliptic.Curve, hash crypto.Hash, data []byte) (innerPrivateKey, error) {
	sk, err := ecdsa.ParseRawPrivateKey(curve, data)
	if err != nil {
		return nil, err
	}
	return newECDSAInnerPrivateKey(curve, hash, sk), nil
}

// ecdsaInnerPublicKey is the innerPublicKey adapter for ECDSA.
type ecdsaInnerPublicKey struct {
	unmarshalFn   func([]byte) (innerPublicKey, error)
	verifyFn      func(msg, sig []byte) bool
	bytesFn       func() []byte
	size          int
	signatureSize int
}

func (k *ecdsaInnerPublicKey) unmarshal(data []byte) (innerPublicKey, error) {
	return k.unmarshalFn(data)
}
func (k *ecdsaInnerPublicKey) Verify(msg, sig []byte) bool { return k.verifyFn(msg, sig) }
func (k *ecdsaInnerPublicKey) Bytes() []byte               { return k.bytesFn() }
func (k *ecdsaInnerPublicKey) Size() int                   { return k.size }
func (k *ecdsaInnerPublicKey) SignatureSize() int          { return k.signatureSize }

// newECDSAInnerPublicKey builds the adapter around pk. pk may be nil
// (prototype use); see newECDSAInnerPrivateKey.
func newECDSAInnerPublicKey(curve elliptic.Curve, hash crypto.Hash, pk *ecdsa.PublicKey) innerPublicKey {
	return &ecdsaInnerPublicKey{
		unmarshalFn: func(data []byte) (innerPublicKey, error) {
			return newECDSAPublicKeyFromBytes(curve, hash, data)
		},
		verifyFn: func(msg, sig []byte) bool {
			digest := ecdsaHashMPrime(hash, msg)
			return ecdsa.VerifyASN1(pk, digest, sig)
		},
		bytesFn: func() []byte {
			b, _ := pk.Bytes() // curve is always one we registered; never errors
			return b
		},
		size: ecPointSize(curve),
		// ECDSA's ASN.1 (r, s) signature is variable length; this is an
		// upper bound, advisory only (see package comment).
		signatureSize: 8 + 2*(ecScalarSize(curve)+3),
	}
}

// newECDSAPublicKeyFromBytes parses a raw (uncompressed SEC 1 point) ECDSA
// public key.
func newECDSAPublicKeyFromBytes(curve elliptic.Curve, hash crypto.Hash, data []byte) (innerPublicKey, error) {
	pk, err := ecdsa.ParseUncompressedPublicKey(curve, data)
	if err != nil {
		return nil, err
	}
	return newECDSAInnerPublicKey(curve, hash, pk), nil
}
