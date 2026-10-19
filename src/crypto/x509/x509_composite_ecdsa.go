// Package x509 — ECDSA adapter for the composite key types
//
// Mirrors x509_composite_rsa.go. The private key is encoded as an RFC 5915
// ECPrivateKey carrying the curve OID and no publicKey field, and the public
// key as an uncompressed SEC 1 point, as required by
// draft-ietf-lamps-pq-composite-sigs-19, Section 4. Unlike RSA, both have a
// size that depends only on the curve, so Size() is exact even for a
// prototype with no real key. ECDSA is always the second
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
	"encoding/asn1"
	"errors"
	"fmt"
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

// ecPrivateKeySize returns the exact size of curve's private key encoding
// (as produced by marshalCompositeECPrivateKey).
func ecPrivateKeySize(curve elliptic.Curve) int {
	oid, _ := oidFromNamedCurve(curve) // curve is always one we registered
	b, _ := asn1.Marshal(ecPrivateKey{
		Version:       ecPrivKeyVersion,
		PrivateKey:    make([]byte, ecScalarSize(curve)),
		NamedCurveOID: oid,
	})
	return len(b)
}

// marshalCompositeECPrivateKey encodes sk as an RFC 5915 ECPrivateKey with
// the curve OID and without the publicKey field.
func marshalCompositeECPrivateKey(sk *ecdsa.PrivateKey) ([]byte, error) {
	oid, ok := oidFromNamedCurve(sk.Curve)
	if !ok {
		return nil, errors.New("x509: unknown elliptic curve")
	}
	priv, err := sk.Bytes()
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(ecPrivateKey{
		Version:       ecPrivKeyVersion,
		PrivateKey:    priv,
		NamedCurveOID: oid,
	})
}

// parseCompositeECPrivateKey parses an RFC 5915 ECPrivateKey for curve. The
// curve OID may be omitted, but if present it must match curve. Unlike
// [ParseECPrivateKey], the private key must be exactly as long as the curve
// order, as RFC 5915 requires, without missing or extra leading zeros.
func parseCompositeECPrivateKey(curve elliptic.Curve, der []byte) (*ecdsa.PrivateKey, error) {
	oid, ok := oidFromNamedCurve(curve)
	if !ok {
		return nil, errors.New("x509: unknown elliptic curve")
	}
	var priv ecPrivateKey
	rest, err := asn1.Unmarshal(der, &priv)
	if err != nil {
		return nil, errors.New("x509: failed to parse composite ECDSA private key: " + err.Error())
	}
	if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after composite ECDSA private key")
	}
	if priv.Version != ecPrivKeyVersion {
		return nil, fmt.Errorf("x509: unknown composite ECDSA private key version %d", priv.Version)
	}
	if len(priv.NamedCurveOID) != 0 && !priv.NamedCurveOID.Equal(oid) {
		return nil, errors.New("x509: composite ECDSA private key curve does not match algorithm")
	}
	if len(priv.PrivateKey) != ecScalarSize(curve) {
		return nil, fmt.Errorf("x509: invalid composite ECDSA private key length: %d", len(priv.PrivateKey))
	}
	return ecdsa.ParseRawPrivateKey(curve, priv.PrivateKey)
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
			b, _ := marshalCompositeECPrivateKey(sk) // curve is always one we registered; never errors
			return b
		},
		publicFn: func() innerPublicKey { return newECDSAInnerPublicKey(curve, hash, &sk.PublicKey) },
		size:     ecPrivateKeySize(curve),
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

// newECDSAPrivateKeyFromBytes parses an ECDSA private key encoded as an
// RFC 5915 ECPrivateKey.
//
// For compatibility with keys written by earlier versions of this package,
// a raw fixed-length big-endian scalar is accepted too. It can't be mistaken
// for an ECPrivateKey: parseCompositeECPrivateKey only accepts one whose
// private key is a full-length scalar, which makes it longer than a raw one.
func newECDSAPrivateKeyFromBytes(curve elliptic.Curve, hash crypto.Hash, data []byte) (innerPrivateKey, error) {
	var sk *ecdsa.PrivateKey
	var err error
	if len(data) == ecScalarSize(curve) {
		sk, err = ecdsa.ParseRawPrivateKey(curve, data)
	} else {
		sk, err = parseCompositeECPrivateKey(curve, data)
	}
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
