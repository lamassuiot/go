// Package x509 — Ed25519 adapter for the composite key types
//
// Mirrors x509_composite_ecdsa.go. Ed25519's raw private key (a 32-byte
// seed), public key (32 bytes) and signature (64 bytes) are all fixed size
// regardless of key material, so every Size()/SignatureSize() here is exact
// even for a prototype with no real key. Ed25519 is always the second
// (traditional, self-delimiting) slot of a composite key. Unlike RSA/ECDSA,
// Ed25519 signs the message representative M' directly (PureEdDSA already
// hashes internally), so there's no separate pre-hash step here.

package x509

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"errors"
	"io"
)

// ed25519InnerPrivateKey is the InnerPrivateKey adapter for Ed25519.
type ed25519InnerPrivateKey struct {
	generateFn  func(io.Reader) (InnerPrivateKey, error)
	unmarshalFn func([]byte) (InnerPrivateKey, error)
	signFn      func(io.Reader, []byte) ([]byte, error)
	bytesFn     func() []byte
	publicFn    func() InnerPublicKey
}

func (k *ed25519InnerPrivateKey) GenerateKey(rnd io.Reader) (InnerPrivateKey, error) {
	return k.generateFn(rnd)
}
func (k *ed25519InnerPrivateKey) Unmarshall(data []byte) (InnerPrivateKey, error) {
	return k.unmarshalFn(data)
}
func (k *ed25519InnerPrivateKey) Sign(rnd io.Reader, msg []byte) ([]byte, error) {
	return k.signFn(rnd, msg)
}
func (k *ed25519InnerPrivateKey) Bytes() []byte          { return k.bytesFn() }
func (k *ed25519InnerPrivateKey) Public() InnerPublicKey { return k.publicFn() }
func (k *ed25519InnerPrivateKey) Size() int              { return ed25519.SeedSize }

// newEd25519InnerPrivateKey builds the adapter around sk. sk may be nil
// (prototype use); signFn/bytesFn/publicFn close over it lazily and are
// only evaluated when called, which never happens for a prototype.
func newEd25519InnerPrivateKey(sk ed25519.PrivateKey) InnerPrivateKey {
	return &ed25519InnerPrivateKey{
		generateFn: func(rnd io.Reader) (InnerPrivateKey, error) {
			return NewEd25519PrivateKey(rnd)
		},
		unmarshalFn: func(data []byte) (InnerPrivateKey, error) {
			return NewEd25519PrivateKeyFromBytes(data)
		},
		signFn: func(_ io.Reader, mPrime []byte) ([]byte, error) {
			return ed25519.Sign(sk, mPrime), nil
		},
		bytesFn:  func() []byte { return sk.Seed() },
		publicFn: func() InnerPublicKey { return newEd25519InnerPublicKey(sk.Public().(ed25519.PublicKey)) },
	}
}

// NewEd25519PrivateKey generates a fresh Ed25519 inner private key.
// rnd is typically [crypto/rand.Reader].
func NewEd25519PrivateKey(rnd io.Reader) (InnerPrivateKey, error) {
	if rnd == nil {
		rnd = cryptorand.Reader
	}
	_, sk, err := ed25519.GenerateKey(rnd)
	if err != nil {
		return nil, err
	}
	return newEd25519InnerPrivateKey(sk), nil
}

// NewEd25519PrivateKeyFromBytes parses a raw (32-byte seed) Ed25519 private key.
func NewEd25519PrivateKeyFromBytes(data []byte) (InnerPrivateKey, error) {
	if len(data) != ed25519.SeedSize {
		return nil, errors.New("x509: invalid composite Ed25519 private key seed length")
	}
	return newEd25519InnerPrivateKey(ed25519.NewKeyFromSeed(data)), nil
}

// ed25519InnerPublicKey is the InnerPublicKey adapter for Ed25519.
type ed25519InnerPublicKey struct {
	unmarshalFn func([]byte) (InnerPublicKey, error)
	verifyFn    func(msg, sig []byte) bool
	bytesFn     func() []byte
}

func (k *ed25519InnerPublicKey) Unmarshall(data []byte) (InnerPublicKey, error) {
	return k.unmarshalFn(data)
}
func (k *ed25519InnerPublicKey) Verify(msg, sig []byte) bool { return k.verifyFn(msg, sig) }
func (k *ed25519InnerPublicKey) Bytes() []byte               { return k.bytesFn() }
func (k *ed25519InnerPublicKey) Size() int                   { return ed25519.PublicKeySize }
func (k *ed25519InnerPublicKey) SignatureSize() int          { return ed25519.SignatureSize }

// newEd25519InnerPublicKey builds the adapter around pk. pk may be nil
// (prototype use); see newEd25519InnerPrivateKey.
func newEd25519InnerPublicKey(pk ed25519.PublicKey) InnerPublicKey {
	return &ed25519InnerPublicKey{
		unmarshalFn: func(data []byte) (InnerPublicKey, error) {
			return NewEd25519PublicKeyFromBytes(data)
		},
		verifyFn: func(msg, sig []byte) bool {
			return ed25519.Verify(pk, msg, sig)
		},
		bytesFn: func() []byte { return []byte(pk) },
	}
}

// NewEd25519PublicKeyFromBytes parses a raw (32-byte) Ed25519 public key.
func NewEd25519PublicKeyFromBytes(data []byte) (InnerPublicKey, error) {
	if len(data) != ed25519.PublicKeySize {
		return nil, errors.New("x509: invalid composite Ed25519 public key length")
	}
	return newEd25519InnerPublicKey(ed25519.PublicKey(data)), nil
}
