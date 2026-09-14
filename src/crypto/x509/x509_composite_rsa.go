// Package x509 — RSA adapter for the composite key types
//
// Mirrors x509_composite_mldsa.go, marshalling via the existing PKCS #1
// helpers. RSA is always the second (traditional, self-delimiting) slot
// of a composite key, so unlike ML-DSA's Size(), the value Size() returns
// here is never relied on to locate a component boundary — only
// informational, which is why the prototype (no real key) can return an
// estimate instead of an exact value.

package x509

import (
	"crypto"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"io"
)

// rsaInnerPrivateKey is the InnerPrivateKey adapter for RSA.
type rsaInnerPrivateKey struct {
	generateFn  func(io.Reader) (InnerPrivateKey, error)
	unmarshalFn func([]byte) (InnerPrivateKey, error)
	signFn      func(io.Reader, []byte) ([]byte, error)
	bytesFn     func() []byte
	publicFn    func() InnerPublicKey
	size        int
}

func (k *rsaInnerPrivateKey) GenerateKey(rnd io.Reader) (InnerPrivateKey, error) {
	return k.generateFn(rnd)
}
func (k *rsaInnerPrivateKey) Unmarshall(data []byte) (InnerPrivateKey, error) {
	return k.unmarshalFn(data)
}
func (k *rsaInnerPrivateKey) Sign(rnd io.Reader, msg []byte) ([]byte, error) {
	return k.signFn(rnd, msg)
}
func (k *rsaInnerPrivateKey) Bytes() []byte          { return k.bytesFn() }
func (k *rsaInnerPrivateKey) Public() InnerPublicKey { return k.publicFn() }
func (k *rsaInnerPrivateKey) Size() int              { return k.size }

// rsaHashMPrime hashes mPrime with hash, as required before RSA
// PSS/PKCS #1 v1.5 signing or verification.
func rsaHashMPrime(hash crypto.Hash, mPrime []byte) []byte {
	h := hash.New()
	h.Write(mPrime)
	return h.Sum(nil)
}

// newRSAInnerPrivateKey builds the adapter around sk. sk may be nil
// (prototype use); signFn/bytesFn/publicFn close over it lazily and are
// only evaluated when called, which never happens for a prototype. size
// can't be deferred the same way, so it falls back to an estimate when
// there's no real key to measure.
func newRSAInnerPrivateKey(bits int, hash crypto.Hash, pss bool, sk *rsa.PrivateKey) InnerPrivateKey {
	size := estimateRSAPrivateKeyDERSize(bits)
	if sk != nil {
		size = len(MarshalPKCS1PrivateKey(sk))
	}
	return &rsaInnerPrivateKey{
		generateFn: func(rnd io.Reader) (InnerPrivateKey, error) {
			return NewRSAPrivateKey(rnd, bits, hash, pss)
		},
		unmarshalFn: func(data []byte) (InnerPrivateKey, error) {
			return NewRSAPrivateKeyFromBytes(bits, hash, pss, data)
		},
		signFn: func(rnd io.Reader, mPrime []byte) ([]byte, error) {
			if rnd == nil {
				rnd = cryptorand.Reader
			}
			digest := rsaHashMPrime(hash, mPrime)
			if pss {
				opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
				return rsa.SignPSS(rnd, sk, hash, digest, opts)
			}
			return rsa.SignPKCS1v15(rnd, sk, hash, digest)
		},
		bytesFn:  func() []byte { return MarshalPKCS1PrivateKey(sk) },
		publicFn: func() InnerPublicKey { return newRSAInnerPublicKey(bits, hash, pss, &sk.PublicKey) },
		size:     size,
	}
}

// NewRSAPrivateKey generates a fresh RSA inner private key with the
// given modulus size, RSA signing hash and padding mode (PSS if pss,
// PKCS #1 v1.5 otherwise). rnd is typically [crypto/rand.Reader].
func NewRSAPrivateKey(rnd io.Reader, bits int, hash crypto.Hash, pss bool) (InnerPrivateKey, error) {
	if rnd == nil {
		rnd = cryptorand.Reader
	}
	sk, err := rsa.GenerateKey(rnd, bits)
	if err != nil {
		return nil, err
	}
	return newRSAInnerPrivateKey(bits, hash, pss, sk), nil
}

// NewRSAPrivateKeyFromBytes parses a raw (PKCS #1 DER) RSA private key.
func NewRSAPrivateKeyFromBytes(bits int, hash crypto.Hash, pss bool, data []byte) (InnerPrivateKey, error) {
	sk, err := ParsePKCS1PrivateKey(data)
	if err != nil {
		return nil, err
	}
	return newRSAInnerPrivateKey(bits, hash, pss, sk), nil
}

// rsaInnerPublicKey is the InnerPublicKey adapter for RSA.
type rsaInnerPublicKey struct {
	unmarshalFn   func([]byte) (InnerPublicKey, error)
	verifyFn      func(msg, sig []byte) bool
	bytesFn       func() []byte
	size          int
	signatureSize int
}

func (k *rsaInnerPublicKey) Unmarshall(data []byte) (InnerPublicKey, error) {
	return k.unmarshalFn(data)
}
func (k *rsaInnerPublicKey) Verify(msg, sig []byte) bool { return k.verifyFn(msg, sig) }
func (k *rsaInnerPublicKey) Bytes() []byte               { return k.bytesFn() }
func (k *rsaInnerPublicKey) Size() int                   { return k.size }
func (k *rsaInnerPublicKey) SignatureSize() int          { return k.signatureSize }

// newRSAInnerPublicKey builds the adapter around pk. pk may be nil
// (prototype use); see newRSAInnerPrivateKey.
func newRSAInnerPublicKey(bits int, hash crypto.Hash, pss bool, pk *rsa.PublicKey) InnerPublicKey {
	size := estimateRSAPublicKeyDERSize(bits)
	signatureSize := bits / 8
	if pk != nil {
		size = len(MarshalPKCS1PublicKey(pk))
		signatureSize = pk.Size()
	}
	return &rsaInnerPublicKey{
		unmarshalFn: func(data []byte) (InnerPublicKey, error) {
			return NewRSAPublicKeyFromBytes(bits, hash, pss, data)
		},
		verifyFn: func(msg, sig []byte) bool {
			digest := rsaHashMPrime(hash, msg)
			if pss {
				opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
				return rsa.VerifyPSS(pk, hash, digest, sig, opts) == nil
			}
			return rsa.VerifyPKCS1v15(pk, hash, digest, sig) == nil
		},
		bytesFn:       func() []byte { return MarshalPKCS1PublicKey(pk) },
		size:          size,
		signatureSize: signatureSize,
	}
}

// NewRSAPublicKeyFromBytes parses a raw (PKCS #1 DER) RSA public key.
func NewRSAPublicKeyFromBytes(bits int, hash crypto.Hash, pss bool, data []byte) (InnerPublicKey, error) {
	pk, err := ParsePKCS1PublicKey(data)
	if err != nil {
		return nil, err
	}
	return newRSAInnerPublicKey(bits, hash, pss, pk), nil
}

// estimateRSAPrivateKeyDERSize approximates the PKCS #1 RSAPrivateKey DER
// size for a modulus of the given bit size; never relied on for correctness.
func estimateRSAPrivateKeyDERSize(bits int) int {
	n := bits / 8
	return n*4 + n/2 + 64
}

// estimateRSAPublicKeyDERSize approximates the PKCS #1 RSAPublicKey DER
// size for a modulus of the given bit size; never relied on for correctness.
func estimateRSAPublicKeyDERSize(bits int) int {
	return bits/8 + 32
}
