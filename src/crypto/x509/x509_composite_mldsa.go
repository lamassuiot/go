// Package x509 — ML-DSA adapter for the composite key types
//
// newMLDSAInnerPrivateKey/newMLDSAInnerPublicKey also serve as
// CompositeAlgorithm's prototype builders when called with a nil key:
// GenerateKey/Unmarshall/Size don't depend on real key material, and
// Sign/Bytes/Public/Verify — which do — are never called on a prototype.

package x509

import (
	"crypto/mldsa"
	"io"
)

// mldsaInnerPrivateKey is the InnerPrivateKey adapter for ML-DSA.
type mldsaInnerPrivateKey struct {
	generateFn  func(io.Reader) (InnerPrivateKey, error)
	unmarshalFn func([]byte) (InnerPrivateKey, error)
	signFn      func(io.Reader, []byte) ([]byte, error)
	bytesFn     func() []byte
	publicFn    func() InnerPublicKey
	size        int
}

func (k *mldsaInnerPrivateKey) GenerateKey(rnd io.Reader) (InnerPrivateKey, error) {
	return k.generateFn(rnd)
}
func (k *mldsaInnerPrivateKey) Unmarshall(data []byte) (InnerPrivateKey, error) {
	return k.unmarshalFn(data)
}
func (k *mldsaInnerPrivateKey) Sign(rnd io.Reader, msg []byte) ([]byte, error) {
	return k.signFn(rnd, msg)
}
func (k *mldsaInnerPrivateKey) Bytes() []byte          { return k.bytesFn() }
func (k *mldsaInnerPrivateKey) Public() InnerPublicKey { return k.publicFn() }
func (k *mldsaInnerPrivateKey) Size() int              { return k.size }

// newMLDSAInnerPrivateKey builds the adapter around sk. sk may be nil
// (prototype use); signFn/bytesFn/publicFn close over it lazily, so
// they're only ever evaluated when actually called, which never happens
// for a prototype.
func newMLDSAInnerPrivateKey(params mldsa.Parameters, label string, sk *mldsa.PrivateKey) InnerPrivateKey {
	return &mldsaInnerPrivateKey{
		generateFn: func(rnd io.Reader) (InnerPrivateKey, error) {
			return NewMLDSAPrivateKey(rnd, params, label)
		},
		unmarshalFn: func(data []byte) (InnerPrivateKey, error) {
			return NewMLDSAPrivateKeyFromBytes(params, label, data)
		},
		signFn: func(_ io.Reader, msg []byte) ([]byte, error) {
			return sk.Sign(nil, msg, &mldsa.Options{Context: label})
		},
		bytesFn:  func() []byte { return sk.Bytes() },
		publicFn: func() InnerPublicKey { return newMLDSAInnerPublicKey(params, label, sk.PublicKey()) },
		size:     mldsa.PrivateKeySize,
	}
}

// NewMLDSAPrivateKey generates a fresh ML-DSA inner private key for the
// given parameter set and context label. rnd is typically
// [crypto/rand.Reader].
func NewMLDSAPrivateKey(rnd io.Reader, params mldsa.Parameters, label string) (InnerPrivateKey, error) {
	var seed [mldsa.PrivateKeySize]byte
	if _, err := io.ReadFull(rnd, seed[:]); err != nil {
		return nil, err
	}
	sk, err := mldsa.NewPrivateKey(params, seed[:])
	if err != nil {
		return nil, err
	}
	return newMLDSAInnerPrivateKey(params, label, sk), nil
}

// NewMLDSAPrivateKeyFromBytes parses a raw ML-DSA seed into an inner private key.
func NewMLDSAPrivateKeyFromBytes(params mldsa.Parameters, label string, data []byte) (InnerPrivateKey, error) {
	sk, err := mldsa.NewPrivateKey(params, data)
	if err != nil {
		return nil, err
	}
	return newMLDSAInnerPrivateKey(params, label, sk), nil
}

// mldsaInnerPublicKey is the InnerPublicKey adapter for ML-DSA.
type mldsaInnerPublicKey struct {
	unmarshalFn   func([]byte) (InnerPublicKey, error)
	verifyFn      func(msg, sig []byte) bool
	bytesFn       func() []byte
	size          int
	signatureSize int
}

func (k *mldsaInnerPublicKey) Unmarshall(data []byte) (InnerPublicKey, error) {
	return k.unmarshalFn(data)
}
func (k *mldsaInnerPublicKey) Verify(msg, sig []byte) bool { return k.verifyFn(msg, sig) }
func (k *mldsaInnerPublicKey) Bytes() []byte               { return k.bytesFn() }
func (k *mldsaInnerPublicKey) Size() int                   { return k.size }
func (k *mldsaInnerPublicKey) SignatureSize() int          { return k.signatureSize }

// newMLDSAInnerPublicKey builds the adapter around pk. pk may be nil
// (prototype use); see newMLDSAInnerPrivateKey.
func newMLDSAInnerPublicKey(params mldsa.Parameters, label string, pk *mldsa.PublicKey) InnerPublicKey {
	return &mldsaInnerPublicKey{
		unmarshalFn: func(data []byte) (InnerPublicKey, error) {
			return NewMLDSAPublicKeyFromBytes(params, label, data)
		},
		verifyFn: func(msg, sig []byte) bool {
			return mldsa.Verify(pk, msg, sig, &mldsa.Options{Context: label}) == nil
		},
		bytesFn:       func() []byte { return pk.Bytes() },
		size:          params.PublicKeySize(),
		signatureSize: params.SignatureSize(),
	}
}

// NewMLDSAPublicKeyFromBytes parses a raw ML-DSA public key.
func NewMLDSAPublicKeyFromBytes(params mldsa.Parameters, label string, data []byte) (InnerPublicKey, error) {
	pk, err := mldsa.NewPublicKey(params, data)
	if err != nil {
		return nil, err
	}
	return newMLDSAInnerPublicKey(params, label, pk), nil
}
