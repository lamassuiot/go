// Package x509 — composite key adapter interfaces and key types
//
// InnerPrivateKey / InnerPublicKey are implemented by algorithm-specific
// adapter structs (x509_composite_mldsa.go, x509_composite_rsa.go), each a
// struct of closures over the concrete key. CompositePrivateKey /
// CompositePublicKey never depend on a specific algorithm; they only drive
// the two inner keys they hold.

package x509

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"errors"
	"io"
)

// InnerPrivateKey is the adapter interface implemented by each concrete
// signature algorithm (ML-DSA, RSA, ...) embedded in a composite private key.
//
// GenerateKey and Unmarshall don't depend on the receiver's own key
// material, only on its configuration — they spawn a fresh sibling of the
// same kind. That's what lets CompositeAlgorithm hold a "prototype" with
// no real key material, used only to produce a real one on demand.
type InnerPrivateKey interface {
	GenerateKey(rnd io.Reader) (InnerPrivateKey, error)
	Unmarshall(data []byte) (InnerPrivateKey, error)
	Public() InnerPublicKey
	// Sign signs msg, which is already the composite message representative M'.
	Sign(rnd io.Reader, msg []byte) ([]byte, error)
	Bytes() []byte
	Size() int
}

// InnerPublicKey is the InnerPrivateKey counterpart for public keys.
type InnerPublicKey interface {
	Unmarshall(data []byte) (InnerPublicKey, error)
	// Verify reports whether sig is a valid signature over msg, which is
	// already the composite message representative M'.
	Verify(msg, sig []byte) bool
	Bytes() []byte
	Size() int
	SignatureSize() int
}

// CompositePrivateKey holds the two inner private keys (one post-quantum,
// one traditional) making up a composite key pair.
type CompositePrivateKey struct {
	innerSk1 InnerPrivateKey
	innerSk2 InnerPrivateKey
	oid      asn1.ObjectIdentifier // identifies the algorithm; resolved via Algorithm()
}

// Algorithm returns the composite algorithm this key belongs to.
func (sk *CompositePrivateKey) Algorithm() *CompositeAlgorithm {
	return compositeAlgorithmByOID(sk.oid)
}

// generateKey generates a fresh CompositePrivateKey of the same kind as
// the receiver (typically CompositeAlgorithm's prototype).
func (sk *CompositePrivateKey) generateKey(rnd io.Reader) (*CompositePrivateKey, error) {
	innerSk1, err := sk.innerSk1.GenerateKey(rnd)
	if err != nil {
		return nil, err
	}
	innerSk2, err := sk.innerSk2.GenerateKey(rnd)
	if err != nil {
		return nil, err
	}
	return &CompositePrivateKey{innerSk1: innerSk1, innerSk2: innerSk2, oid: sk.oid}, nil
}

// unmarshall parses data into a fresh CompositePrivateKey: the first
// innerSk1.Size() bytes decode innerSk1, the remainder decodes innerSk2.
func (sk *CompositePrivateKey) unmarshall(data []byte) (*CompositePrivateKey, error) {
	size := sk.innerSk1.Size()
	if len(data) <= size {
		return nil, errors.New("x509: composite private key data too short")
	}
	innerSk1, err := sk.innerSk1.Unmarshall(data[:size])
	if err != nil {
		return nil, err
	}
	innerSk2, err := sk.innerSk2.Unmarshall(data[size:])
	if err != nil {
		return nil, err
	}
	return &CompositePrivateKey{innerSk1: innerSk1, innerSk2: innerSk2, oid: sk.oid}, nil
}

// marshall serializes sk: innerSk1.Bytes() || innerSk2.Bytes().
func (sk *CompositePrivateKey) marshall() []byte {
	return append(sk.innerSk1.Bytes(), sk.innerSk2.Bytes()...)
}

// sign signs mPrime with both inner keys and concatenates the results.
func (sk *CompositePrivateKey) sign(rnd io.Reader, mPrime []byte) ([]byte, error) {
	sig1, err := sk.innerSk1.Sign(rnd, mPrime)
	if err != nil {
		return nil, err
	}
	sig2, err := sk.innerSk2.Sign(rnd, mPrime)
	if err != nil {
		return nil, err
	}
	return append(sig1, sig2...), nil
}

// Public implements [crypto.Signer]. It returns the corresponding
// [*CompositePublicKey] as a [crypto.PublicKey]; use a type assertion to
// recover the concrete type.
func (sk *CompositePrivateKey) Public() crypto.PublicKey {
	return &CompositePublicKey{
		innerPk1: sk.innerSk1.Public(),
		innerPk2: sk.innerSk2.Public(),
		oid:      sk.oid,
	}
}

// CompositeSignerOpts implements [crypto.SignerOpts] for composite algorithms.
//
// HashFunc returns [crypto.Hash](0): no external pre-hashing is performed,
// so callers MUST pass the raw, un-hashed message to [CompositePrivateKey.Sign].
// Use CompositeSignerOpts{Context: ctx} to attach a context string (max 255
// bytes); any other SignerOpts value (e.g. from [CreateCertificate]) is
// treated as an empty context.
type CompositeSignerOpts struct {
	Context []byte
}

func (CompositeSignerOpts) HashFunc() crypto.Hash { return 0 }

// Sign implements [crypto.Signer]. msg must be the full, un-hashed message.
func (sk *CompositePrivateKey) Sign(rnd io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	var ctx []byte
	if so, ok := opts.(CompositeSignerOpts); ok {
		ctx = so.Context
	}
	return sk.Algorithm().CompositeSign(rnd, sk, msg, ctx)
}

// CompositePublicKey holds the two inner public keys (one post-quantum,
// one traditional) making up a composite public key.
type CompositePublicKey struct {
	innerPk1 InnerPublicKey
	innerPk2 InnerPublicKey
	oid      asn1.ObjectIdentifier
}

// Algorithm returns the composite algorithm this key belongs to.
func (pk *CompositePublicKey) Algorithm() *CompositeAlgorithm {
	return compositeAlgorithmByOID(pk.oid)
}

// Equal reports whether pk and x have the same algorithm and key material.
func (pk *CompositePublicKey) Equal(x crypto.PublicKey) bool {
	other, ok := x.(*CompositePublicKey)
	if !ok || !pk.oid.Equal(other.oid) {
		return false
	}
	return bytes.Equal(pk.innerPk1.Bytes(), other.innerPk1.Bytes()) &&
		bytes.Equal(pk.innerPk2.Bytes(), other.innerPk2.Bytes())
}

// unmarshall parses data into a fresh CompositePublicKey: the first
// innerPk1.Size() bytes decode innerPk1, the remainder decodes innerPk2.
func (pk *CompositePublicKey) unmarshall(data []byte) (*CompositePublicKey, error) {
	size := pk.innerPk1.Size()
	if len(data) <= size {
		return nil, errors.New("x509: composite public key data too short")
	}
	innerPk1, err := pk.innerPk1.Unmarshall(data[:size])
	if err != nil {
		return nil, err
	}
	innerPk2, err := pk.innerPk2.Unmarshall(data[size:])
	if err != nil {
		return nil, err
	}
	return &CompositePublicKey{innerPk1: innerPk1, innerPk2: innerPk2, oid: pk.oid}, nil
}

// marshall serializes pk: innerPk1.Bytes() || innerPk2.Bytes().
func (pk *CompositePublicKey) marshall() []byte {
	return append(pk.innerPk1.Bytes(), pk.innerPk2.Bytes()...)
}

// verify checks that sig is a valid composite signature over mPrime.
func (pk *CompositePublicKey) verify(mPrime, sig []byte) bool {
	s1Size := pk.innerPk1.SignatureSize()
	if len(sig) <= s1Size {
		return false
	}
	return pk.innerPk1.Verify(mPrime, sig[:s1Size]) && pk.innerPk2.Verify(mPrime, sig[s1Size:])
}
