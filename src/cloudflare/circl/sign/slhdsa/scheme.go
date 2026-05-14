package slhdsa

import (
	"crypto/rand"
	"encoding/asn1"

	"cloudflare/circl/internal/sha3"
	"cloudflare/circl/sign"
)

func (id ID) Scheme() sign.Scheme { return scheme{id.params()} }

type scheme struct{ *params }

func (s scheme) Name() string          { return s.name }
func (s scheme) SeedSize() int         { return s.PrivateKeySize() }
func (s scheme) SupportsContext() bool { return true }

// sigAlgs is the NIST sigAlgs OID arc: { 2 16 840 1 101 3 4 3 }.
var sigAlgsArc = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3}

// Oid returns the OID for this SLH-DSA parameter set per RFC 9909 §3.
// This satisfies the circlPki.CertificateScheme interface.
func (s scheme) Oid() asn1.ObjectIdentifier {
	// RFC 9909 §3 assigns sigAlgs arcs 20–31 to the 12 Pure SLH-DSA OIDs.
	var arc int
	switch s.ID {
	case SHA2_128s:
		arc = 20
	case SHA2_128f:
		arc = 21
	case SHA2_192s:
		arc = 22
	case SHA2_192f:
		arc = 23
	case SHA2_256s:
		arc = 24
	case SHA2_256f:
		arc = 25
	case SHAKE_128s:
		arc = 26
	case SHAKE_128f:
		arc = 27
	case SHAKE_192s:
		arc = 28
	case SHAKE_192f:
		arc = 29
	case SHAKE_256s:
		arc = 30
	case SHAKE_256f:
		arc = 31
	default:
		panic("slhdsa: unknown parameter set")
	}
	oid := make(asn1.ObjectIdentifier, len(sigAlgsArc)+1)
	copy(oid, sigAlgsArc)
	oid[len(sigAlgsArc)] = arc
	return oid
}

// GenerateKey is similar to [GenerateKey] function, except it always reads
// random bytes from [rand.Reader].
func (s scheme) GenerateKey() (sign.PublicKey, sign.PrivateKey, error) {
	return GenerateKey(rand.Reader, s.ID)
}

// Sign returns a randomized pure signature of the message with the context
// given.
// If options is nil, an empty context is used.
// It returns an empty slice if the signature generation fails.
//
// Panics if the key is not a [PrivateKey] or when the [ID] mismatches.
func (s scheme) Sign(
	priv sign.PrivateKey, message []byte, options *sign.SignatureOpts,
) []byte {
	k, ok := priv.(PrivateKey)
	if !ok || s.ID != k.ID {
		panic(sign.ErrTypeMismatch)
	}

	var context []byte
	if options != nil {
		context = []byte(options.Context)
	}

	sig, err := SignRandomized(&k, rand.Reader, NewMessage(message), context)
	if err != nil {
		return nil
	}

	return sig
}

// Verify returns true if the signature of the message with the specified
// context is valid.
// If options is nil, an empty context is used.
//
// Panics if the key is not a [PublicKey] or when the [ID] mismatches.
func (s scheme) Verify(
	pub sign.PublicKey, message, signature []byte, options *sign.SignatureOpts,
) bool {
	k, ok := pub.(PublicKey)
	if !ok || s.ID != k.ID {
		panic(sign.ErrTypeMismatch)
	}

	var context []byte
	if options != nil {
		context = []byte(options.Context)
	}

	return Verify(&k, NewMessage(message), signature, context)
}

// DeriveKey deterministically generates a pair of keys from a seed.
//
// Panics if seed is not of length [sign.Scheme.SeedSize].
func (s scheme) DeriveKey(seed []byte) (sign.PublicKey, sign.PrivateKey) {
	if len(seed) != s.SeedSize() {
		panic(sign.ErrSeedSize)
	}

	n := s.n
	buf := make([]byte, 3*n)
	if s.isSHA2 {
		s.mgf1(buf, seed, 3*n)
	} else {
		sha3.ShakeSum256(buf, seed)
	}

	c := cursor(buf)
	skSeed := c.Next(n)
	skPrf := c.Next(n)
	pkSeed := c.Next(n)

	return slhKeyGenInternal(s.params, skSeed, skPrf, pkSeed)
}

func (s scheme) UnmarshalBinaryPublicKey(b []byte) (sign.PublicKey, error) {
	k := PublicKey{ID: s.ID}
	err := k.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}

	return k, nil
}

func (s scheme) UnmarshalBinaryPrivateKey(b []byte) (sign.PrivateKey, error) {
	k := PrivateKey{ID: s.ID}
	err := k.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}

	return k, nil
}
