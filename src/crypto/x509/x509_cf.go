package x509

import (
	"crypto"
	"encoding/asn1"

	circlPki "cloudflare/circl/pki"
	circlSign "cloudflare/circl/sign"
	"cloudflare/circl/sign/mldsa/mldsa44"
	"cloudflare/circl/sign/mldsa/mldsa65"
	"cloudflare/circl/sign/mldsa/mldsa87"
	"cloudflare/circl/sign/slhdsa"
)

// To add a signature scheme from Circl
//
//   1. make sure it implements CertificateScheme,
//	 2. add SignatureAlgorithm and PublicKeyAlgorithm constants in x509.go
//   3. add row in circlSchemes below
//   4. update publicKeyAlgoName in x509.go

var circlSchemes = [...]struct {
	sga    SignatureAlgorithm
	alg    PublicKeyAlgorithm
	scheme circlSign.Scheme
}{
	{PureMLDSA44, MLDSA, mldsa44.Scheme()},
	{PureMLDSA65, MLDSA, mldsa65.Scheme()},
	{PureMLDSA87, MLDSA, mldsa87.Scheme()},
	// SLH-DSA (RFC 9909) — Pure SLH-DSA parameter sets.
	{PureSLHDSASHA2128s, SLHDSA, slhdsa.SHA2_128s.Scheme()},
	{PureSLHDSASHA2128f, SLHDSA, slhdsa.SHA2_128f.Scheme()},
	{PureSLHDSASHA2192s, SLHDSA, slhdsa.SHA2_192s.Scheme()},
	{PureSLHDSASHA2192f, SLHDSA, slhdsa.SHA2_192f.Scheme()},
	{PureSLHDSASHA2256s, SLHDSA, slhdsa.SHA2_256s.Scheme()},
	{PureSLHDSASHA2256f, SLHDSA, slhdsa.SHA2_256f.Scheme()},
	{PureSLHDSASHAKE128s, SLHDSA, slhdsa.SHAKE_128s.Scheme()},
	{PureSLHDSASHAKE128f, SLHDSA, slhdsa.SHAKE_128f.Scheme()},
	{PureSLHDSASHAKE192s, SLHDSA, slhdsa.SHAKE_192s.Scheme()},
	{PureSLHDSASHAKE192f, SLHDSA, slhdsa.SHAKE_192f.Scheme()},
	{PureSLHDSASHAKE256s, SLHDSA, slhdsa.SHAKE_256s.Scheme()},
	{PureSLHDSASHAKE256f, SLHDSA, slhdsa.SHAKE_256f.Scheme()},
}

func CirclSchemeByPublicKeyAlgorithm(alg PublicKeyAlgorithm) circlSign.Scheme {
	for _, cs := range circlSchemes {
		if cs.alg == alg {
			return cs.scheme
		}
	}
	return nil
}

func SignatureAlgorithmByCirclScheme(scheme circlSign.Scheme) SignatureAlgorithm {
	for _, cs := range circlSchemes {
		if cs.scheme == scheme {
			return cs.sga
		}
	}
	return UnknownSignatureAlgorithm
}

func PublicKeyAlgorithmByCirclScheme(scheme circlSign.Scheme) PublicKeyAlgorithm {
	for _, cs := range circlSchemes {
		if cs.scheme == scheme {
			return cs.alg
		}
	}
	return UnknownPublicKeyAlgorithm
}

func init() {
	for _, cs := range circlSchemes {
		signatureAlgorithmDetails = append(signatureAlgorithmDetails,
			struct {
				algo       SignatureAlgorithm
				name       string
				oid        asn1.ObjectIdentifier
				params     asn1.RawValue
				pubKeyAlgo PublicKeyAlgorithm
				hash       crypto.Hash
				isRSAPSS   bool
			}{
				cs.sga,
				cs.scheme.Name(),
				cs.scheme.(circlPki.CertificateScheme).Oid(),
				emptyRawValue,
				cs.alg,
				crypto.Hash(0), // No pre-hashing
				false,
			},
		)
	}
}
