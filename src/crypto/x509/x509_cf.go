package x509

import (
	"crypto"
	"encoding/asn1"

	circlPki "cloudflare/circl/pki"
	circlSign "cloudflare/circl/sign"
	"cloudflare/circl/sign/mldsa/mldsa44"
	"cloudflare/circl/sign/mldsa/mldsa65"
	"cloudflare/circl/sign/mldsa/mldsa87"
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
				crypto.Hash(0),      // No pre-hashing
				false,
			},
		)
	}
}
