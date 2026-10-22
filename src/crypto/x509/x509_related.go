package x509

import (
	"bytes"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"slices"
	"time"
)

// id-pe-relatedCert, RFC 9763
var relatedCertificateExtensionOid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 36}

type relatedCertificateExtension struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashValue     []byte
}

// CreateBoundCertificate creates a certificate with the RelatedCertificate
// extension (RFC 9763) for relatedCertDer.
func CreateBoundCertificate(randSource io.Reader, template, parent *Certificate, relatedCertDer []byte, pubKey, privKey any) ([]byte, error) {
	relatedCert, err := ParseCertificate(relatedCertDer)
	if err != nil {
		return nil, err
	}

	if err := checkRelatedCertificate(template, relatedCert, time.Now()); err != nil {
		return nil, err
	}

	hash, digestAlgorithm := relatedCertDigest(relatedCert.SignatureAlgorithm)
	relatedCertExtension := relatedCertificateExtension{
		HashAlgorithm: digestAlgorithm,
		HashValue:     hashRelatedCert(hash, relatedCert),
	}
	rawRelatedCertExtension, err := asn1.Marshal(relatedCertExtension)
	if err != nil {
		return nil, err
	}

	// Work on a copy so the caller's template is not modified
	boundTemplate := *template
	boundTemplate.ExtraExtensions = append(slices.Clone(template.ExtraExtensions), pkix.Extension{
		Id:    relatedCertificateExtensionOid,
		Value: rawRelatedCertExtension,
	})

	return CreateCertificate(randSource, &boundTemplate, parent, pubKey, privKey)
}

type relatedCertDigestInfo struct {
	hash crypto.Hash
	oid  asn1.ObjectIdentifier
}

var relatedCertDigests = []relatedCertDigestInfo{
	{crypto.SHA256, oidSHA256},
	{crypto.SHA384, oidSHA384},
	{crypto.SHA512, oidSHA512},
}

// relatedCertDigest returns the hash of the signature algorithm, defaulting to
// SHA-256 (the first entry) when it has none or it is unsupported.
func relatedCertDigest(sigAlgo SignatureAlgorithm) (crypto.Hash, pkix.AlgorithmIdentifier) {
	hash := sigAlgo.hashFunc()
	i := slices.IndexFunc(relatedCertDigests, func(d relatedCertDigestInfo) bool {
		return d.hash == hash
	})
	if i < 0 {
		i = 0
	}
	d := relatedCertDigests[i]
	return d.hash, pkix.AlgorithmIdentifier{Algorithm: d.oid}
}

func hashRelatedCert(hash crypto.Hash, related *Certificate) []byte {
	h := hash.New()
	h.Write(related.Raw)
	return h.Sum(nil)
}

func checkRelatedCertificate(template, related *Certificate, now time.Time) error {
	if template.IsCA {
		return errors.New("x509: a bound certificate must be an end-entity certificate")
	}
	if related.IsCA {
		return errors.New("x509: the related certificate must be an end-entity certificate")
	}
	if now.Before(related.NotBefore) || now.After(related.NotAfter) {
		return errors.New("x509: the related certificate is not valid at the time of issuance")
	}
	if template.KeyUsage&related.KeyUsage != template.KeyUsage {
		return errors.New("x509: the related certificate does not contain all the key usages of the bound certificate")
	}
	for _, eku := range template.ExtKeyUsage {
		if !slices.Contains(related.ExtKeyUsage, eku) {
			return errors.New("x509: the related certificate does not contain all the extended key usages of the bound certificate")
		}
	}
	for _, eku := range template.UnknownExtKeyUsage {
		if !slices.ContainsFunc(related.UnknownExtKeyUsage, eku.Equal) {
			return errors.New("x509: the related certificate does not contain all the extended key usages of the bound certificate")
		}
	}
	return nil
}

// VerifyRelatedCertificate checks that cert has a RelatedCertificate extension
// matching related.
func VerifyRelatedCertificate(cert, related *Certificate) error {
	i := slices.IndexFunc(cert.Extensions, func(e pkix.Extension) bool {
		return e.Id.Equal(relatedCertificateExtensionOid)
	})
	if i < 0 {
		return errors.New("x509: the certificate does not contain the RelatedCertificate extension")
	}

	var ext relatedCertificateExtension
	if rest, err := asn1.Unmarshal(cert.Extensions[i].Value, &ext); err != nil || len(rest) != 0 {
		return errors.New("x509: malformed RelatedCertificate extension")
	}

	j := slices.IndexFunc(relatedCertDigests, func(d relatedCertDigestInfo) bool {
		return d.oid.Equal(ext.HashAlgorithm.Algorithm)
	})
	if j < 0 {
		return errors.New("x509: unsupported hash algorithm in the RelatedCertificate extension")
	}

	if !bytes.Equal(hashRelatedCert(relatedCertDigests[j].hash, related), ext.HashValue) {
		return errors.New("x509: the related certificate does not match the RelatedCertificate extension")
	}
	return nil
}
