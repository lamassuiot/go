package x509

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"time"
)

// id-aa-relatedCertRequest, RFC 9763
var relatedCertRequestAttributeOid = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 60}

type issuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type requesterCertificate struct {
	CertID       issuerAndSerialNumber
	RequestTime  int64
	LocationInfo []asn1.RawValue
	Signature    asn1.BitString
}

// RelatedCertRequestAttribute is the relatedCertRequest CSR attribute (RFC 9763).
type RelatedCertRequestAttribute struct {
	RawIssuer    []byte
	SerialNumber *big.Int
	RequestTime  time.Time
	LocationInfo []string
	Signature    []byte
}

// CreateRelatedCertRequestAttribute creates the attribute for related, signed
// with its private key, to be used in CertificateRequest.ExtraAttributes.
func CreateRelatedCertRequestAttribute(rand io.Reader, related *Certificate, relatedKey crypto.Signer, requestTime time.Time, locationInfo []string) (asn1.RawValue, error) {
	if pub, ok := relatedKey.Public().(interface{ Equal(crypto.PublicKey) bool }); !ok || !pub.Equal(related.PublicKey) {
		return asn1.RawValue{}, errors.New("x509: the private key does not match the related certificate")
	}
	if len(locationInfo) == 0 {
		return asn1.RawValue{}, errors.New("x509: locationInfo must contain at least one URI")
	}

	req := requesterCertificate{
		CertID:      issuerAndSerialNumber{Issuer: asn1.RawValue{FullBytes: related.RawIssuer}, SerialNumber: related.SerialNumber},
		RequestTime: requestTime.Unix(),
	}
	for _, uri := range locationInfo {
		req.LocationInfo = append(req.LocationInfo, asn1.RawValue{Tag: asn1.TagIA5String, Bytes: []byte(uri)})
	}

	signed, err := relatedCertRequestSignedData(req)
	if err != nil {
		return asn1.RawValue{}, err
	}
	sigAlgo, _, err := signingParamsForKey(relatedKey, 0)
	if err != nil {
		return asn1.RawValue{}, err
	}
	signature, err := signTBS(signed, relatedKey, sigAlgo, rand)
	if err != nil {
		return asn1.RawValue{}, err
	}
	req.Signature = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}

	der, err := asn1.Marshal(struct {
		Type   asn1.ObjectIdentifier
		Values []requesterCertificate `asn1:"set"`
	}{relatedCertRequestAttributeOid, []requesterCertificate{req}})
	if err != nil {
		return asn1.RawValue{}, err
	}
	return asn1.RawValue{FullBytes: der}, nil
}

// ParseRelatedCertRequestAttribute returns the attribute of csr.
func ParseRelatedCertRequestAttribute(csr *CertificateRequest) (*RelatedCertRequestAttribute, error) {
	var tbs tbsCertificateRequest
	if _, err := asn1.Unmarshal(csr.RawTBSCertificateRequest, &tbs); err != nil {
		return nil, err
	}

	for _, rawAttr := range tbs.RawAttributes {
		var attr struct {
			Type   asn1.ObjectIdentifier
			Values []asn1.RawValue `asn1:"set"`
		}
		if _, err := asn1.Unmarshal(rawAttr.FullBytes, &attr); err != nil || !attr.Type.Equal(relatedCertRequestAttributeOid) {
			continue
		}
		if len(attr.Values) != 1 {
			return nil, errors.New("x509: the relatedCertRequest attribute must contain exactly one value")
		}

		var req requesterCertificate
		if rest, err := asn1.Unmarshal(attr.Values[0].FullBytes, &req); err != nil || len(rest) != 0 {
			return nil, errors.New("x509: malformed relatedCertRequest attribute")
		}
		if len(req.LocationInfo) == 0 {
			return nil, errors.New("x509: the relatedCertRequest attribute has no locationInfo")
		}

		result := &RelatedCertRequestAttribute{
			RawIssuer:    req.CertID.Issuer.FullBytes,
			SerialNumber: req.CertID.SerialNumber,
			RequestTime:  time.Unix(req.RequestTime, 0),
			Signature:    req.Signature.RightAlign(),
		}
		for _, uri := range req.LocationInfo {
			if uri.Class != asn1.ClassUniversal || uri.Tag != asn1.TagIA5String {
				return nil, errors.New("x509: locationInfo must contain IA5String URIs")
			}
			result.LocationInfo = append(result.LocationInfo, string(uri.Bytes))
		}
		return result, nil
	}
	return nil, errors.New("x509: the certificate request does not contain the relatedCertRequest attribute")
}

// Verify checks that the attribute identifies related, is at most maxAge old
// and is signed with related's key.
func (a *RelatedCertRequestAttribute) Verify(related *Certificate, now time.Time, maxAge time.Duration) error {
	if !bytes.Equal(a.RawIssuer, related.RawIssuer) || a.SerialNumber.Cmp(related.SerialNumber) != 0 {
		return errors.New("x509: the related certificate is not the one identified by the attribute")
	}
	if age := now.Sub(a.RequestTime); age > maxAge || age < -maxAge {
		return errors.New("x509: the relatedCertRequest requestTime is not fresh")
	}

	signed, err := relatedCertRequestSignedData(requesterCertificate{
		CertID:      issuerAndSerialNumber{Issuer: asn1.RawValue{FullBytes: a.RawIssuer}, SerialNumber: a.SerialNumber},
		RequestTime: a.RequestTime.Unix(),
	})
	if err != nil {
		return err
	}
	sigAlgo, _, err := signingParamsForPublicKey(related.PublicKey, 0)
	if err != nil {
		return err
	}
	return checkSignature(sigAlgo, signed, a.Signature, related.PublicKey, false)
}

// relatedCertRequestSignedData returns the signed input: DER(certID) || DER(requestTime).
func relatedCertRequestSignedData(req requesterCertificate) ([]byte, error) {
	certID, err := asn1.Marshal(req.CertID)
	if err != nil {
		return nil, err
	}
	requestTime, err := asn1.Marshal(req.RequestTime)
	if err != nil {
		return nil, err
	}
	return append(certID, requestTime...), nil
}
