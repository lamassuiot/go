package x509

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func TestCreateBoundCertificate(t *testing.T) {
	rsaKey := func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 3072) }
	p256Key := func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }
	p521Key := func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P521(), rand.Reader) }
	ed25519Key := func() (crypto.Signer, error) {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		return k, err
	}

	testcases := []struct {
		name       string
		issuerKey  func() (crypto.Signer, error)
		subjectKey func() (crypto.Signer, error)
		sigAlgo    SignatureAlgorithm
		wantDigest asn1.ObjectIdentifier
	}{
		{name: "SHA256-RSA", issuerKey: rsaKey, subjectKey: rsaKey, sigAlgo: SHA256WithRSA, wantDigest: oidSHA256},
		{name: "SHA384-RSA-PSS", issuerKey: rsaKey, subjectKey: rsaKey, sigAlgo: SHA384WithRSAPSS, wantDigest: oidSHA384},
		{name: "SHA512-ECDSA", issuerKey: p521Key, subjectKey: p521Key, sigAlgo: ECDSAWithSHA512, wantDigest: oidSHA512},
		{name: "Ed25519 falls back to SHA256", issuerKey: ed25519Key, subjectKey: ed25519Key, sigAlgo: PureEd25519, wantDigest: oidSHA256},
		{name: "ECDSA subject issued by RSA CA", issuerKey: rsaKey, subjectKey: p256Key, sigAlgo: SHA384WithRSA, wantDigest: oidSHA384},
		{name: "RSA subject issued by ECDSA CA", issuerKey: p521Key, subjectKey: rsaKey, sigAlgo: ECDSAWithSHA512, wantDigest: oidSHA512},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			relatedCert, err := createRelatedCertificate(tc.issuerKey, tc.subjectKey, tc.sigAlgo)
			if err != nil {
				t.Fatal(err)
			}

			extraExtensions := []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{5, 0}}}
			template := &Certificate{
				SerialNumber:    big.NewInt(2),
				Subject:         pkix.Name{Organization: []string{"Test Org"}},
				ExtraExtensions: extraExtensions,
			}
			pqKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
			if err != nil {
				t.Fatal(err)
			}
			der, err := CreateBoundCertificate(rand.Reader, template, template, relatedCert.Raw, pqKey.Public(), pqKey)
			if err != nil {
				t.Fatalf("error generating the bound certificate: %v", err)
			}
			boundCert, err := ParseCertificate(der)
			if err != nil {
				t.Fatalf("error parsing the bound certificate: %v", err)
			}

			if len(template.ExtraExtensions) != len(extraExtensions) {
				t.Errorf("the template's ExtraExtensions were modified")
			}

			var ext *pkix.Extension
			for i := range boundCert.Extensions {
				if boundCert.Extensions[i].Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 36}) {
					ext = &boundCert.Extensions[i]
				}
			}
			if ext == nil {
				t.Fatal("the bound certificate does not contain the RelatedCertificate extension")
			}
			if ext.Critical {
				t.Error("the RelatedCertificate extension must not be critical")
			}

			var parsed relatedCertificateExtension
			if rest, err := asn1.Unmarshal(ext.Value, &parsed); err != nil || len(rest) != 0 {
				t.Fatalf("could not parse the RelatedCertificate extension: %v", err)
			}

			if !parsed.HashAlgorithm.Algorithm.Equal(tc.wantDigest) {
				t.Errorf("hash algorithm: expected %v, got %v", tc.wantDigest, parsed.HashAlgorithm.Algorithm)
			}

			var want []byte
			switch {
			case tc.wantDigest.Equal(oidSHA256):
				sum := sha256.Sum256(relatedCert.Raw)
				want = sum[:]
			case tc.wantDigest.Equal(oidSHA384):
				sum := sha512.Sum384(relatedCert.Raw)
				want = sum[:]
			case tc.wantDigest.Equal(oidSHA512):
				sum := sha512.Sum512(relatedCert.Raw)
				want = sum[:]
			}
			if !bytes.Equal(parsed.HashValue, want) {
				t.Error("the hash value does not match the related certificate")
			}
		})
	}
}

func createRelatedCertificate(issuerKey, subjectKey func() (crypto.Signer, error), sigAlgo SignatureAlgorithm) (*Certificate, error) {
	caPriv, err := issuerKey()
	if err != nil {
		return nil, fmt.Errorf("could not generate the issuer key: %v", err)
	}
	caTemplate := &Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test CA"}},
		KeyUsage:              KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDer, err := CreateCertificate(rand.Reader, caTemplate, caTemplate, caPriv.Public(), caPriv)
	if err != nil {
		return nil, fmt.Errorf("could not create the CA certificate: %v", err)
	}
	caCert, err := ParseCertificate(caDer)
	if err != nil {
		return nil, err
	}

	subjectPriv, err := subjectKey()
	if err != nil {
		return nil, fmt.Errorf("could not generate the subject key: %v", err)
	}
	template := &Certificate{
		SerialNumber:       big.NewInt(3),
		Subject:            pkix.Name{Organization: []string{"Test Org"}, CommonName: "related"},
		KeyUsage:           KeyUsageDigitalSignature,
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		SignatureAlgorithm: sigAlgo,
	}
	der, err := CreateCertificate(rand.Reader, template, caCert, subjectPriv.Public(), caPriv)
	if err != nil {
		return nil, fmt.Errorf("could not create the related certificate: %v", err)
	}
	cert, err := ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if cert.SignatureAlgorithm != sigAlgo {
		return nil, fmt.Errorf("related certificate signed with %v, expected %v", cert.SignatureAlgorithm, sigAlgo)
	}
	return cert, nil
}

func TestCreateBoundCertificateChecks(t *testing.T) {
	now := time.Now()
	createRelated := func(tmpl Certificate) *Certificate {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.SerialNumber = big.NewInt(1)
		tmpl.Subject = pkix.Name{CommonName: "related"}
		der, err := CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	valid := Certificate{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	withUsages := func(c Certificate, ku KeyUsage, eku ...ExtKeyUsage) Certificate {
		c.KeyUsage, c.ExtKeyUsage = ku, eku
		return c
	}
	customEKU := []asn1.ObjectIdentifier{{1, 2, 3, 4}}

	testcases := []struct {
		name     string
		related  Certificate
		template Certificate
		wantErr  bool
	}{
		{"no usages", valid, Certificate{}, false},
		{"usages are a subset",
			withUsages(valid, KeyUsageDigitalSignature|KeyUsageKeyEncipherment, ExtKeyUsageClientAuth, ExtKeyUsageServerAuth),
			withUsages(Certificate{}, KeyUsageDigitalSignature, ExtKeyUsageClientAuth), false},
		{"missing key usage",
			withUsages(valid, KeyUsageDigitalSignature),
			withUsages(Certificate{}, KeyUsageDigitalSignature|KeyUsageKeyEncipherment), true},
		{"missing extended key usage",
			withUsages(valid, KeyUsageDigitalSignature, ExtKeyUsageClientAuth),
			withUsages(Certificate{}, KeyUsageDigitalSignature, ExtKeyUsageServerAuth), true},
		{"missing unknown extended key usage", valid, Certificate{UnknownExtKeyUsage: customEKU}, true},
		{"unknown extended key usage present",
			Certificate{NotBefore: valid.NotBefore, NotAfter: valid.NotAfter, UnknownExtKeyUsage: customEKU},
			Certificate{UnknownExtKeyUsage: customEKU}, false},
		{"expired", Certificate{NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour)}, Certificate{}, true},
		{"not yet valid", Certificate{NotBefore: now.Add(time.Hour), NotAfter: now.Add(2 * time.Hour)}, Certificate{}, true},
		{"CA related certificate", Certificate{NotBefore: valid.NotBefore, NotAfter: valid.NotAfter, IsCA: true, BasicConstraintsValid: true}, Certificate{}, true},
		{"CA template", valid, Certificate{IsCA: true, BasicConstraintsValid: true}, true},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			relatedCert := createRelated(tc.related)
			pqKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
			if err != nil {
				t.Fatal(err)
			}
			template := tc.template
			template.SerialNumber = big.NewInt(2)
			template.Subject = pkix.Name{CommonName: "bound"}
			_, err = CreateBoundCertificate(rand.Reader, &template, &template, relatedCert.Raw, pqKey.Public(), pqKey)
			if (err != nil) != tc.wantErr {
				t.Errorf("wantErr %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestVerifyRelatedCertificate(t *testing.T) {
	ecKey := func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }
	related, err := createRelatedCertificate(ecKey, ecKey, ECDSAWithSHA256)
	if err != nil {
		t.Fatal(err)
	}
	other, err := createRelatedCertificate(ecKey, ecKey, ECDSAWithSHA256)
	if err != nil {
		t.Fatal(err)
	}

	pqKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	createWith := func(extra ...pkix.Extension) *Certificate {
		t.Helper()
		template := &Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "bound"}, ExtraExtensions: extra}
		der, err := CreateCertificate(rand.Reader, template, template, pqKey.Public(), pqKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	relatedExtension := func(algorithm asn1.ObjectIdentifier, value []byte) pkix.Extension {
		t.Helper()
		der, err := asn1.Marshal(relatedCertificateExtension{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: algorithm},
			HashValue:     value,
		})
		if err != nil {
			t.Fatal(err)
		}
		return pkix.Extension{Id: relatedCertificateExtensionOid, Value: der}
	}

	template := &Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "bound"}}
	der, err := CreateBoundCertificate(rand.Reader, template, template, related.Raw, pqKey.Public(), pqKey)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	sum384 := sha512.Sum384(related.Raw)
	sum1 := sha1.Sum(related.Raw)

	testcases := []struct {
		name    string
		cert    *Certificate
		related *Certificate
		wantErr bool
	}{
		{"matching certificate", bound, related, false},
		{"different certificate", bound, other, true},
		{"no extension", createWith(), related, true},
		{"SHA-384 digest", createWith(relatedExtension(oidSHA384, sum384[:])), related, false},
		{"wrong hash value", createWith(relatedExtension(oidSHA256, make([]byte, 32))), related, true},
		{"unsupported digest", createWith(relatedExtension(asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, sum1[:])), related, true},
		{"malformed extension", createWith(pkix.Extension{Id: relatedCertificateExtensionOid, Value: []byte{1, 2, 3}}), related, true},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyRelatedCertificate(tc.cert, tc.related); (err != nil) != tc.wantErr {
				t.Errorf("wantErr %v, got %v", tc.wantErr, err)
			}
		})
	}
}
