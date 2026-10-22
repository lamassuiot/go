package x509

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"slices"
	"testing"
	"time"
)

func TestRelatedCertRequestAttribute(t *testing.T) {
	ecKey := func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }
	rsaKey := func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 3072) }
	edKey := func() (crypto.Signer, error) {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		return k, err
	}

	testcases := []struct {
		name string
		key  func() (crypto.Signer, error)
	}{
		{"ECDSA", ecKey},
		{"RSA", rsaKey},
		{"Ed25519", edKey},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := tc.key()
			if err != nil {
				t.Fatal(err)
			}
			related := selfSignedRelated(t, key)
			now := time.Now().Truncate(time.Second)
			locations := []string{"https://example.com/related.crt", "http://example.org/other.crt"}

			attr, err := CreateRelatedCertRequestAttribute(rand.Reader, related, key, now, locations)
			if err != nil {
				t.Fatal(err)
			}
			csr := createCSRWithAttributes(t, attr)

			parsed, err := ParseRelatedCertRequestAttribute(csr)
			if err != nil {
				t.Fatal(err)
			}
			if !parsed.RequestTime.Equal(now) || !slices.Equal(parsed.LocationInfo, locations) {
				t.Errorf("unexpected attribute content: %+v", parsed)
			}
			if err := parsed.Verify(related, now, time.Minute); err != nil {
				t.Errorf("valid attribute rejected: %v", err)
			}
		})
	}
}

func TestRelatedCertRequestAttributeVerify(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	related := selfSignedRelated(t, key)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other := selfSignedRelated(t, otherKey)
	now := time.Now().Truncate(time.Second)

	parse := func(requestTime time.Time) *RelatedCertRequestAttribute {
		t.Helper()
		attr, err := CreateRelatedCertRequestAttribute(rand.Reader, related, key, requestTime, []string{"https://example.com/a.crt"})
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseRelatedCertRequestAttribute(createCSRWithAttributes(t, attr))
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}

	tampered := parse(now)
	tampered.RequestTime = tampered.RequestTime.Add(time.Second)

	testcases := []struct {
		name    string
		attr    *RelatedCertRequestAttribute
		related *Certificate
		wantErr bool
	}{
		{"valid", parse(now), related, false},
		{"other certificate", parse(now), other, true},
		{"stale", parse(now.Add(-time.Hour)), related, true},
		{"from the future", parse(now.Add(time.Hour)), related, true},
		{"tampered request time", tampered, related, true},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.attr.Verify(tc.related, now, time.Minute)
			if (err != nil) != tc.wantErr {
				t.Errorf("wantErr %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestCreateRelatedCertRequestAttributeErrors(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	related := selfSignedRelated(t, key)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := CreateRelatedCertRequestAttribute(rand.Reader, related, otherKey, time.Now(), []string{"https://example.com"}); err == nil {
		t.Error("expected an error for a key that does not match the related certificate")
	}
	if _, err := CreateRelatedCertRequestAttribute(rand.Reader, related, key, time.Now(), nil); err == nil {
		t.Error("expected an error for empty locationInfo")
	}
}

func TestParseRelatedCertRequestAttributeMissing(t *testing.T) {
	csr := createCSRWithAttributes(t)
	if _, err := ParseRelatedCertRequestAttribute(csr); err == nil {
		t.Error("expected an error for a CSR without the attribute")
	}
}

func selfSignedRelated(t *testing.T, key crypto.Signer) *Certificate {
	t.Helper()
	template := &Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "related"}}
	der, err := CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func createCSRWithAttributes(t *testing.T, attrs ...asn1.RawValue) *CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &CertificateRequest{Subject: pkix.Name{CommonName: "bound"}, ExtraAttributes: attrs}
	der, err := CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	return csr
}
