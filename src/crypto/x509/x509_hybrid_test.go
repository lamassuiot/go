package x509

import (
	"bytes"
	"cloudflare/circl/sign/mldsa/mldsa65"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"hash"
	"math/big"
	"reflect"
	"testing"
)

// In order to dump a PEM encoded certificate, use the following instruction:
// pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: deltaCert.Raw})

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Test Cases                                                                 //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

func TestReconstructRootDeltaCertificate(t *testing.T) {
	// Decode the base certificate
	block, _ := pem.Decode([]byte(MLDSA_BASE_ECDSA_P521_DELTA))
	if block == nil {
		t.Errorf("Unexpected Error Decoding the Sample Certificate")
	}
	base, err := ParseCertificate(block.Bytes)
	if err != nil {
		t.Errorf("Unexpected Error %v", err)
	}

	// Reconstruct the Delta Certificate
	delta, err := ReconstructDeltaCertificate(base)
	if err != nil {
		t.Errorf("ReconstructDeltaCertificate(): %v", err)
	}

	// Verify delta has correct serial number
	serial := bigFromString("69312012636240201618468802377251194874906625216")
	if serial.String() != delta.SerialNumber.String() {
		t.Errorf("ReconstructDeltaCertificate() - SerialNumber: want %v, got %v", serial, delta.SerialNumber)
	}

	// Verify certificate has correct Signature Algorithm
	sigAlgo := "ECDSA-SHA512"
	if delta.SignatureAlgorithm.String() != sigAlgo {
		t.Errorf("ReconstructDeltaCertificate() - Signature Algorithm: want %v, got %v", sigAlgo, delta.SignatureAlgorithm)
	}

	// Verify certificate Issuer
	issuer := "CN=ECDSA Root - G1,OU=Post-Heffalump Research Department+OU=Post-Heffalump Research Department,O=Royal Institute of Public Key Infrastructure+O=Royal Institute of Public Key Infrastructure,C=XX+C=XX"
	if delta.Issuer.String() != issuer {
		t.Errorf("ReconstructDeltaCertificate() - Issuer: want %v, got %v", issuer, delta.Issuer)
	}

	// Verify certificate Public Key Algorithm
	pubKeyAlgo := "ECDSA"
	if delta.PublicKeyAlgorithm.String() != pubKeyAlgo {
		t.Errorf("ReconstructDeltaCertificate() - PubKeyAlgorithm: want %v, got %v", pubKeyAlgo, delta.PublicKeyAlgorithm)
	}

	// Verify certificate Extensions
	if len(delta.Extensions) != 4 {
		t.Errorf("ReconstructDeltaCertificate() - Extensions: want %v extensions, got %v", 4, len(delta.Extensions))
	}

	basicConstraintsOid := "2.5.29.19"
	basicConstraintsValue := []byte{0x30, 0x03, 0x01, 0x01, 0xFF}
	if delta.Extensions[0].Id.String() != basicConstraintsOid && bytes.Equal(delta.Extensions[0].Value, basicConstraintsValue) {
		t.Errorf("ReconstructDeltaCertificate() - basicConstraints: want %v,%v got %v,%v", basicConstraintsOid, basicConstraintsValue, delta.Extensions[0].Id, delta.Extensions[0].Value)
	}

	keyUsageOid := "2.5.29.15"
	keyUsageValue := []byte{0x04, 0x04, 0x03, 0x02, 0x01, 0x86}
	if delta.Extensions[1].Id.String() != keyUsageOid && bytes.Equal(delta.Extensions[1].Value, keyUsageValue) {
		t.Errorf("ReconstructDeltaCertificate() - keyUsage: want %v,%v got %v,%v", keyUsageOid, keyUsageValue, delta.Extensions[1].Id, delta.Extensions[1].Value)
	}

	subjectKeyIdentifierOid := "2.5.29.14"
	subjectKeyIdentifierValue := []byte{0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x9B, 0x07, 0xB4, 0xA4, 0x75, 0xC4, 0xBC, 0x91, 0x5D, 0x35, 0xE0, 0xC9, 0xA1, 0xC1, 0x62, 0xE2, 0x77, 0x55, 0xD6, 0x3F}
	if delta.Extensions[2].Id.String() != subjectKeyIdentifierOid && bytes.Equal(delta.Extensions[2].Value, subjectKeyIdentifierValue) {
		t.Errorf("ReconstructDeltaCertificate() - subjectKeyIdentifier: want %v,%v got %v,%v", subjectKeyIdentifierOid, subjectKeyIdentifierValue, delta.Extensions[2].Id, delta.Extensions[2].Value)
	}

	authorityKeyIdentifierOid := "2.5.29.35"
	authorityKeyIdentifierValue := []byte{0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x9B, 0x07, 0xB4, 0xA4, 0x75, 0xC4, 0xBC, 0x91, 0x5D, 0x35, 0xE0, 0xC9, 0xA1, 0xC1, 0x62, 0xE2, 0x77, 0x55, 0xD6, 0x3F}
	if delta.Extensions[2].Id.String() != authorityKeyIdentifierOid && bytes.Equal(delta.Extensions[2].Value, authorityKeyIdentifierValue) {
		t.Errorf("ReconstructDeltaCertificate() - authorityKeyIdentifier: want %v,%v got %v,%v", authorityKeyIdentifierOid, authorityKeyIdentifierValue, delta.Extensions[2].Id, delta.Extensions[2].Value)
	}

	// Verify delta certificate signature
	err = delta.CheckSignature(delta.SignatureAlgorithm, delta.RawTBSCertificate, delta.Signature)
	if err != nil {
		t.Errorf("ReconstructDeltaCertificate() - Incorrect Delta Signature")
	}

	// Verify base certificate signature
	err = base.CheckSignature(base.SignatureAlgorithm, base.RawTBSCertificate, base.Signature)
	if err != nil {
		t.Errorf("ReconstructDeltaCertificate() - Incorrect Base Signature")
	}
}

func TestCreateChameleonRootCertificate(t *testing.T) {
	// Generate the certificate
	_, _, chameleonCert, err := createChameleonRoot()
	if err != nil {
		t.Error(err)
	}

	// Check that the chameleon certificate contains the Delta extension
	found := false
	for _, ext := range chameleonCert.Extensions {
		if ext.Id.String() == deltaExtensionOid.String() {
			found = true
		}
	}
	if !found {
		t.Error("Expected the chameleon certificate to have a Delta extension")
	}

	// Check that the chameleon certificate is valid
	err = chameleonCert.CheckSignature(chameleonCert.SignatureAlgorithm, chameleonCert.RawTBSCertificate, chameleonCert.Signature)
	if err != nil {
		t.Error("Incorrect base signature")
	}

	// Reconstruct the delta certificate
	deltaCert, err := ReconstructDeltaCertificate(chameleonCert)
	if err != nil {
		t.Error(err)
	}

	// Verify the delta signature
	err = deltaCert.CheckSignature(deltaCert.SignatureAlgorithm, deltaCert.RawTBSCertificate, deltaCert.Signature)
	if err != nil {
		t.Error(err)
		t.Error("Incorrect delta signature")
	}
}

func TestCreateChameleonSubordinateCertificate(t *testing.T) {
	// Generate a root chameleon certificate
	deltaRootPrivKey, baseRootPrivKey, baseRootCert, err := createChameleonRoot()
	if err != nil {
		t.Error(err)
	}

	// Extract the delta certificate
	deltaRootCert, err := ReconstructDeltaCertificate(baseRootCert)
	if err != nil {
		t.Error(err)
	}

	// Generate a root chameleon certificate
	template := Certificate{
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		KeyUsage: KeyUsageCertSign | KeyUsageKeyEncipherment | KeyUsageDigitalSignature,
		IsCA:     true,
	}

	// Generate the traditional and post quantum keys
	deltaPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Error("Could not generate the RSA key")
	}
	_, basePrivKey, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Error("Could not generate the RSA key")
	}

	// Create a subordinate certificate
	chameleonDer, err := CreateChameleonCertificate(
		rand.Reader, &template, &template, deltaRootCert, baseRootCert, &deltaPrivKey.PublicKey, basePrivKey.Public(), deltaRootPrivKey, baseRootPrivKey)
	if err != nil {
		t.Error(err)
	}
	chameleonCert, err := ParseCertificate(chameleonDer)
	if err != nil {
		t.Error(err)
	}

	// Check that the newly created chameleon certificate is valid
	err = baseRootCert.CheckSignature(chameleonCert.SignatureAlgorithm, chameleonCert.RawTBSCertificate, chameleonCert.Signature)
	if err != nil {
		t.Error("Incorrect base signature")
	}

	// Reconstruct the delta certificate
	deltaCert, err := ReconstructDeltaCertificate(chameleonCert)
	if err != nil {
		t.Error(err)
	}

	// Verify the delta signature
	err = deltaRootCert.CheckSignature(deltaCert.SignatureAlgorithm, deltaCert.RawTBSCertificate, deltaCert.Signature)
	if err != nil {
		t.Error(err)
		t.Error("Incorrect delta signature")
	}
}

func TestDeltaCertificateExtensionContentWhenDeltaAndBaseParentTemplateIsTheSame(t *testing.T) {
	// Create a chameleon root certificate
	_, _, chameleonCert, err := createChameleonRoot()
	if err != nil {
		t.Error(err)
	}

	// Get the Raw Delta Extension
	var deltaExtension pkix.Extension
	for _, extension := range chameleonCert.Extensions {
		if extension.Id.Equal(deltaExtensionOid) {
			deltaExtension = extension
		}
	}

	// Check that the delta extension only has the Serial Number, Signature Algorithm,
	// Public Key Informtion and Signature Value fields.
	dcd, err := parseDeltaExtension(deltaExtension.Value)
	if err != nil {
		t.Error("Invalid delta extension")
	}

	if dcd.Issuer.Bytes != nil || dcd.Validity != (validity{}) || dcd.Subject.Bytes != nil {
		t.Error("DCD contains duplicate information")
	}

	// Check that it only contains the minimum
	for _, ext := range dcd.Extensions {
		if !ext.Id.Equal(oidExtensionSubjectKeyId) {
			t.Error("DCD contains unnecessary extensions")
		}
	}
}

func TestDeltaCertificateExtensionContentWhenDeltaAndBaseHaveDifferentExtensions(t *testing.T) {
	// Create a templates with some differing extensions
	deltaExtensions := []pkix.Extension{
		{
			Id:    oidExtensionSubjectKeyId,
			Value: []byte{0x01},
		},
		{
			Id:    oidExtensionAuthorityKeyId,
			Value: []byte{0x01},
		},
		{
			Id:    oidExtensionSubjectAltName,
			Value: []byte{0xde, 0xad, 0xbe, 0xef},
		},
	}
	deltaTemplate := Certificate{
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		KeyUsage:   KeyUsageCertSign | KeyUsageKeyEncipherment | KeyUsageDigitalSignature,
		IsCA:       true,
		Extensions: deltaExtensions,
	}

	baseExtensions := []pkix.Extension{
		{
			Id:    oidExtensionSubjectKeyId,
			Value: []byte{0x02},
		},
		{
			Id:    oidExtensionAuthorityKeyId,
			Value: []byte{0x02},
		},
		{
			Id:    oidExtensionSubjectAltName,
			Value: []byte{0xde, 0xad, 0xbe, 0xef},
		},
	}
	baseTemplate := Certificate{
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		KeyUsage:   KeyUsageCertSign | KeyUsageKeyEncipherment | KeyUsageDigitalSignature,
		IsCA:       true,
		Extensions: baseExtensions,
	}

	// Generate the traditional and post quantum keys
	tradPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Error("Could not generate the RSA key")
	}
	_, pqPrivKey, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Error("Could not generate the RSA key")
	}

	// Generate the chameleon certificate
	chameleonDer, err := CreateChameleonCertificate(
		rand.Reader, &deltaTemplate, &baseTemplate, &deltaTemplate, &baseTemplate, &tradPrivKey.PublicKey, pqPrivKey.Public(), tradPrivKey, pqPrivKey)
	if err != nil {
		t.Error(err)
	}

	// Return the parsed certificate
	chameleonCert, err := ParseCertificate(chameleonDer)
	if err != nil {
		t.Error(err)
	}

	// Get the Raw Delta Extension
	var deltaExtension pkix.Extension
	for _, extension := range chameleonCert.Extensions {
		if extension.Id.Equal(deltaExtensionOid) {
			deltaExtension = extension
		}
	}
	dcd, err := parseDeltaExtension(deltaExtension.Value)
	if err != nil {
		t.Error("Invalid delta extension")
	}

	// Check that the DCD extension only contains the different extensions
	for _, ext := range dcd.Extensions {
		if !ext.Id.Equal(oidExtensionSubjectKeyId) && !ext.Id.Equal(oidExtensionAuthorityKeyId) {
			t.Errorf("DCD contains unnecessary extension: %v", ext.Id)
		}
	}
}

func TestChameleonCertificateHonorsExtraExtensions(t *testing.T) {
	rawValues := []asn1.RawValue{}
	rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeDNS, Class: 2, Bytes: []byte("dev.lamassu.io")})
	value, _ := asn1.Marshal(rawValues)
	extensions := []pkix.Extension{
		{
			Id:    oidExtensionSubjectAltName, // Subject Alternative Name OID
			Value: value,
		},
	}

	// Generate the certificate
	_, _, chameleonCert, err := createChameleonRootWithExtensions(extensions)
	if err != nil {
		t.Error(err)
	}

	// Check that the chameleon certificate contains the Extra extension
	found := false
	for _, ext := range chameleonCert.Extensions {
		if ext.Id.String() == (asn1.ObjectIdentifier)(oidExtensionSubjectAltName).String() {
			found = true
		}
	}
	if !found {
		t.Error("Expected the chameleon certificate to have a SAN extension")
	}
}

// TODO -> modify when IANA assigns an official OIDs
func TestChameleonDeltaCSRAttributeOids(t *testing.T) {
	expectedOid := asn1.ObjectIdentifier{2, 16, 840, 1, 114027, 80, 6, 2}
	if !deltaCertificateRequestAttributeOid.Equal(expectedOid) {
		t.Errorf("Error: expected %s got %s", expectedOid, deltaCertificateRequestAttributeOid)
	}

	expectedOid = asn1.ObjectIdentifier{2, 16, 840, 1, 114027, 80, 6, 3}
	if !deltaCertificateRequestSignatureAttributeOid.Equal(expectedOid) {
		t.Errorf("Error: expected %s got %s", expectedOid, deltaCertificateRequestSignatureAttributeOid)
	}
}

func TestChameleonDeltaCSRAttributeSubjectPKInfo(t *testing.T) {
	testcases := []struct {
		name             string
		privKeyGenerator func() (crypto.Signer, error)
	}{
		{
			name: "RSA",
			privKeyGenerator: func() (crypto.Signer, error) {
				return rsa.GenerateKey(rand.Reader, 4096)
			},
		},
		{
			name: "MLDSA",
			privKeyGenerator: func() (crypto.Signer, error) {
				_, key, err := mldsa65.GenerateKey(rand.Reader)
				return key, err
			},
		},
	}

	for _, tc := range testcases {
		// Get the base key
		_, basePrivKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Error(err)
		}

		// Generate the delta key
		deltaPrivKey, _ := tc.privKeyGenerator()
		deltaPubKeyBytes, deltaPublicKeyAlgorithm, _ := marshalPublicKey(deltaPrivKey.Public())

		// Create a Delta CSR
		template := CertificateRequest{
			Subject: pkix.Name{CommonName: "Test CSR"},
		}

		csr, parsedAttribute, err := createChameleonCSRAndParseAttribute(&template, &template, deltaPrivKey, basePrivKey)
		if err != nil {
			t.Error(err)
		}

		// Verify the public key information of the base CSR corresponds to the base priv key
		if !reflect.DeepEqual(csr.PublicKey, basePrivKey.Public()) {
			t.Errorf("Error: the CSR contains an incorrect public key")
		}

		// Verify the extension contains the correct public key info
		if !parsedAttribute.PublicKeyInfo.Algorithm.Algorithm.Equal(deltaPublicKeyAlgorithm.Algorithm) || !bytes.Equal(parsedAttribute.PublicKeyInfo.PublicKey.Bytes, deltaPubKeyBytes) {
			t.Errorf("Error: the delta CSR attribute specifies an incorrect public key")
		}
	}
}

func TestChameleonDeltaCSRAttributeSubjectName(t *testing.T) {
	testcases := []struct {
		name         string
		baseSubject  pkix.Name
		deltaSubject pkix.Name
	}{
		{
			name:         "Same Subject",
			baseSubject:  pkix.Name{CommonName: "Subject A"},
			deltaSubject: pkix.Name{CommonName: "Subject A"},
		},
		{
			name:        "No Delta Subject",
			baseSubject: pkix.Name{CommonName: "Subject A"},
		},
		{
			name:         "Different Subject",
			baseSubject:  pkix.Name{CommonName: "Subject A"},
			deltaSubject: pkix.Name{CommonName: "Subject B"},
		},
		{
			name:         "Another Different Subject",
			baseSubject:  pkix.Name{CommonName: "Subject A"},
			deltaSubject: pkix.Name{CommonName: "Subject C"},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// Get the base and delta keys
			_, basePrivKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Error(err)
			}
			_, deltaPrivKey, _ := mldsa65.GenerateKey(rand.Reader)
			if err != nil {
				t.Error(err)
			}

			// Create the base and delta templates
			baseTemplate := CertificateRequest{
				Subject: tc.baseSubject,
			}

			deltaTemplate := CertificateRequest{}
			if tc.deltaSubject.String() != "" {
				deltaTemplate.Subject = tc.deltaSubject
			}

			// Generate the CSR and parse the delta extension
			csr, parsedAttribute, err := createChameleonCSRAndParseAttribute(&deltaTemplate, &baseTemplate, deltaPrivKey, basePrivKey)
			if err != nil {
				t.Error(err)
			}

			// Verify the base subject
			if csr.Subject.String() != tc.baseSubject.String() {
				t.Errorf("Error: expected base Subject %v, got %v", tc.baseSubject.String(), csr.Subject.String())
			}

			// Parse and verify the delta subject
			if tc.deltaSubject.String() != "" && tc.deltaSubject.String() != tc.baseSubject.String() {
				var csrDeltaSubject pkix.Name
				rdnSequence, err := parseName(parsedAttribute.Subject.Bytes)
				if err != nil {
					t.Errorf("Error: unexpected error when parsing the Delta Attribute Subject %v", err)
				}
				csrDeltaSubject.FillFromRDNSequence(rdnSequence)

				if csrDeltaSubject.String() != tc.deltaSubject.String() {
					t.Errorf("Error: expected the delta subject to be %v, got %v", tc.deltaSubject.String(), csrDeltaSubject.String())
				}
			} else if len(parsedAttribute.Subject.Bytes) > 0 {
				t.Error("Error: expected the delta subject to be empty")
			}
		})
	}
}

func TestChameleonDeltaCSRSignatureAttribute(t *testing.T) {
	testcases := []struct {
		name    string
		subject pkix.Name
	}{
		{
			name:    "Subject A",
			subject: pkix.Name{CommonName: "Subject A"},
		},
		{
			name:    "Subject B",
			subject: pkix.Name{CommonName: "Subject B"},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			_, basePrivKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Error(err)
			}
			deltaPubKey, deltaPrivKey, _ := mldsa65.GenerateKey(rand.Reader)
			if err != nil {
				t.Error(err)
			}

			template := CertificateRequest{
				Subject: tc.subject,
			}

			csr, signature, err := createChameleonCSRAndExtractSignature(&template, &template, deltaPrivKey, basePrivKey)
			if err != nil {
				t.Error(err)
			}

			// Remove the delta CSR signature attribute from the csr
			var index int
			found := false
			for i := 0; i < len(csr.Extensions) && !found; i++ {
				if csr.Extensions[i].Id.Equal(deltaCertificateRequestSignatureAttributeOid) {
					index = i
					found = true
				}
			}

			// Get the raw bytes for the cleaned CSR
			csr.Attributes = nil
			csr.ExtraExtensions = append(csr.Extensions[0:index], csr.Extensions[index+1:]...)
			if err != nil {
				t.Error(err)
			}
			innerCsrDer, err := CreateCertificateRequest(rand.Reader, csr, basePrivKey)
			if err != nil {
				t.Error(err)
			}
			innerCsr, err := ParseCertificateRequest(innerCsrDer)
			if err != nil {
				t.Error(err)
			}

			// Check the signature
			valid := mldsa65.Verify(deltaPubKey, innerCsr.RawTBSCertificateRequest, nil, signature)
			if !valid {
				t.Error("Error: invalid delta request signature attribute value")
			}
		})
	}
}

func TestChameleonDeltaCSRAttributeExtensions(t *testing.T) {
	testcases := []struct {
		name            string
		baseExtensions  []pkix.Extension
		deltaExtensions []pkix.Extension
	}{
		{
			name: "No extensions",
		},
		{
			name: "Same extensions",
			baseExtensions: []pkix.Extension{
				{
					Id:    oidExtensionSubjectKeyId,
					Value: []byte{0x01},
				},
			},
			deltaExtensions: []pkix.Extension{
				{
					Id:    oidExtensionSubjectKeyId,
					Value: []byte{0x01},
				},
			},
		},
		{
			name: "Different extensions",
			baseExtensions: []pkix.Extension{
				{
					Id:    oidExtensionSubjectKeyId,
					Value: []byte{0x01},
				},
			},
			deltaExtensions: []pkix.Extension{
				{
					Id:    oidExtensionSubjectKeyId,
					Value: []byte{0x02},
				},
			},
		},
		{
			name:           "Extra extension",
			baseExtensions: []pkix.Extension{},
			deltaExtensions: []pkix.Extension{
				{
					Id:    oidExtensionSubjectKeyId,
					Value: []byte{0x01},
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// Get the base and delta keys
			_, basePrivKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Error(err)
			}
			_, deltaPrivKey, _ := mldsa65.GenerateKey(rand.Reader)
			if err != nil {
				t.Error(err)
			}

			// Create the base and delta templates
			baseTemplate := CertificateRequest{
				Subject:         pkix.Name{CommonName: "Test CSR"},
				ExtraExtensions: tc.baseExtensions,
			}

			deltaTemplate := CertificateRequest{}
			if len(tc.deltaExtensions) > 0 {
				deltaTemplate.ExtraExtensions = tc.deltaExtensions
			}

			// Generate the CSR and parse the delta extension
			csr, parsedAttribute, err := createChameleonCSRAndParseAttribute(&deltaTemplate, &baseTemplate, deltaPrivKey, basePrivKey)
			if err != nil {
				t.Error(err)
			}

			// Verify the base Extensions
			baseExtIndexes := buildExtensionIndexMap(csr.Extensions)
			for _, ext := range baseTemplate.Extensions {
				index, ok := baseExtIndexes[ext.Id.String()]

				if !ok || !bytes.Equal(csr.Extensions[index].Value, ext.Value) {
					t.Error("Error: incorrect base CSR extensions")
				}
			}

			// Parse and verify the delta extensions
			if len(tc.deltaExtensions) > 0 {
				deltaExtIndexes := buildExtensionIndexMap(deltaTemplate.Extensions)
				for _, ext := range parsedAttribute.Extensions {
					baseIndex, extInBase := baseExtIndexes[ext.Id.String()]
					deltaIndex, ok := deltaExtIndexes[ext.Id.String()]

					if !extInBase || !ok || bytes.Equal(csr.Extensions[baseIndex].Value, ext.Value) || !bytes.Equal(deltaTemplate.Extensions[deltaIndex].Value, ext.Value) {
						t.Error("Error: incorrect delta CSR extensions")
					}
				}
			} else if len(parsedAttribute.Subject.Bytes) > 0 {
				t.Error("Error: expected the delta subject to be empty")
			}
		})
	}
}

func TestChameleonDeltaCSRAttributeSignatureAlgorithm(t *testing.T) {
	testcases := []struct {
		name     string
		deltaKey func() (crypto.Signer, error)
	}{
		{
			name: "RSA",
			deltaKey: func() (crypto.Signer, error) {
				return rsa.GenerateKey(rand.Reader, 4096)
			},
		},
		{
			name: "Ed25519",
			deltaKey: func() (crypto.Signer, error) {
				_, key, err := ed25519.GenerateKey(rand.Reader)
				return key, err
			},
		},
		{
			name: "MLDSA",
			deltaKey: func() (crypto.Signer, error) {
				_, key, err := mldsa65.GenerateKey(rand.Reader)
				return key, err
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// Get the base key
			_, baseKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Error(err)
			}
			deltaKey, err := tc.deltaKey()
			if err != nil {
				t.Error(err)
			}

			// Create the base and delta templates
			template := CertificateRequest{
				Subject: pkix.Name{CommonName: "Test CA"},
			}

			// Generate the CSR and parse the delta extension
			_, parsedAttribute, err := createChameleonCSRAndParseAttribute(&template, &template, deltaKey, baseKey)
			if err != nil {
				t.Error(err)
			}

			// Verify the Signature Algorithm parameter
			_, sigAlgo, err := signingParamsForKey(deltaKey, template.SignatureAlgorithm)
			if err != nil {
				t.Errorf("Error: unexpected error ocurred: %v", err)
			}

			if !parsedAttribute.SignatureAlgorithm.Algorithm.Equal(sigAlgo.Algorithm) {
				t.Errorf("Error: expected %v signature algorithm, got %v", parsedAttribute.SignatureAlgorithm.Algorithm, sigAlgo.Algorithm)
			}
		})
	}
}

func TestParseChameleonCertificateRequest(t *testing.T) {

	testcases := []struct {
		name              string
		deltaTemplate     *CertificateRequest
		baseTemplate      *CertificateRequest
		deltaKeyGenerator func() (crypto.Signer, error)
		baseKeyGenerator  func() (crypto.Signer, error)
	}{
		{
			name: "OK/RSA-MLDSA",
			deltaTemplate: &CertificateRequest{
				Subject: pkix.Name{CommonName: "Test Delta Subject"},
			},
			baseTemplate: &CertificateRequest{
				Subject: pkix.Name{CommonName: "Test Base Subject"},
			},
			deltaKeyGenerator: func() (crypto.Signer, error) {
				_, key, err := mldsa65.GenerateKey(rand.Reader)
				return key, err
			},
			baseKeyGenerator: func() (crypto.Signer, error) {
				return rsa.GenerateKey(rand.Reader, 4096)
			},
		},
	}

	checkOk := func(name string, subject string, publicKeyInfo []byte, extensions []pkix.Extension, signatureAlgorithm SignatureAlgorithm, csr *CertificateRequest) error {
		if subject != csr.Subject.String() {
			return fmt.Errorf("Error parsing %s: expected subject %v, got %v", name, subject, csr.Subject.String())
		}

		if !bytes.Equal(publicKeyInfo, csr.RawSubjectPublicKeyInfo) {
			return fmt.Errorf("Error parsing %s: incorrect subject public key info", name)
		}

		if !reflect.DeepEqual(extensions, csr.Extensions) {
			return fmt.Errorf("Error parsing %s: extensions don't match", name)
		}

		if signatureAlgorithm != csr.SignatureAlgorithm {
			return fmt.Errorf("Error parsing %s: expected %v signature algorithm, got %v", name, signatureAlgorithm, csr.SignatureAlgorithm)
		}

		return nil
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			deltaKey, err := tc.deltaKeyGenerator()
			if err != nil {
				t.Errorf("Error: unexpected error %v", err)
			}

			baseKey, err := tc.baseKeyGenerator()
			if err != nil {
				t.Errorf("Error: unexpected error %v", err)
			}

			csr, parsedAttribute, err := createChameleonCSRAndParseAttribute(tc.deltaTemplate, tc.baseTemplate, deltaKey, baseKey)
			if err != nil {
				t.Errorf("Error: unexpected error generating the Delta CSR %v", err)
			}

			deltaCsr, baseCsr, err := ParseChameleonCertificateRequest(csr.Raw)
			if err != nil {
				t.Errorf("Error: unexpected error occurred when parsing the Delta CSR %v", err)
			}

			err = checkOk("Delta CSR", tc.deltaTemplate.Subject.String(), parsedAttribute.PublicKeyInfo.Raw, parsedAttribute.Extensions, getSignatureAlgorithmFromAI(parsedAttribute.SignatureAlgorithm), deltaCsr)
			if err != nil {
				t.Error(err)
			}

			// The delta CSR should not contain the delta related extensions
			extensionMap := buildExtensionIndexMap(deltaCsr.Extensions)
			_, isPresent := extensionMap[deltaCertificateRequestAttributeOid.String()]
			if isPresent {
				t.Errorf("Error parsing Delta CSR: resulting CSR contains the Delta Attribute")
			}

			_, isPresent = extensionMap[deltaCertificateRequestSignatureAttributeOid.String()]
			if isPresent {
				t.Errorf("Error parsing Delta CSR: resulting CSR contains the Delta Attribute Signature")
			}


			err = checkOk("Base CSR", tc.baseTemplate.Subject.String(), csr.RawSubjectPublicKeyInfo, csr.Extensions, csr.SignatureAlgorithm, baseCsr)
			if err != nil {
				t.Error(err)
			}
		})
	}
}

func TestParseChameleonCertificateRequestWithExtraExtensions(t *testing.T) {
	deltaTemplate := CertificateRequest{
		Subject: pkix.Name{CommonName: "Test Delta Subject"},
	}
	baseTemplate := CertificateRequest{
		Subject: pkix.Name{CommonName: "Test Base Subject"},
	}
	_, deltaKey, err := mldsa65.GenerateKey(rand.Reader)
	baseKey, err := rsa.GenerateKey(rand.Reader, 4096)

	
	csr, parsedAttribute, err := createChameleonCSRAndParseAttribute(&deltaTemplate, &baseTemplate, deltaKey, baseKey)
	if err != nil {
		t.Error("Unexpected error occured when creating the Delta CSR")
	}

	parsedAttribute.Extensions = append(parsedAttribute.Extensions, pkix.Extension{
		Id: oidExtensionSubjectAltName,
		Value: []byte{0xde, 0xad, 0xbe, 0xef},
	})

	var index int
	for i, ext := range csr.Extensions {
		if ext.Id.Equal(deltaCertificateRequestAttributeOid) {
			index = i
		}
	}

	rawValue, err := asn1.Marshal(*parsedAttribute)
	if err != nil {
		fmt.Println(err)
		t.Error("Unexpected error occured when marshalling the modified attribute")
	}

	csr.Extensions[index] = pkix.Extension{
		Id: deltaCertificateRequestAttributeOid,
		Value: rawValue,
	}

	// Force the extension modification to take effect
	csr.ExtraExtensions = csr.Extensions
	csr.Extensions = nil
	csr.Attributes = nil

	// Rebuild the CSR (Note: the signature will change. However, it does not matter for this test)
	csr.Raw = nil
	csr.RawTBSCertificateRequest = nil
	rawCsr, err := CreateCertificateRequest(rand.Reader, csr, baseKey)
	if err != nil {
		t.Error("Unexpected error rebuilding the base CSR")
	}

	_, _, err = ParseChameleonCertificateRequest(rawCsr)
	if err == nil {
		t.Error("Error: an error should have been raised when parsing a Delta CSR Attribute with extra extensions")
	}
}

func TestCreateBoundRootCertificate(t *testing.T) {
	testcases := []struct {
		name                string
		privateKeyGenerator func() (crypto.Signer, error)
	}{
		{
			name: "SHA256-RSA/MLDSA",
			privateKeyGenerator: func() (crypto.Signer, error) {
				return rsa.GenerateKey(rand.Reader, 4096)
			},
		},
		{
			name: "SHA512-ECDSA/MLDSA",
			privateKeyGenerator: func() (crypto.Signer, error) {
				return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
			},
		},
		{
			name: "PureEd25519/MLDSA",
			privateKeyGenerator: func() (crypto.Signer, error) {
				_, privKey, err := ed25519.GenerateKey(rand.Reader)
				return privKey, err
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			relatedCert, pqCert, err := createBoundCertificatePair(tc.privateKeyGenerator)
			if err != nil {
				t.Error(err)
			}

			// Expect the bound certificate to contain the Related Certificate Extension
			parsedExtension, err := parseRelatedCertificateExtension(pqCert)
			if err != nil {
				t.Error(err)
			}

			// Expect the hash algorithm to be the one specified in the related certificate
			sigAlgo := getSignatureAlgorithmFromAI(parsedExtension.HashAlgorithm)
			if sigAlgo != relatedCert.SignatureAlgorithm {
				t.Errorf("Error: expected '%v' signature algorithm but got '%v'", relatedCert.SignatureAlgorithm, sigAlgo)
			}

			// Expect the hash value to correspond with the related certificate
			err = validateRelateCertificateHash(relatedCert, parsedExtension.HashAlgorithm.Algorithm, parsedExtension.HashValue)
			if err != nil {
				t.Error("Error: hash value not valid")
			}
		})
	}
}

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Helper functions                                                           //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

func createChameleonRoot() (crypto.Signer, crypto.Signer, *Certificate, error) {
	// Generate a root chameleon certificate
	template := Certificate{
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		KeyUsage: KeyUsageCertSign | KeyUsageKeyEncipherment | KeyUsageDigitalSignature,
		IsCA:     true,
	}
	return createChameleonCertificate(&template)
}

func createChameleonRootWithExtensions(extensions []pkix.Extension) (crypto.Signer, crypto.Signer, *Certificate, error) {
	// Generate a root chameleon certificate
	template := Certificate{
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		KeyUsage:        KeyUsageCertSign | KeyUsageKeyEncipherment | KeyUsageDigitalSignature,
		IsCA:            true,
		ExtraExtensions: extensions,
	}
	return createChameleonCertificate(&template)
}

func createChameleonCertificate(template *Certificate) (crypto.Signer, crypto.Signer, *Certificate, error) {
	// Generate the traditional and post quantum keys
	tradPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Could not generate the RSA key")
	}
	_, pqPrivKey, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Could not generate the RSA key")
	}

	// Generate the chameleon certificate
	chameleonDer, err := CreateChameleonCertificate(rand.Reader, template, template, template, template, &tradPrivKey.PublicKey, pqPrivKey.Public(), tradPrivKey, pqPrivKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// Return the parsed certificate
	chameleonCert, err := ParseCertificate(chameleonDer)
	return tradPrivKey, pqPrivKey, chameleonCert, err
}

func createBoundCertificatePair(privateKeyGenerator func() (crypto.Signer, error)) (*Certificate, *Certificate, error) {
	// Generate a new template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("Error generating the serial number")
	}
	template := Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		KeyUsage: KeyUsageCertSign | KeyUsageKeyEncipherment | KeyUsageDigitalSignature,
		IsCA:     true,
	}

	// Generate a traditional certificate
	tradPrivKey, err := privateKeyGenerator()
	if err != nil {
		return nil, nil, fmt.Errorf("Could not generate the RSA key")
	}
	relatedCertDer, err := CreateCertificate(rand.Reader, &template, &template, tradPrivKey.Public(), tradPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not generate the base certificate")
	}
	relatedCert, err := parseCertificate(relatedCertDer)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not parse the base certificate")
	}

	// Generate the Post-Quantum private key
	_, pqPrivKey, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not generate the RSA key")
	}

	// Create the bound certificate
	pqDerBytes, err := CreateBoundCertificate(rand.Reader, &template, &template, relatedCertDer, pqPrivKey.Public(), pqPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Error generating the Bound Certificate: %v", err)
	}
	pqCert, err := ParseCertificate(pqDerBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Error parsing the Bound Certificate: %v", err)
	}

	return relatedCert, pqCert, nil
}

func validateRelateCertificateHash(relatedCert *Certificate, sigAlgo asn1.ObjectIdentifier, hashValue []byte) error {
	var hashAlgo hash.Hash
	switch sigAlgo.String() {
	case oidSignatureSHA1WithRSA.String(), oidSignatureDSAWithSHA1.String(), oidSignatureECDSAWithSHA1.String():
		hashAlgo = sha1.New()
	case oidSignatureSHA256WithRSA.String(), oidSignatureDSAWithSHA256.String(), oidSignatureECDSAWithSHA256.String():
		hashAlgo = sha256.New()
	case oidSignatureSHA384WithRSA.String(), oidSignatureECDSAWithSHA384.String():
		hashAlgo = sha512.New384()
	case oidSignatureSHA512WithRSA.String(), oidSignatureECDSAWithSHA512.String():
		hashAlgo = sha512.New()
	default:
		hashAlgo = sha256.New()
	}

	_, err := hashAlgo.Write(relatedCert.Raw)
	if err != nil {
		return err
	}
	hash := hashAlgo.Sum(nil)

	valid := bytes.Equal(hash[:], hashValue)
	if !valid {
		return fmt.Errorf("Error: hash value not valid")
	}

	return nil
}

func parseRelatedCertificateExtension(certificate *Certificate) (*relatedCertificateExtension, error) {
	// Expect the bound certificate to contain the Related Certificate Extension
	present := false
	var relatedCertExtension pkix.Extension
	for _, ext := range certificate.Extensions {
		if ext.Id.Equal(relatedCertificateExtensionOid) {
			present = true
			relatedCertExtension = ext
		}
	}
	if !present {
		return nil, fmt.Errorf("Error: the bound Post-Quantum certificate does not contain the related certificate extension")
	}

	// Parse the extension
	var parsedExtension relatedCertificateExtension
	_, err := asn1.Unmarshal(relatedCertExtension.Value, &parsedExtension)

	if err != nil {
		return nil, fmt.Errorf("Error: could not parse the RelatedCertificate extension")
	}

	return &parsedExtension, nil
}

func createChameleonCSRAndParseAttribute(deltaTemplate, baseTemplate *CertificateRequest, deltaPrivKey, basePrivKey any) (*CertificateRequest, *deltaCertificateRequestAttribute, error) {
	csrBytes, err := CreateChameleonCertificateRequest(rand.Reader, deltaTemplate, baseTemplate, deltaPrivKey, basePrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Error: unexpected error when creating the Delta CSR %v", err)
	}

	// Parse the CSR
	csr, err := ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Error: unexpected error when parsing the Delta CSR %v", err)
	}

	// Recover the DeltaCertificateRequest attribute
	var deltaCsrAttribute pkix.Extension
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(deltaCertificateRequestAttributeOid) {
			deltaCsrAttribute = ext
		}
	}
	if deltaCsrAttribute.Value == nil {
		return nil, nil, fmt.Errorf("Error: the CSR does not contain a Delta CSR attribute")
	}

	// Parse the extension
	parsedAttribute, err := parseDeltaCertificateRequestAttribute(deltaCsrAttribute.Value)
	if err != nil {
		return nil, nil, fmt.Errorf("Error: unexpected error when parsing the delta CSR attribute: %v", err)
	}

	return csr, parsedAttribute, nil
}

func createChameleonCSRAndExtractSignature(deltaTemplate, baseTemplate *CertificateRequest, deltaPrivKey, basePrivKey any) (*CertificateRequest, []byte, error) {
	csrBytes, err := CreateChameleonCertificateRequest(rand.Reader, deltaTemplate, baseTemplate, deltaPrivKey, basePrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Error: unexpected error when creating the Delta CSR %v", err)
	}

	// Parse the CSR
	csr, err := ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Error: unexpected error when parsing the Delta CSR %v", err)
	}

	// Recover the Delta Signature Attribute
	var deltaSignatureAttribute pkix.Extension
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(deltaCertificateRequestSignatureAttributeOid) {
			deltaSignatureAttribute = ext
		}
	}
	if deltaSignatureAttribute.Value == nil {
		return nil, nil, fmt.Errorf("Error: the CSR does not contain a Delta Signature attribute")
	}

	var signature asn1.BitString
	_, err = asn1.Unmarshal(deltaSignatureAttribute.Value, &signature)
	if err != nil {
		return nil, nil, err
	}

	return csr, signature.RightAlign(), nil
}

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Test data                                                                 //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

const MLDSA_BASE_ECDSA_P521_DELTA = `
-----BEGIN CERTIFICATE-----
MIIZCDCCDAWgAwIBAgIUFWd6hCxGhDNL+S1OL3UY7w+psbQwCwYJYIZIAWUDBAMS
MIGMMQswCQYDVQQGEwJYWDE1MDMGA1UECgwsUm95YWwgSW5zdGl0dXRlIG9mIFB1
YmxpYyBLZXkgSW5mcmFzdHJ1Y3R1cmUxKzApBgNVBAsMIlBvc3QtSGVmZmFsdW1w
IFJlc2VhcmNoIERlcGFydG1lbnQxGTAXBgNVBAMMEE1MLURTQSBSb290IC0gRzEw
HhcNMjQxMDE3MjMzNzIzWhcNMzQxMDE1MjMzNzIzWjAvMQswCQYDVQQGEwJYWDEP
MA0GA1UECgwGSGFuYWtvMQ8wDQYDVQQLDAZZYW1hZGEwggeyMAsGCWCGSAFlAwQD
EgOCB6EA/a6iHTzCfanvaHi8GU+U+oX5nDkvkSj/c/eGnGt0f70YDjvXoNmwXSxI
pFHz7mLnmJ09lEI2O1OGLgUFjAYdubQRMlvjj0OzZjD4gJhs/c6G8B2loKtd6aOW
t4KPPVpmmvXaOFwFeU3NVq+JYZh8Uk7dCQ6PNC6FqIirE+5X8EqoG1SvOe8jYDt+
KVu7Q9VKSNMEwZYoa9lE/JDlQ+CTr3LsC4XbpHGFzxlbXBz2hPv9Rq+K5JGKZ8Xe
WiEvJ0gwU9BuEJ1zwA/mKO/gmYcxFwVT24aaoW4nDwZ4eyUmDxdH6y1PK7Anwbbm
Izis+50FisFbSCv+FCg+M4Bwa+VFLcnG2RB31dwR6Qx7WOyMhYEXycQIPwD1GRLO
zJopFVAoeWFIUec28gSLPG/a6WtZthVf3AwNlEU9q5GVMyNXi4wikwr3oMW0JHea
Muv1dN+QEHPKFUP/pVdrux+39EdUP2Ydh0m4xB4cPTYD3b0PEtNvlwWvprP1S6yE
GbbFNCqXKoPiGLeTgEiKIzDr9b0DxFMQhjzHBEKxnTbpFpYTuFuUApUAnmm6DzUj
o1V1RdsIqG5B1ZEGaJxHkBZle7Xr6ALw9Pr8ypmaUNnjq9E4ZxoqBWhuWQLsomB3
gLXrXcTTZGo/Yr603KZacjL0fitoplczRu91crEqLV4d7s1jNZKKRC+0p2cYDcIn
ktjgf8ypkgElWo+GdgoMmUdqtzpORIbq3pWV3AJfL9PU8tB6KTCN86Rxb/syTG7Y
53TLW67qyY6xY/BGvdxtdjw7zNkkOhO6AUywFn8xi5+B9S3n11ICSXrn6Rpu+Qgt
z1GKl53ltc97Gv19eFn48u7uPwkqtHVyvRqCzEMBygZKcy2Weaij3gsXW+JWYxtP
zJgrn9fA3zGia9CWPe/+W0xGuIm0nXf4H85rrJ8Iwgh7lwlQeoWaXFIzxtj5YSks
ksZGy0YcW1QfmUGpeu5j6qLBuLfNyKgNpRxMbqC50UQh0hSJkOr9mwEPEL7A0LJG
SlRnqNo7gCmhxTRKyaNR3luLZbIJfj4j3ltlPCDCRBrIFXkTbAiE8tfillgWqnCK
phdQHtzLRvFPaFpCDMhXuAyjLXW/6JhERClap5dJFjYVH0YWvWffcRPChusVSSLh
lTGxD5QYe8S0EkECJ1ajlUCyRf1kOPejJSh/gsW0DLvYW3vIypDJhnDcD40CPqqz
B5YduFeFGkYLnJs6LA1JyosJGkblcUA5O+eqz7AIdK02GPLL5eDAeQ/HCXgIa8AN
nXa3eErpAv7V6TCIdUpUdAMzTSf1E5x30uas4PBbF85MZWTP5xH2eGHmaNvi2UQd
Zg3FVfWa4hv99IIlBPqDykd60RHKrWSXwB16R0zzzLy8vcIDPMrC9M2rOGkJF2w1
KZ6u86/PGUVvwESxz+7jpxkMFdsgQ79ffhJYxjJNBY0EEe9C3vz4+vIDm0PW7YhR
BZ11pWYH+4v8WzhT1HmGIfq6QQYh9Pz9uHsNc9Pl5kTQu1jTgdSeqFbshUNWuvGo
LeGhoIC6fn5cYKJhKEslFl4fcJr5eQfVzwhXncZkloHgrrFYprv35Odqo/2AAPu6
+ILsegIY+D809nrQWBsZLNs7gopYi68xHc/yA6vOFGu7hLk/6qeV8ZNr89aGQU3Q
WBLmFRCZ+c4325uNmr2uhZntOK2ELVDosHkMkxynQPKDXheUGhU2lP/3bT+aGsug
l+0eXYYrxR3qnc5fM8u9ntJUGDTV9z/CzcBovHdMJfR16gbs4Qi5tsrwp1Teu8cI
SKh1zgdlxXKk/F7D0q3xiMcS8RC4fp3wstOVzgaQNrJEgAcN3tNsblu1JYKoSwoe
Rg94FAvULY8PLlkntNvjWAqAQXr1UW/diWX20wSUG9qFCmyo/TFpUbXIUER1kwi4
j/Ll5tLfziGWWsnAehE8heeZSkeKwa63ZBjUAZzQ2Ycohd3I+yzf3sbL6q4v4qtT
tpRSJh4f25YJEg4DPYCUxpS1ZQyhZ7yG77ylKgw2+pA1Kv3wArO/3pWff+NZoP9O
LKDrOmNY2ythYRxjfvwerjAl93vcnqm/t84XY1PNWk4uvf5M3ZqBF4skeMAtTdsD
y1ROQuAMBvnuXdg58cBDe6RSInoJyn8sZYILyveHt9bK4E9O3icOfCMaCweeJ30x
SDOrW9bdB7jA3WHqzSrg1NqJJGUwCQTYdmbACzOsiDaduUZAB4BaD666bzcSUjHf
QEN5/930H4wFNyRBAcrjlyJ0s3SCDG+8RX0EVN8QFt+A+0VFPpkTeIqsOzHaSwjs
WhALemYVCFpuqCc9ILDh7LmGNPkAUFpVjCGOWiNTxP1jhiQWp/gR7fF3Y/8tpFF0
/Le6X7p4VysXETscgXtopK/eT4eRo08wI2bkR7V8E9eiV+djFJw9uiHxmYH2HN2X
xVNWRGnpZRUiHzHIm0mQwmaamkaz+v8D8zNa2EC8PNcE1UAjqiKEcxOm3pBcFozT
BnDx5gJ0zcOP29+DZWKDNNHwr+ldHK51ttXeBn44LVC7CsG8CcN+/hMK0oGs7ivE
eC4YVfpeimX5k4ZfG0BfQAEVSUkgQL5d0VyW3Ceiunzc4wbYHTOjggNDMIIDPzAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUmwe0pHXE
vJFdNeDJocFi4ndV1j8wHwYDVR0jBBgwFoAUmwe0pHXEvJFdNeDJocFi4ndV1j8w
ggLaBgpghkgBhvprUAYBBIICyjCCAsYCFAwkDuI+vCXkurYIEro2dlv/uUTAoAww
CgYIKoZIzj0EAwShgY4wgYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJ
bnN0aXR1dGUgb2YgUHVibGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwi
UG9zdC1IZWZmYWx1bXAgUmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UEAwwPRUNE
U0EgUm9vdCAtIEcxo4GOMIGLMQswCQYDVQQGEwJYWDE1MDMGA1UECgwsUm95YWwg
SW5zdGl0dXRlIG9mIFB1YmxpYyBLZXkgSW5mcmFzdHJ1Y3R1cmUxKzApBgNVBAsM
IlBvc3QtSGVmZmFsdW1wIFJlc2VhcmNoIERlcGFydG1lbnQxGDAWBgNVBAMMD0VD
RFNBIFJvb3QgLSBHMTCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEAQBWBqe/Q4Q1
JyfnroW1iKkTDwv2CcjHF6ecRBfenEI4tqznJL3KkJIahCtrqV3Ei2nJSJEtekRB
WYE9Kt7ztptcAIV8Xinj7DC9hIgjECBAK17BMAgxrvqncZjdpR1EDboorK5IoEXV
yCx2gF3X07QL6aKbAHIZ5vr1GxzWr3MVUYytpFIwUDAOBgNVHQ8BAf8EBAMCAQYw
HQYDVR0OBBYEFOuj0ItR/hLczCFmh4UPmMdnc4g0MB8GA1UdIwQYMBaAFOuj0ItR
/hLczCFmh4UPmMdnc4g0A4GLADCBhwJBSedLEjpfk08YZ62kFSQSHccgNOtbbh0+
3HvjCZYA3Ct6OxtLRK9uKmdAk9BeNO/xpcOUMAyI8odp2jmoIlcy9TcCQgCYNtGZ
6+1o1RDSTp73sJZzy1M8TuBejmKoUPQ1T2/bQdXfPu+gRTx9gPrkDUDLdVDvqcLx
bxPhPVp+9EIuK3rCjTALBglghkgBZQMEAxIDggzuAKKWJqZR+Ce+zJlGjCzLJWmx
/c3mxMug0vo1NtheVQ4Id3Lnhv5yimxnGXCdtkCcRyQGef6ku2gpf6AeSTBaA9sa
C3d8sB1HLTlPnwBXTWJ0xgp0kGVqCfwrbeRdCsoFrRoz1V2ETBecFehgQFHYLWtO
Q/VZrXPpwUxjIJRpSdxIw3SCsADjT/cQI9CQl5riMFOsZedRRPxSpw6lAGo557Ul
IgsxXA90mZQvRONY3mh8YkDT5uxQV0xRlyLLcZ3dxkzKgZrndz9F1yPrDGA0ixdk
F+3u4mxt8BJYZyRA2UeLEPG0OAIORmCeNuuixnFytGkctTd83GHeAszUtSanOyIU
JSomB/9G/omW3TU8uI8zWFuW+Fac8kpcNIECMujWUpB4RlxTWC/eTqrSiH7leE41
aCaZC8Hd1jwTEK2xvPC8KCI/apk71rnmX4KFOCgG8FirIw/Usv6mnqt2G65nNlde
7gWS8XoMFJDtYWDUpkgwRwLHvBNvKK/WikRDG3pSI8E1UyU1MU5R1JQnQRgzjazR
5lWhsMLrYoC+wi+XKNkFjeKVbgoiVoAD3ZKGnkJvIEueilGEWTYoTiobKBHzDjI3
b9x0GuBU0Z/MiRsycsDJUrl8hK8kpgBAS7ENTaowGdE9KhiqzY4xX83vgjy0bDL4
X9+2CXuQtFR5QotYapjA1HJUM5UuB5ix7i32dbZfnrJOZqcgocWuFRkShsAAu/wH
wFeeiJodlAlFVh3onDgh76316MewB/VLpM3G4EctzI9i5xqJzKXjlKWXP9ZjW/Sd
50R42fe6AaUqN4DaNbwOQaBs48auupU+EK6NytQl9rCeCJ4gicnM1no4QQbcwecZ
VvrrCs8egd3hawzMuCRhKeNzaYVeqnWhsRWdLxJANa07ANQqgXLhSx7vDBLiIQLA
UNqNYndYjEG3jirFxITUtHcz4ekZC7hpGkbl5qabQvrlk6lJ7yfuNuoO5jcCKY/C
BbOluVgjOeYeBfqJ9u9MwMcTUs26DkpW9h5YXIXATBj9dI3Tzp6fb9qtg9zBTHap
JKwmbUbgbPJSabtFMwh5XUpIpsJ+Mujek4uQ2GNaA6YfitHeDP91DM9ZUVFM7/5/
0BysQZLfD3SDO2Q/TnCug4XlCy0Z8ChnCBRGldqU1cMKPszXviLauBoM6aiLx7Lf
feuMxZVWJ1xC3crrP4OXpEO7IkIsDeKoVBBdkhV9RuD394h7jSCljMEVCYKCRUWV
mvffcmJNxfIfTgeLboHiAu0vDjE6s9vrcUASTDTgXuooy3rQ4q4fkWvV+cLPCZH9
sRZQvGcziMWrubTPa3WuVG9FHmejYcTsRTIxl1IlU8IjgW5hzwdmiZKI9cnCPqxy
a+uSk7K/by9rG4msxklsijdQ8CRg3V4mgNW5FTa6hXpfabmYWEZetYzJ7CISueCH
RtevtYz5HTARC5KB2CcYMV3Cz1AaIxd29lZpWJFd8sWLN50P/1KBanqeFfqXgIuW
RVE26I1IyMrrxzPUN6F+C7AWEEFGI5rue3M2EdIAAP3Sv6paLut9cESLS8zQBz8J
nL+RXsvL3ctYW5XbcuDIFJaIAENJArveEI4u4Oyvxyz0bp5JmS8tpRTWUoRWBt9B
hAp4axTi2eUWn6XHCBTG5DIyi4i+Tz8yt+zkBLdCh/b/UgxVtH6O5jcrOc9j0kb7
IJGacW71sE/sM0xCLFvqo2pEaKrt2dF+3/sK9TsT8TCisrEC4iCeSWt/I6Jb1RIc
TjBIt+yP/0u+B/pZVs9sUQpNkgkUmxAgJsuhH9PkIV+26vijDppKSgod4CrlCrkE
gvUe55DhUTx7bi2TNNUwQNRY8KeGsJMEOap6TIV0MdEnvRqpnVpWlYWSIpC4lJFH
uEPkkfumLKphH+ZrComFg/8Ys0ApNiGpAIIDngUkOvUggT51vyk5EnzJs7n6XQoI
cnJ+nax/+bLC9UHo6llqmggUXOUnRupclyJUo99uafwyoCw/8y43OI4s7CffQZ9U
JJLOT5WvoFXLqZlLl99CmQRZ/+0CEObOxsf5zmt2YbKKLVh1xZCyOyglODG5fU1O
a+droWi/K/Y8EN2TFYC9278AC9TVFhY7QoMhn1eG3Lc5cNfL5G5aPcbIybJUJ1XT
17wHKrExmRG8/itNHB7Yh4uetwumgls+vWL/QpCepU3kTMc4yXMnuYkmqmA4vW/B
vy4CCSarPjUCoF7hyfPSEv2fI1iTleJl5lDNsII8uz2zW2kNGK9RVKNPkMAW5EqR
nVGdt6TzpNlRtBo8ZZbV6g00+ZRKrW0iXfYRv6jT0+02/BjCA4sr+KwwTS70oU0s
MIsgfLFRWUP2swV3oUsGrxL+r8OckzqTmRzMMk0MCiIm6Tg2DSBhiMF9Sn8cajIW
PVpBZoPlmPz3S0LqMH4KFRHqx8HIcRUKdRSItOn7h7kZEl4dkrY6HehbZd/s0h4Z
EIUotKN/Ls8NbS+NqxvKkiu/udt+tGjWzlauHR1I8b4uyJMoE1A+pJS5A5AdXPsr
q0Nj3cHhvZCSdbsFH4pWd7m90EWc4e54EX6NHnFUlvypjmQ5rXAIdNn3uMQ9hD9F
BQjDa9p5KI8bTvQBojS1fuOKR2wTqjCFVAjnnTgQ1xvDtIdBDPpfFwB/fIvh2wRi
tnu/9bs4suGX7yXWIAg+KopJUL5AjF8QUyOPzDVAVHQk+rRjg2rcb4b72dR56o8F
Y8GvdTAJGKApxFFKXk+YRYXUBczoaV6XG3J4+pieHv10P/wNrua2nKotTNgQ3X3e
Lg8BYMejeUAFyaLSn/taMsCwDAQfEIExx8wCB3ySp7oa0l70V2IjXReTijM8M2Yf
osYQ6KX01GyP01BGPiLj4Z2CeAr7y7QH5qkWBIQNOPEOMpC/3lKfWgF0GUrW1qzD
lxRSRcqYrmvWpT3tZYftGt1WqpFHi6N4R09KaLrEEgF57CYfKrQJisBKehm63v5A
2Pbc9mRsbCz1KSP0dtKSaXhaMBSbs/AflAOEniA45ZozFQHIp2VIgvYVxe0kV+i4
0UOGBb4eckx8jfXr9zG1MyLCmc3tBEDZIIicJSaqGA4lRpKQoGbHOxGEEgvWi46e
pRUpsCh7xP9k4bwrAGiFUOsq+NneS0DL5/iosSwjVlrF1CKjpG6zvTNgtSgQ0WL0
5/1f/gH9KJDyzVukKsl8xfK/EQw7q9zNxlw3DdqX0Gh74+AwLpUCMIen4+XgKxTD
9qLphL/gsWtncpaK2buRmQii2++Px8+8XbrReAENjLfuEH4m1Pnqo/tVtGpt2JOv
KrtM7Abj9ZRcxVthhy+K6cZwC9qcFSeuswcU81bqpJ4pmEcgCbd+DnqMBBMJsJHs
wKrhY4VaOpKt15lWQzqaHV2+S9uVmhS48aIUw4GWhfuwWLVwTACEtUvqPR8eK1n/
MLP0tmLlc2igdIQ0+Rj+27GJOm4sWx58kEnOlO1E5AlaMmoclJuVtwn7LSjdLY6/
HVBYST10of4OwXTk6reKpZnfzwI4Jb1Ml6MKyujGrBHfFpF0ezY8gGnhUif+GeCa
A5qySvwYq7dHpbhBsWFZXf5coK5xCUX7MblWY1kzDXqKr0dTiSHL0AxKD5DORpal
poSnF1auJcqwyoPDvtJxG/k2pWZD6206v6o/Ed2VItKgzeRQBznFCLhAbKSZKSjQ
VDT8HpX1xoakWvXrmE5g0/2UVQu39MuHkoXV3MwG45N/03fyUsR+MAAvyjfOqlmb
8UFQYGdAeA/P5+60DRCtC/v/9jlWj+uDDbyUD5rYlO9kLKlxmKgdH2LHerJ63Y4a
0P4PvBNYiPevrvN9WO5f0Z5N/fMwz88gm8Q2TVt3kJqHPj9SFI1e/KVOCZQlNTLh
ewnrNZZAjP9yQGbxnIgeiftnSmBM/30VxCgDv1+hE1FeG2jm4URgsiIu53rX6Ac7
HUl48/QWIXHMUQxSWXeXxGKI+SaVFRrM+5DCjWxW4bM190Joj21R7dBRfCbmdLrI
y6uhLJqKtZ+imkZnGpd33lWBJp9wuOVSEJWiS2Jwj4sgdrywD1mSPkyG2oXZOLUL
A3e8SFVGQaI7aFwG7wiRibgnuLz1omU/n46f02Gjj/0kSkqlhWIT7rqKkRYimMhE
6PTVRRLDmFK6OhK2WSCDIXGkQxv/pD5TOL0bjchj/FF9sQhDhG7W8IPOLMrtRsmK
PHfQ4l6+SUMo+tVNfo87m6uQismTwSu6nt4X+CNFvb5bY9Apltg5HAkTInJ41ed+
Shu2siOaLEbfQ3rjeeyTwuCnn8NPOe3VBLfhEvznBR+wCQA7W6/UiUoJCZgZwQkP
pGbnhaBP+YJF9ypE/mS0RGhti6UGKS9QWXaH9h4hVlt3krr4IiVYgpGetb/vCA5d
fYAjMD9K/AAAAAAAAAAAAAAAAAAAAAUNFR4jKA==
-----END CERTIFICATE-----`
