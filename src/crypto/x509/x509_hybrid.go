package x509

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"hash"
	"io"
	"math/big"
	"fmt"
)

// Current proposed OID for the delta extension in a "Chameleon" certificate, as defined
// in the version 6 of the draft (draft-bonnell-lamps-chameleon-certs-06)
// TODO -> Revise and modify value if the Draft is approved and IANA assigns an OID for
//
//	the extension.
var deltaExtensionOid = asn1.ObjectIdentifier{2, 16, 840, 1, 114027, 80, 6, 1}

// OID for the RelatedCertificate Extension as per RFC-9763
var relatedCertificateExtensionOid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1}

// OIDs for the Delta CSR
var deltaCertificateRequestAttributeOid = asn1.ObjectIdentifier{2, 16, 840, 1, 114027, 80, 6, 2}
var deltaCertificateRequestSignatureAttributeOid = asn1.ObjectIdentifier{2, 16, 840, 1, 114027, 80, 6, 3}

type deltaCertificateDescriptor struct {
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:0"`
	Issuer             asn1.RawValue            `asn1:"optional,explicit,tag:1"`
	Validity           validity                 `asn1:"optional,explicit,tag:2"`
	Subject            asn1.RawValue            `asn1:"optional,explicit,tag:3"`
	PublicKey          publicKeyInfo
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:4"`
	SignatureValue     asn1.BitString
}

type relatedCertificateExtension struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashValue     []byte
}

type deltaCertificateRequestAttribute struct {
	Subject            asn1.RawValue `asn1:"optional,explicit,tag:0"`
	PublicKeyInfo      publicKeyInfo
	Extensions         []pkix.Extension         `asn1:"optional,explicit,tag:1"`
	SignatureAlgorithm pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:2"`
}

// CreateChameleonCertificate creates a new x509 chameleon certificate as per
// `draft-bonnell-lamps-chameleon-certs-06`.
func CreateChameleonCertificate(randSource io.Reader, deltaTemplate, baseTemplate, deltaParent, baseParent *Certificate, deltaPubKey, basePubKey, deltaPrivKey, basePrivKey any) ([]byte, error) {
	// Generate a secure serial number for the delta certificate
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	deltaSerialNumber, err := rand.Int(randSource, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("x509: could not generate delta certificate serial number")
	}
	deltaTemplate.SerialNumber = deltaSerialNumber

	// Generate the delta certificate
	deltaDer, err := CreateCertificate(randSource, deltaTemplate, deltaParent, deltaPubKey, deltaPrivKey)
	if err != nil {
		return nil, err
	}
	deltaCert, err := ParseCertificate(deltaDer)
	if err != nil {
		return nil, err
	}

	// Get the raw values for the necessary fields
	_, signatureAlgorithm, _ := signingParamsForPublicKey(deltaPubKey, deltaTemplate.SignatureAlgorithm)
	pubKeyBytes, pubKeyAlgorithm, _ := marshalPublicKey(deltaPubKey)

	// Add the delta extension to the template
	deltaExt := deltaCertificateDescriptor{}
	deltaExt.SerialNumber = deltaCert.SerialNumber
	deltaExt.SignatureAlgorithm = signatureAlgorithm

	// Omit issuer if it is the same as the base certificate's issuer
	if deltaParent.Subject.String() != baseParent.Subject.String() {
		deltaExt.Issuer = asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        1,
			IsCompound: true,
			Bytes:      deltaCert.RawIssuer,
		}
	}

	// Omit validity if is the same as the base certificate's validity
	if deltaTemplate.NotBefore != baseTemplate.NotBefore || deltaTemplate.NotAfter != baseTemplate.NotAfter {
		deltaExt.Validity = validity{
			NotBefore: deltaCert.NotBefore,
			NotAfter:  deltaCert.NotAfter,
		}
	}

	// Omit subject if is the same as the base certificate's subject
	if deltaTemplate.Subject.String() != baseTemplate.Subject.String() {
		deltaExt.Subject = asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        3,
			IsCompound: true,
			Bytes:      deltaCert.RawSubject,
		}
	}

	deltaExt.PublicKey = publicKeyInfo{
		Raw:       nil,
		Algorithm: pubKeyAlgorithm,
		PublicKey: asn1.BitString{
			Bytes:     pubKeyBytes,
			BitLength: len(pubKeyBytes) * 8,
		},
	}

	// For efficiency's sake, convert the base template extensions into a map to avoid O(n*m)
	// complexity in the for loop
	baseExtensionIndexes := buildExtensionIndexMap(baseTemplate.Extensions)

	// Copy the necessary extensions and avoid duplication as per the draft's indications
	// 	- Subject Key Identifier MUST be copied
	//  - Extensions with different value must be copied
	for _, ext := range deltaCert.Extensions {
		baseExtIndex, ok := baseExtensionIndexes[ext.Id.String()]
		appendExtension := ext.Id.Equal(oidExtensionSubjectKeyId) || ok && !bytes.Equal(ext.Value, baseTemplate.Extensions[baseExtIndex].Value)

		if appendExtension {
			deltaExt.Extensions = append(deltaExt.Extensions, ext)
		}
	}

	deltaExt.SignatureValue = asn1.BitString{
		Bytes:     deltaCert.Signature,
		BitLength: len(deltaCert.Signature) * 8,
	}

	// Encode the delta certificate descriptor extension
	rawDeltaExt, err := asn1.MarshalWithParams(deltaExt, `asn1:"optional"`)
	if err != nil {
		return nil, err
	}

	baseTemplate.ExtraExtensions = append(baseTemplate.ExtraExtensions, pkix.Extension{
		Id:    deltaExtensionOid,
		Value: rawDeltaExt,
	})

	// Change the serial number to generate the base/outer certificate
	baseSerialNumber, err := rand.Int(randSource, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("x509: could not generate base certificate serial number")
	}
	baseTemplate.SerialNumber = baseSerialNumber

	// Generate the base/outer certificate
	return CreateCertificate(randSource, baseTemplate, baseParent, basePubKey, basePrivKey)
}

func ReconstructDeltaCertificate(base *Certificate) (*Certificate, error) {
	// Build a map with all base certificate extensions and their index
	baseExtensions := buildExtensionIndexMap(base.Extensions)

	// Check if the base certificate contains a DCD extension
	dcdIndex, ok := baseExtensions[deltaExtensionOid.String()]
	if !ok {
		return nil, fmt.Errorf("Error: the certificate does not contain a Delta Certificate Descriptor extension")
	}

	// Parse the Delta Certificate Descriptor extension
	dcd, err := parseDeltaExtension(base.Extensions[dcdIndex].Value)
	if err != nil {
		//return nil, fmt.Errorf("Error parsing the Delta Certificate Descriptor")
		return nil, err
	}

	// 1. Clone the base certificate and remove the DCD extension
	// In order to do this, the base certificate is encoded and decoded to create
	// a new object.
	deltaCert, err := ParseCertificate(base.Raw)
	if err != nil {
		return nil, err
	}
	deltaCert.Extensions = append(deltaCert.Extensions[:dcdIndex], deltaCert.Extensions[dcdIndex+1:]...)

	// 2. Replace the Serial Number
	deltaCert.SerialNumber = dcd.SerialNumber

	// 3. Replace the Signature Algorithm (if required)
	// TODO -> Make this optional, as per Page 9 of the draft
	deltaCert.SignatureAlgorithm = getSignatureAlgorithmFromAI(dcd.SignatureAlgorithm)

	// 4. Replace the Issuer field (if required)
	if len(dcd.Issuer.Bytes) > 0 {
		deltaCert.RawIssuer = dcd.Subject.Bytes
		issuerRDNs, err := parseName(dcd.Issuer.Bytes)
		deltaCert.Issuer.FillFromRDNSequence(issuerRDNs)

		if err != nil {
			return nil, err
		}
	}

	// 6. Replace the Subject Public Key information
	deltaCert.RawSubjectPublicKeyInfo = dcd.PublicKey.Raw
	deltaCert.PublicKeyAlgorithm = getPublicKeyAlgorithmFromOID(dcd.PublicKey.Algorithm.Algorithm)
	deltaCert.PublicKey, err = parsePublicKey(&dcd.PublicKey)
	if err != nil {
		return nil, err
	}

	// 7. Replace the subject field (if required)
	if len(dcd.Subject.Bytes) > 0 {
		deltaCert.RawSubject = dcd.Subject.Bytes
		subjectRDNs, err := parseName(dcd.Subject.Bytes)
		deltaCert.Subject.FillFromRDNSequence(subjectRDNs)

		if err != nil {
			return nil, err
		}
	}

	// 8. Parse extensions and see if any modifications are required
	for _, ext := range dcd.Extensions {
		// If the extension does not exist in the base certificate, return an error
		index, ok := baseExtensions[ext.Id.String()]
		if !ok {
			return nil, fmt.Errorf("Error: The deltaCertificateExtension contains extensions not present in the base certificate")
		}

		// Update the extension in the template
		deltaCert.Extensions[index] = ext
	}

	// 9. Replace the value of the Signature field
	deltaCert.Signature = dcd.SignatureValue.RightAlign()

	// 10. Recompute the ASN.1 encoded value of the certificate by replacing the Raw
	//     and RawTBSCertificate fields with the delta values
	err = deltaCert.deriveRawCertificate()
	if err != nil {
		return nil, err
	}

	// Return the reconstructed certificate
	return deltaCert, nil
}

func CreateChameleonCertificateRequest(rand io.Reader, deltaTemplate, baseTemplate *CertificateRequest, deltaPrivKey, basePrivKey any) ([]byte, error) {
	// Generate the delta CSR
	deltaCsrDer, err := CreateCertificateRequest(rand, deltaTemplate, deltaPrivKey)
	if err != nil {
		return nil, err
	}

	deltaCsr, err := ParseCertificateRequest(deltaCsrDer)
	if err != nil {
		return nil, err
	}

	// Create the delta attribute
	deltaAttribute := deltaCertificateRequestAttribute{}

	// Add the subject if necessary
	if deltaTemplate.Subject.String() != "" && deltaTemplate.Subject.String() != baseTemplate.Subject.String() {
		deltaAttribute.Subject = asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      deltaCsr.RawSubject,
		}
	}

	// Add the subject public key information
	key, ok := deltaPrivKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("Error: invalid delta private key")
	}
	pubKeyBytes, pubKeyAlgorithm, err := marshalPublicKey(key.Public())
	deltaAttribute.PublicKeyInfo = publicKeyInfo{
		Raw:       nil,
		Algorithm: pubKeyAlgorithm,
		PublicKey: asn1.BitString{
			Bytes:     pubKeyBytes,
			BitLength: len(pubKeyBytes) * 8,
		},
	}

	// If necessary, add differing extensions
	baseExtensions := buildExtensionIndexMap(baseTemplate.Extensions)
	for _, ext := range deltaTemplate.Extensions {
		index, _ := baseExtensions[ext.Id.String()]

		// TODO add test case for extension present in delta and not in base -> this should fail
		if !bytes.Equal(baseTemplate.Extensions[index].Value, ext.Value) {
			deltaAttribute.Extensions = append(deltaAttribute.Extensions, ext)
		}
	}

	// Add the signature algorithm information
	_, algoId, err := signingParamsForPublicKey(key.Public(), deltaTemplate.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}
	deltaAttribute.SignatureAlgorithm = algoId

	// Add the attribute to the base CSR template
	rawDeltaAttribute, err := asn1.MarshalWithParams(deltaAttribute, `asn1:"optional"`)
	if err != nil {
		return nil, err
	}

	baseTemplate.ExtraExtensions = append(baseTemplate.ExtraExtensions, pkix.Extension{
		Id:    deltaCertificateRequestAttributeOid,
		Value: rawDeltaAttribute,
	})

	// Compute the tbsCertificateRaw for the CSR in its current form
	csrBytes, err := CreateCertificateRequest(rand, baseTemplate, basePrivKey)
	if err != nil {
		return nil, err
	}
	csr, err := ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, err
	}

	// Get the signing params
	sigAlgo, _, err := signingParamsForKey(key, deltaTemplate.SignatureAlgorithm)
	if err != nil || sigAlgo == UnknownSignatureAlgorithm {
		return nil, fmt.Errorf("Error: Unknown Signature Algorithm")
	}
	hashFunc := sigAlgo.hashFunc()

	// If necessary pre-hash the certificate request info
	bytesToSign := csr.RawTBSCertificateRequest
	if hashFunc != 0 {
		h := hashFunc.New()
		h.Write(bytesToSign)
		bytesToSign = h.Sum(nil)
	}

	// Compute the signature
	signature, err := key.Sign(rand, bytesToSign, hashFunc)
	if err != nil {
		return nil, err
	}

	signatureValue := asn1.BitString{
		Bytes:     signature,
		BitLength: len(csr.Signature) * 8,
	}
	rawSignature, err := asn1.Marshal(signatureValue)
	if err != nil {
		return nil, err
	}

	baseTemplate.ExtraExtensions = append(baseTemplate.ExtraExtensions, pkix.Extension{
		Id:    deltaCertificateRequestSignatureAttributeOid,
		Value: rawSignature,
	})

	// Build the final CSR
	return CreateCertificateRequest(rand, baseTemplate, basePrivKey)
}

func ParseChameleonCertificateRequest(base []byte) (*CertificateRequest, *CertificateRequest, error) {
	// Parse the CSR
	baseCsr, err := ParseCertificateRequest(base)
	if err != nil {
		return nil, nil, err
	}

	extensionMap := buildExtensionIndexMap(baseCsr.Extensions)

	// Extract and the delta attribute
	deltaAttributeIndex, ok := extensionMap[deltaCertificateRequestAttributeOid.String()]
	if !ok {
		return nil, nil, fmt.Errorf("Error: delta CSR does not contain a delta certificate request attribute")
	}

	parsedAttribute, err := parseDeltaCertificateRequestAttribute(baseCsr.Extensions[deltaAttributeIndex].Value)
	if err != nil {
		return nil, nil, fmt.Errorf("Error parsing the delta CSR attribute")
	}

	// Extract the delta signature attribute
	deltaSignatureIndex, ok := extensionMap[deltaCertificateRequestSignatureAttributeOid.String()]
	if !ok {
		return nil, nil, fmt.Errorf("Error: delta CSR does not contain a delta certificate request attribute")
	}

	var deltaSignature asn1.BitString
	_, err = asn1.Unmarshal(baseCsr.Extensions[deltaSignatureIndex].Value, &deltaSignature)
	if err != nil {
		return nil, nil, fmt.Errorf("Error parsing the delta CSR attribute")
	}

	deltaCsr, err := deriveDeltaCSR(baseCsr, parsedAttribute, deltaSignature)
	if err != nil {
		return nil, nil, err
	}

	return deltaCsr, baseCsr, nil
}

func CreateBoundCertificate(randSource io.Reader, template, parent *Certificate, relatedCertDer []byte, pubKey, privKey any) ([]byte, error) {
	// Parse the related certificate
	relatedCert, err := ParseCertificate(relatedCertDer)
	if err != nil {
		return nil, err
	}

	// Get the AlgorithmIdentifier for the Related Certificate's signature algorithm
	_, signatureAlgorithm, err := signingParamsForPublicKey(relatedCert.PublicKey, relatedCert.SignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	// Compute the hash value of the related cert
	hashValue, err := computeRelatedCertHash(signatureAlgorithm.Algorithm, relatedCert)
	if err != nil {
		return nil, err
	}

	// Build and encode the related certificate extension
	relatedCertExtension := relatedCertificateExtension{
		HashAlgorithm: signatureAlgorithm,
		HashValue:     hashValue,
	}
	rawRelatedCertExtension, err := asn1.Marshal(relatedCertExtension)
	if err != nil {
		return nil, err
	}

	// Add the extension to the template
	template.ExtraExtensions = []pkix.Extension{
		{
			Id:    relatedCertificateExtensionOid,
			Value: rawRelatedCertExtension,
		},
	}

	// Create the certificate
	return CreateCertificate(randSource, template, parent, pubKey, privKey)
}

func computeRelatedCertHash(signatureAlgorithm asn1.ObjectIdentifier, relatedCertificate *Certificate) ([]byte, error) {
	var hashAlgo hash.Hash
	switch signatureAlgorithm.String() {
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

	_, err := hashAlgo.Write(relatedCertificate.Raw)
	if err != nil {
		return nil, err
	}
	hash := hashAlgo.Sum(nil)

	return hash[:], nil
}

func parseDeltaExtension(deltaDer []byte) (*deltaCertificateDescriptor, error) {
	// Attempt to parse the delta extension
	deltaExtension := deltaCertificateDescriptor{}
	_, err := asn1.Unmarshal(deltaDer, &deltaExtension)
	if err != nil {
		return nil, err
	}

	// Return the result
	return &deltaExtension, nil
}

func parseDeltaCertificateRequestAttribute(deltaAttributeDer []byte) (*deltaCertificateRequestAttribute, error) {
	// Attempt to parse the delta extension
	deltaAttribute := deltaCertificateRequestAttribute{}
	_, err := asn1.Unmarshal(deltaAttributeDer, &deltaAttribute)
	if err != nil {
		return nil, err
	}

	// Return the result
	return &deltaAttribute, nil
}

func (c *Certificate) deriveRawCertificate() error {
	// Get the raw values of the appropriate fields
	_, signatureAlgorithm, err := signingParamsForPublicKey(c.PublicKey, c.SignatureAlgorithm)
	if err != nil {
		return err
	}

	publicKeyBytes, publicKeyAlgorithm, err := marshalPublicKey(c.PublicKey)
	if err != nil {
		return err
	}
	encodedPublicKey := asn1.BitString{BitLength: len(publicKeyBytes) * 8, Bytes: publicKeyBytes}

	// Create the TBSCertificate struct and encode it
	certTBSCertificate := tbsCertificate{
		Version:            2,
		SerialNumber:       c.SerialNumber,
		SignatureAlgorithm: signatureAlgorithm,
		Issuer:             asn1.RawValue{FullBytes: c.RawIssuer},
		Validity:           validity{c.NotBefore.UTC(), c.NotAfter.UTC()},
		Subject:            asn1.RawValue{FullBytes: c.RawSubject},
		PublicKey:          publicKeyInfo{nil, publicKeyAlgorithm, encodedPublicKey},
		Extensions:         c.Extensions,
	}

	c.RawTBSCertificate, err = asn1.Marshal(certTBSCertificate)
	if err != nil {
		return err
	}

	// Rebuild the Certificate struct and encode it
	signed := certificate{
		TBSCertificate:     certTBSCertificate,
		SignatureAlgorithm: signatureAlgorithm,
		SignatureValue: asn1.BitString{
			Bytes:     c.Signature,
			BitLength: len(c.Signature) * 8,
		},
	}
	c.Raw, err = asn1.Marshal(signed)
	if err != nil {
		return err
	} else {
		return nil
	}
}

func deriveDeltaCSR(baseCsr *CertificateRequest, parsedAttribute *deltaCertificateRequestAttribute, signature asn1.BitString) (*CertificateRequest, error) {
	// Create the raw TBS structure
	deltaTBSCertificateRequest := tbsCertificateRequest{}

	// Modify the necessary fields
	if len(parsedAttribute.Subject.Bytes) > 0 {
		deltaTBSCertificateRequest.Subject = asn1.RawValue{FullBytes: parsedAttribute.Subject.Bytes}
	} else {
		deltaTBSCertificateRequest.Subject = asn1.RawValue{FullBytes: baseCsr.RawSubject}
	}

	deltaTBSCertificateRequest.PublicKey = parsedAttribute.PublicKeyInfo

	// Check if the parsed attribute contains extensions not present in the base
	baseExtensions := buildExtensionIndexMap(baseCsr.Extensions)
	for _, ext := range parsedAttribute.Extensions {
		_, ok := baseExtensions[ext.Id.String()]

		if !ok {
			return nil, fmt.Errorf("Error: the Delta CSR Attribute contains extensions not present in the Base CSR")
		}
	}


	// Modify or copy the baseCsr extensions
	var extensions []pkix.Extension
	deltaExtensions := buildExtensionIndexMap(parsedAttribute.Extensions)
	for _, ext := range baseCsr.Extensions {
		_, ok := deltaExtensions[ext.Id.String()]

		if ok {
			extensions = append(extensions, parsedAttribute.Extensions[deltaExtensions[ext.Id.String()]])
		} else {
			extensions = append(extensions, ext)
		}
	}

	deltaTBSCertificateRequest.Raw = nil
	rawDeltaTBSCertificateRequest, err := asn1.Marshal(deltaTBSCertificateRequest)
	if err != nil {
		return nil, err
	}
	deltaTBSCertificateRequest.Raw = rawDeltaTBSCertificateRequest

	deltaCSR := certificateRequest{
		TBSCSR:             deltaTBSCertificateRequest,
		SignatureAlgorithm: parsedAttribute.SignatureAlgorithm,
		SignatureValue:     signature,
	}

	// Encode the CSR
	deltaCSRDer, err := asn1.Marshal(deltaCSR)
	if err != nil {
		return nil, err
	}

	// Parse the CSR and return the object
	return ParseCertificateRequest(deltaCSRDer)
}

func buildExtensionIndexMap(extensions []pkix.Extension) map[string]int {
	extensionMap := make(map[string]int)

	for index, ext := range extensions {
		extensionMap[ext.Id.String()] = index
	}

	return extensionMap
}
