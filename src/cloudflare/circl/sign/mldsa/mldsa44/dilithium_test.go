package mldsa44

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"testing"
)

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Tests                                                                      //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

var testcases = []struct {
	name  string
	pem   string
	check func(crypto.Signer, error) error
}{
	{
		name:  "Expanded Format RFC 9881",
		pem:   expanded_format_rfc,
		check: checkOk,
	},
	{
		name:  "Expanded Format Cloudflare Circl",
		pem:   expanded_format_cf,
		check: checkOk,
	},
	{
		name:  "Seed Format RFC 9881",
		pem:   seed_format_rfc,
		check: checkOk,
	},
	{
		name:  "Both Format RFC 9881",
		pem:   both_format_rfc,
		check: checkOk,
	},
	{
		name:  "Both Format With Incompatible Keys RFC 9881",
		pem:   both_format_wrong_keys_rfc,
		check: checkBothFail,
	},
}

func TestUnmarshal(t *testing.T) {
	t.Parallel()

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// Parse the PEM file
			packedSk, err := unpackKey(tc.pem)
			if err != nil {
				t.Fatal(err)
			}

			// Unmarshal the private key
			var sk PrivateKey
			err = sk.UnmarshalBinary(packedSk)

			// Run the check function
			err = tc.check(&sk, err)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUnmarshallFromBinary(t *testing.T) {
	t.Parallel()

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// Parse the PEM file
			packedSk, err := unpackKey(tc.pem)
			if err != nil {
				t.Fatal(err)
			}

			// Unmarshal the private key
			scheme := Scheme()
			sk, err := scheme.UnmarshalBinaryPrivateKey(packedSk)

			// Run the check function
			err = tc.check(sk, err)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTLSIdentifer(t *testing.T) {
	sch := scheme{}
	if sch.TLSIdentifier() != 0x0904 {
		t.Fatal("mldsa44: Invalid TLS code point")
	}
}

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Helper functions and structures                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

func unpackKey(pemKey string) ([]byte, error) {
	// Parse the PEM string
	pemData, _ := pem.Decode([]byte(pemKey))

	// Obtain the pkcs8 private key structure
	var privKey pkcs8
	_, err := asn1.Unmarshal(pemData.Bytes, &privKey)
	if err != nil {
		return nil, err
	}

	// Obtain the packed private key
	var packedSk asn1.RawValue
	_, err = asn1.Unmarshal(privKey.PrivateKey, &packedSk)

	return packedSk.Bytes, err
}

func unmarshalKey(packedSk []byte) (*PrivateKey, error) {
	// Unmarshal the private key
	var sk PrivateKey
	err := sk.UnmarshalBinary(packedSk)

	return &sk, err
}

func checkOk(sk crypto.Signer, err error) error {
	// Check that the key was unmarshalled without errors
	if err != nil {
		return err
	}

	// Test signing and verifying a message
	switch pk := sk.Public().(type) {
	case *PublicKey:
		// Test that sk is not nil
		if bytes.Equal(pk.Bytes(), make([]byte, PublicKeySize)) {
			return fmt.Errorf("Error: could not unmarshal public key")
		}

		msg := []byte{0xde, 0xad, 0xbe, 0xef}
		sig, err := sk.Sign(rand.Reader, msg, crypto.Hash(0))
		if err != nil || !Verify(pk, msg, nil, sig) {
			return fmt.Errorf("Error: unmarshalled private key could not sign a message")
		}
	default:
		return fmt.Errorf("Error: could not derive the public key")
	}

	return nil
}

func checkBothFail(sk crypto.Signer, err error) error {
	// Check that when the seed and expanded keys are not the same, an error is raised
	if err == nil || err.Error() != "error: incompatible seed and key values" {
		return fmt.Errorf("Unexpected Error: %s", err)
	}

	return nil
}

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Sample data                                                                //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

const seed_format_rfc = `
-----BEGIN PRIVATE KEY-----
MDQCAQAwCwYJYIZIAWUDBAMRBCKAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
GhscHR4f
-----END PRIVATE KEY-----
`

const expanded_format_rfc = `
-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----
`
const expanded_format_cf = `
-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----
`

const both_format_rfc = `
-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----
`

const both_format_wrong_keys_rfc = `
-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----
`
