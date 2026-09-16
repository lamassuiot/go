// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import "crypto/x509"

// Composite ML-DSA+RSA algorithms (draft-ietf-lamps-pq-composite-sigs).
//
// No IANA codepoints have been assigned for these algorithms in the TLS
// SignatureScheme registry, so these use the private use range reserved by
// RFC 8446, Section 4.2.3 (0xFE00-0xFFFF).
const (
	CompositeMLDSA44RSA2048PSSHA256     SignatureScheme = 0xFE00
	CompositeMLDSA44RSA2048PKCS15SHA256 SignatureScheme = 0xFE01
	CompositeMLDSA65RSA3072PSSHA512     SignatureScheme = 0xFE02
	CompositeMLDSA65RSA3072PKCS15SHA512 SignatureScheme = 0xFE03
	CompositeMLDSA65RSA4096PSSHA512     SignatureScheme = 0xFE04
	CompositeMLDSA65RSA4096PKCS15SHA512 SignatureScheme = 0xFE05
	CompositeMLDSA87RSA3072PSSHA512     SignatureScheme = 0xFE06
	CompositeMLDSA87RSA4096PSSHA512     SignatureScheme = 0xFE07
)

// compositeSignatureSchemes pairs each composite SignatureScheme with its
// x509.CompositeAlgorithm, in preference order. Order must track
// x509.CompositeAlgorithms.
var compositeSignatureSchemes = []struct {
	scheme SignatureScheme
	algo   *x509.CompositeAlgorithm
}{
	{CompositeMLDSA44RSA2048PSSHA256, x509.MLDSA44_RSA2048_PSS_SHA256},
	{CompositeMLDSA44RSA2048PKCS15SHA256, x509.MLDSA44_RSA2048_PKCS15_SHA256},
	{CompositeMLDSA65RSA3072PSSHA512, x509.MLDSA65_RSA3072_PSS_SHA512},
	{CompositeMLDSA65RSA3072PKCS15SHA512, x509.MLDSA65_RSA3072_PKCS15_SHA512},
	{CompositeMLDSA65RSA4096PSSHA512, x509.MLDSA65_RSA4096_PSS_SHA512},
	{CompositeMLDSA65RSA4096PKCS15SHA512, x509.MLDSA65_RSA4096_PKCS15_SHA512},
	{CompositeMLDSA87RSA3072PSSHA512, x509.MLDSA87_RSA3072_PSS_SHA512},
	{CompositeMLDSA87RSA4096PSSHA512, x509.MLDSA87_RSA4096_PSS_SHA512},
}

var (
	compositeAlgorithmByScheme map[SignatureScheme]*x509.CompositeAlgorithm
	compositeSchemeByAlgorithm map[*x509.CompositeAlgorithm]SignatureScheme
)

func init() {
	compositeAlgorithmByScheme = make(map[SignatureScheme]*x509.CompositeAlgorithm, len(compositeSignatureSchemes))
	compositeSchemeByAlgorithm = make(map[*x509.CompositeAlgorithm]SignatureScheme, len(compositeSignatureSchemes))
	for _, e := range compositeSignatureSchemes {
		compositeAlgorithmByScheme[e.scheme] = e.algo
		compositeSchemeByAlgorithm[e.algo] = e.scheme
	}
}

// isCompositeSignatureScheme reports whether s identifies a composite
// ML-DSA+RSA algorithm.
func isCompositeSignatureScheme(s SignatureScheme) bool {
	_, ok := compositeAlgorithmByScheme[s]
	return ok
}
