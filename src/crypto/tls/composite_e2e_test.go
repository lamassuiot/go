// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

func compositeTestCert(t *testing.T, alg *x509.CompositeAlgorithm, cn string) Certificate {
	t.Helper()
	pub, priv, err := alg.GenerateCompositeKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateCompositeKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return cert
}

func TestCompositeHandshakeTLS13(t *testing.T) {
	alg := x509.MLDSA65_RSA3072_PSS_SHA512
	serverCert := compositeTestCert(t, alg, "example.com")
	clientCert := compositeTestCert(t, alg, "client")

	pool := x509.NewCertPool()
	pool.AddCert(serverCert.Leaf)
	clientPool := x509.NewCertPool()
	clientPool.AddCert(clientCert.Leaf)

	serverConfig := &Config{
		Certificates: []Certificate{serverCert},
		ClientAuth:   RequireAndVerifyClientCert,
		ClientCAs:    clientPool,
		MinVersion:   VersionTLS13,
	}
	clientConfig := &Config{
		Certificates: []Certificate{clientCert},
		RootCAs:      pool,
		ServerName:   "example.com",
		MinVersion:   VersionTLS13,
	}

	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	clientConn := Client(c, clientConfig)
	serverConn := Server(s, serverConfig)

	errCh := make(chan error, 1)
	go func() {
		errCh <- serverConn.Handshake()
	}()

	if err := clientConn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	cs := clientConn.ConnectionState()
	if _, ok := cs.PeerCertificates[0].PublicKey.(*x509.CompositePublicKey); !ok {
		t.Errorf("client-side peer cert public key = %T, want *x509.CompositePublicKey", cs.PeerCertificates[0].PublicKey)
	}
	ss := serverConn.ConnectionState()
	if _, ok := ss.PeerCertificates[0].PublicKey.(*x509.CompositePublicKey); !ok {
		t.Errorf("server-side peer cert public key = %T, want *x509.CompositePublicKey", ss.PeerCertificates[0].PublicKey)
	}

	msg := []byte("hello over composite TLS")
	go func() {
		clientConn.Write(msg)
	}()
	buf := make([]byte, len(msg))
	if _, err := serverConn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Errorf("got %q, want %q", buf, msg)
	}
}

func TestCompositeSignatureSchemesExcludedFromTLS12(t *testing.T) {
	algs := supportedSignatureAlgorithms(VersionTLS10, VersionTLS12)
	for _, a := range algs {
		if isCompositeSignatureScheme(a) {
			t.Errorf("composite scheme %v advertised for TLS 1.2 range", a)
		}
	}
	algs13 := supportedSignatureAlgorithms(VersionTLS10, VersionTLS13)
	found := false
	for _, a := range algs13 {
		if isCompositeSignatureScheme(a) {
			found = true
		}
	}
	if !found {
		t.Errorf("composite schemes not advertised when TLS 1.3 is in range")
	}
}
