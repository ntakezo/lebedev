// Package ca is the proxy's certificate authority: it holds a root CA and mints
// short-lived leaf certificates per SNI host so the proxy can terminate TLS for
// any origin the client visits, once the root is trusted on the machine.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Authority is a root CA plus a cache of leaf certificates keyed by host. It is
// safe for concurrent use. Leaves share one key, as browsers key trust off the
// root, not the leaf.
type Authority struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certDER []byte
	leafKey *ecdsa.PrivateKey

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// Generate creates a new in-memory root CA whose subject and issuer common name
// is name. Persist it with Save so the same root can be reused and trusted.
func Generate(name string) (*Authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := newSerial()
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: name, Organization: []string{name}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return newAuthority(cert, key, der)
}

// Load reads a previously saved root CA certificate and key from PEM files.
func Load(certPath, keyPath string) (*Authority, error) {
	cert, der, err := readCert(certPath)
	if err != nil {
		return nil, err
	}
	key, err := readKey(keyPath)
	if err != nil {
		return nil, err
	}
	return newAuthority(cert, key, der)
}

// LoadOrGenerate loads the root CA from the given paths, or generates and saves
// a fresh one under name when either file is missing.
func LoadOrGenerate(certPath, keyPath, name string) (*Authority, error) {
	if fileExists(certPath) && fileExists(keyPath) {
		return Load(certPath, keyPath)
	}
	a, err := Generate(name)
	if err != nil {
		return nil, err
	}
	if err := a.Save(certPath, keyPath); err != nil {
		return nil, err
	}
	return a, nil
}

func newAuthority(cert *x509.Certificate, key *ecdsa.PrivateKey, der []byte) (*Authority, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Authority{
		cert:    cert,
		key:     key,
		certDER: der,
		leafKey: leafKey,
		cache:   map[string]*tls.Certificate{},
	}, nil
}

// CertPEM returns the root CA certificate in PEM form, suitable for installing
// into a system or browser trust store.
func (a *Authority) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.certDER})
}

// Save writes the root CA certificate and key to certPath and keyPath, creating
// their parent directories if needed. The key file and any created directories
// are given owner-only permissions since they hold the CA private key.
func (a *Authority) Save(certPath, keyPath string) error {
	keyDER, err := x509.MarshalECPrivateKey(a.key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, a.CertPEM(), 0o644); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return os.WriteFile(keyPath, keyPEM, 0o600)
}

// LeafFor returns a leaf certificate valid for host (any port is ignored),
// minting and caching one on first use.
func (a *Authority) LeafFor(host string) (*tls.Certificate, error) {
	host = stripPort(host)
	if host == "" {
		return nil, fmt.Errorf("ca: empty host")
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.cache[host]; ok {
		return c, nil
	}
	leaf, err := a.mint(host)
	if err != nil {
		return nil, err
	}
	a.cache[host] = leaf
	return leaf, nil
}

// TLSConfig returns a server TLS config that serves per-host leaf certificates
// and advertises nextProtos via ALPN (e.g. "h2", "http/1.1").
func (a *Authority) TLSConfig(nextProtos []string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: nextProtos,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return a.LeafFor(hello.ServerName)
		},
	}
}

func (a *Authority) mint(host string) (*tls.Certificate, error) {
	sn, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &a.leafKey.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  a.leafKey,
		Leaf:        leaf,
	}, nil
}

func readCert(path string) (*x509.Certificate, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, nil, fmt.Errorf("ca: no PEM certificate in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, block.Bytes, nil
}

func readKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("ca: no PEM key in %s", path)
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
