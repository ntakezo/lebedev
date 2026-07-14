package ca

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"path/filepath"
	"testing"
)

func TestLeafForSignedByCAWithSANs(t *testing.T) {
	a, err := Generate("Lebedev Test CA")
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := a.LeafFor("example.com:443")
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(a.cert)
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "example.com", Roots: roots}); err != nil {
		t.Errorf("leaf does not chain to CA: %v", err)
	}
	if leaf.Leaf.Subject.CommonName != "example.com" {
		t.Errorf("CN = %q", leaf.Leaf.Subject.CommonName)
	}
}

func TestLeafForIPUsesIPSAN(t *testing.T) {
	a, err := Generate("Lebedev Test CA")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := a.LeafFor("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.Leaf.IPAddresses) != 1 || !leaf.Leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("IP SANs = %v", leaf.Leaf.IPAddresses)
	}
	if len(leaf.Leaf.DNSNames) != 0 {
		t.Errorf("unexpected DNS SANs = %v", leaf.Leaf.DNSNames)
	}
}

func TestLeafForCachesByHost(t *testing.T) {
	a, err := Generate("Lebedev Test CA")
	if err != nil {
		t.Fatal(err)
	}
	first, _ := a.LeafFor("example.com")
	second, _ := a.LeafFor("example.com:8443")
	if first != second {
		t.Error("expected cached leaf reuse for same host")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	a, err := Generate("Lebedev Test CA")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Save(certPath, keyPath); err != nil {
		t.Fatal(err)
	}

	b, err := Load(certPath, keyPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// A leaf minted by the loaded CA must still chain to the original cert.
	leaf, err := b.LeafFor("example.com")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(a.cert)
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "example.com", Roots: roots}); err != nil {
		t.Errorf("loaded CA minted leaf that does not chain to saved root: %v", err)
	}
}

func TestLoadOrGenerateCreatesMissingDir(t *testing.T) {
	// Mimic a fresh machine where the CA directory (e.g. ~/.lebedev) does not
	// exist yet: LoadOrGenerate must create it rather than fail to write.
	dir := filepath.Join(t.TempDir(), "lebedev")
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	a, err := LoadOrGenerate(certPath, keyPath, "Lebedev Test CA")
	if err != nil {
		t.Fatalf("LoadOrGenerate into missing dir: %v", err)
	}
	if !fileExists(certPath) || !fileExists(keyPath) {
		t.Fatal("CA files were not written")
	}

	// A second call must load the persisted CA, not regenerate it.
	b, err := LoadOrGenerate(certPath, keyPath, "Lebedev Test CA")
	if err != nil {
		t.Fatalf("LoadOrGenerate reload: %v", err)
	}
	if !a.cert.Equal(b.cert) {
		t.Error("second call regenerated the CA instead of loading it")
	}
}

func TestTLSConfigServesLeafForSNI(t *testing.T) {
	a, err := Generate("Lebedev Test CA")
	if err != nil {
		t.Fatal(err)
	}
	cfg := a.TLSConfig([]string{"h2", "http/1.1"})
	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf.Subject.CommonName != "api.example.com" {
		t.Errorf("CN = %q", cert.Leaf.Subject.CommonName)
	}
}
