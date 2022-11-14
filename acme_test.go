package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestClient_ObtainCertificate(t *testing.T) {
	client := NewLegoClient()
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("success to create private key")

	provider, err := GetProvider(TencentCloud, "AKIDa0f8NPFuMXUDhusuqkkY8Wfrqa5VhfPv", "TkncJlz0mMjrlPoxVqwZ3MPHzUlqiMn6")
	if err != nil {
		t.Fatal(err)
	}
	ca := NewZeroSSLCA(
		"jyTTP18NxjHlSCCCZu3Hfg",
		"_gGl1zX7eGEqTzlozK4hCrcBN4AyZ0auihmxIe4LpTIfWI7HXs7qGsk17V0O1nwD9jAdC_H-Uz98Hck9PLQ5XQ",
	)

	t.Log("start obtaining certificate")
	cert, err := client.ObtainCertificate(
		"d739429337@hotmail.com",
		[]Provider{provider},
		[]string{"test.klloong.com"},
		ca, privateKey, privateKey, true,
	)
	if err != nil {
		t.Fatal(err)
	}

	// resource info
	t.Log("got cert")
	t.Log("domain", cert.Domain)
	t.Log("cert url", cert.CertURL)
	t.Log("cert stable url", cert.CertStableURL)
	t.Log("private key", string(cert.PrivateKey))
	t.Log("certificate", string(cert.Resource.Certificate))
	t.Log("IssuerCertificate", string(cert.IssuerCertificate))
	t.Log("csr", string(cert.CSR))

	// meta info
	t.Log("cert date valid", cert.NotBefore)
	t.Log("cert date expired", cert.NotAfter)
}
