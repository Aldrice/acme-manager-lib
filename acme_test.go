package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"
)

func TestClient_ObtainCertificate(t *testing.T) {
	client := NewACMEClient()
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return
	}
	privateBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("private key", string(privateBytes))
	publicBytes := elliptic.Marshal(privateKey.PublicKey.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)
	t.Log("public key", string(publicBytes))

	cfg := tencentcloud.NewDefaultConfig()
	cfg.SecretID = "AKIDa0f8NPFuMXUDhusuqkkY8Wfrqa5VhfPv"
	cfg.SecretKey = "TkncJlz0mMjrlPoxVqwZ3MPHzUlqiMn6"
	provider, err := tencentcloud.NewDNSProviderConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	challenger := NewZeroSSL(
		"jyTTP18NxjHlSCCCZu3Hfg",
		"_gGl1zX7eGEqTzlozK4hCrcBN4AyZ0auihmxIe4LpTIfWI7HXs7qGsk17V0O1nwD9jAdC_H-Uz98Hck9PLQ5XQ",
	)

	cert, err := client.ObtainCertificate(
		"d739429337@hotmail.com",
		provider,
		challenger,
		privateKey,
		privateKey,
		true,
		"test.klloong.com",
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("got cert")
	t.Log("domain", cert.Domain)
	t.Log("cert url", cert.CertURL)
	t.Log("cert stable url", cert.CertStableURL)
	t.Log("private key", string(cert.PrivateKey))
	t.Log("certificate", string(cert.Certificate))
	t.Log("IssuerCertificate", string(cert.IssuerCertificate))
	t.Log("csr", string(cert.CSR))
}
