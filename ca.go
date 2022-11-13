package acme

import (
	"crypto/x509"
	"github.com/go-acme/lego/v4/certificate"
)

const (
	DirURLZeroSSL = "https://acme.zerossl.com/v2/DV90"
)

type CertAgent struct {
	url  string
	kid  string
	hmac string
}

func NewZeroSSLCA(kid, hmac string) CertAgent {
	return CertAgent{
		url:  DirURLZeroSSL,
		kid:  kid,
		hmac: hmac,
	}
}

type Certificate struct {
	*certificate.Resource
	*x509.Certificate
}

func NewCertificate(acrt *certificate.Resource) (*Certificate, error) {
	xcrt, err := x509.ParseCertificate(acrt.Certificate)
	if err != nil {
		return nil, err
	}
	return &Certificate{
		Resource:    acrt,
		Certificate: xcrt,
	}, nil
}
