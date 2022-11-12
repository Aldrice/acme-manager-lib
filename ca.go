package acme

import (
	"crypto/x509"
	"github.com/go-acme/lego/v4/certificate"
)

type CertAgent interface {
	URL() string
	Kid() string
	Hmac() string
}

type ZeroSSL struct {
	kid  string
	hmac string
}

func NewZeroSSL(kid string, hmac string) *ZeroSSL {
	return &ZeroSSL{kid: kid, hmac: hmac}
}

func (z ZeroSSL) URL() string {
	return "https://acme.zerossl.com/v2/DV90"
}

func (z ZeroSSL) Kid() string {
	return z.kid
}

func (z ZeroSSL) Hmac() string {
	return z.hmac
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
