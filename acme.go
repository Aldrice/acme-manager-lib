package acme

import (
	"crypto"
	"fmt"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type Client struct{}

func NewLegoClient() *Client {
	return &Client{}
}

type Account struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func newAccount(email string, key crypto.PrivateKey) *Account {
	return &Account{Email: email, key: key}
}

func (u *Account) GetEmail() string {
	return u.Email
}
func (u *Account) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *Account) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func (c *Client) error(format string, a ...any) error {
	return fmt.Errorf("acme: "+format, a)
}

func (c *Client) ObtainCertificate(
	email string,
	providers []Provider,
	domains []string,
	ca CertAgent,
	acctKey,
	certKey crypto.PrivateKey,
	bundle bool,
) (*Certificate, error) {
	if domains == nil || len(domains) == 0 {
		return nil, c.error("no domain to be obtained")
	}
	if providers == nil || len(providers) == 0 {
		return nil, c.error("no provider had been issued")
	}

	a := newAccount(email, acctKey)
	config := lego.NewConfig(a)
	config.CADirURL = ca.url

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, c.error(err.Error())
	}

	// using dns provider
	for _, provider := range providers {
		err = setProvider(client, provider)
		if err != nil {
			return nil, c.error(err.Error())
		}
	}

	// New users will need to register
	a.Registration, err = client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
		TermsOfServiceAgreed: true,
		Kid:                  ca.kid,
		HmacEncoded:          ca.hmac,
	})
	if err != nil {
		return nil, c.error(err.Error())
	}

	// obtain the certification
	cert, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains:    domains,
		Bundle:     bundle,
		PrivateKey: certKey,
	})
	if err != nil {
		return nil, c.error(err.Error())
	}
	return NewCertificate(cert)
}
