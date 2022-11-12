package acme

import (
	"crypto"
	"fmt"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type Client struct{}

func NewACMEClient() *Client {
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
	provider challenge.Provider,
	ca CertAgent,
	acctKey,
	certKey crypto.PrivateKey,
	bundle bool,
	domains ...string,
) (*Certificate, error) {
	if domains == nil || len(domains) == 0 {
		return nil, c.error("no domain to be obtained")
	}
	if provider == nil {
		return nil, c.error("no provider had been issued")
	}

	a := newAccount(email, acctKey)
	config := lego.NewConfig(a)
	config.CADirURL = ca.URL()

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	// using dns provider
	err = client.Challenge.SetDNS01Provider(provider)
	if err != nil {
		return nil, err
	}

	// New users will need to register
	reg, err := client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
		TermsOfServiceAgreed: true,
		Kid:                  ca.Kid(),
		HmacEncoded:          ca.Hmac(),
	})
	if err != nil {
		return nil, err
	}
	a.Registration = reg

	// obtain the certification
	cert, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains:    domains,
		Bundle:     bundle,
		PrivateKey: certKey,
	})
	if err != nil {
		return nil, err
	}
	return NewCertificate(cert)
}
