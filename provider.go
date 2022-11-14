package acme

import (
	"errors"
	"fmt"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"
)

type ProviderType int

const (
	DNS ProviderType = iota
	TLS
	HTTP
)

type Provider interface {
	Provider() (challenge.Provider, error)
	Type() ProviderType
}

func setProvider(client *lego.Client, p Provider) error {
	pdr, err := p.Provider()
	if err != nil {
		return fmt.Errorf("provider: %s", err.Error())
	}
	switch p.Type() {
	case DNS:
		return client.Challenge.SetDNS01Provider(pdr)
	case HTTP:
		return client.Challenge.SetHTTP01Provider(pdr)
	case TLS:
		return client.Challenge.SetTLSALPN01Provider(pdr)
	default:
		return errors.New("provider: unsupported provider type")
	}
}

type TencentCloudProvider struct {
	*tencentcloud.Config
}

func NewTencentCloudProvider(secID, secKey string) *TencentCloudProvider {
	cfg := tencentcloud.NewDefaultConfig()
	cfg.SecretID = secID
	cfg.SecretKey = secKey
	return &TencentCloudProvider{cfg}
}

func (t *TencentCloudProvider) Provider() (challenge.Provider, error) {
	return tencentcloud.NewDNSProviderConfig(t.Config)
}

func (t *TencentCloudProvider) Type() ProviderType {
	return DNS
}

func GetProvider(pType DNSProviderType, items ...string) (Provider, error) {
	ctr, ok := defaultDNSProviderCreatorsMap[pType]
	if !ok {
		return nil, errors.New("dns provider: unsupported dns provider type")
	}
	if ctr.ItemsAmount != len(items) {
		return nil, errors.New("dns provider: amount of items is invalid")
	}
	return ctr.CreateFunc(items...)
}

type DNSProviderType string

const (
	TencentCloud DNSProviderType = "tencent_cloud"
)

var defaultDNSProviderCreatorsMap = map[DNSProviderType]DNSProviderCreator{
	TencentCloud: {
		CreateFunc: func(items ...string) (Provider, error) {
			return NewTencentCloudProvider(items[0], items[1]), nil
		},
		ItemsAmount:     2,
		DNSProviderType: TencentCloud,
	},
}

// DNSProviderCreator used to create dns provider
type DNSProviderCreator struct {
	CreateFunc  func(items ...string) (Provider, error)
	ItemsAmount int
	DNSProviderType
}
