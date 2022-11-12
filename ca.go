package acme

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
