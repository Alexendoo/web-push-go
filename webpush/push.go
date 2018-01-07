package webpush

import (
	"net/http"
)

// Subscription is a User Agent's push message subscription
//
// - https://www.w3.org/TR/push-api/#dom-pushsubscription
type Subscription struct {
	Endpoint string

	// 16 random bytes generated by the user agent, auth_secret in RFC 8291
	// encryption summary
	Auth   []byte
	P256DH *PublicKey
}

func New(sub *Subscription, message []byte) (*http.Request, error) {
	keypair, err := generateKey(p256)
	if err != nil {
		return nil, err
	}

	salt, err := randomBytes(16)
	if err != nil {
		return nil, err
	}

	return encrypt(sub, keypair, message, salt)
}
