package webpush

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
)

// - https://www.w3.org/TR/push-api/#dom-pushsubscriptionjson
type subscriptionJSON struct {
	Endpoint string    `json:"endpoint"`
	Keys     *keysJSON `json:"keys"`
}

// - https://www.w3.org/TR/push-api/#dom-pushencryptionkeyname
type keysJSON struct {
	Auth   urlSafeBytes `json:"auth"`
	P256DH urlSafeBytes `json:"p256dh"`
}

// urlSafeBytes is the same []byte, however implements text [un]marshalling
// using URL safe base64 encoding (base64.URLEncoding) instead of regular
// base64 (base64.StdEncoding)
type urlSafeBytes []byte

func (k *urlSafeBytes) UnmarshalText(text []byte) error {
	maxLen := base64.URLEncoding.DecodedLen(len(text))
	out := make(urlSafeBytes, maxLen)

	n, err := base64.URLEncoding.Decode(out, text)

	*k = out[:n]

	return err
}

func (k urlSafeBytes) MarshalText() ([]byte, error) {
	len := base64.URLEncoding.EncodedLen(len(k))
	out := make([]byte, len)

	base64.URLEncoding.Encode(out, k)

	return out, nil
}

func (p *PublicKey) MarshalBinary() ([]byte, error) {
	if p.X == nil {
		return nil, errors.New("webpush: invalid public key")
	}

	return elliptic.Marshal(p256, p.X, p.Y), nil
}

func (p *PublicKey) UnmarshalBinary(data []byte) error {
	x, y := elliptic.Unmarshal(p256, data)

	if x == nil {
		return errors.New("webpush: invalid public key")
	}

	p.X, p.Y = x, y

	return nil
}

func UnmarshalSubscription(data []byte) (*Subscription, error) {
	subJSON := &subscriptionJSON{}
	err := json.Unmarshal(data, subJSON)
	if err != nil {
		return nil, err
	}

	p256dh := &PublicKey{}
	err = p256dh.UnmarshalBinary(subJSON.Keys.P256DH)
	if err != nil {
		return nil, err
	}

	sub := &Subscription{
		Endpoint: subJSON.Endpoint,

		Auth:   subJSON.Keys.Auth,
		P256DH: p256dh,
	}

	return sub, err
}
