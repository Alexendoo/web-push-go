package webpush

import (
	"bytes"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

// urlSafeBytes is the same []byte, however implements text unmarshalling using
// URL safe base64 encoding (base64.URLEncoding) instead of regular base64
type urlSafeBytes []byte

func (k *urlSafeBytes) UnmarshalText(text []byte) error {
	// Chrome incorrectly encode values as padded base64
	text = bytes.TrimRightFunc(text, func(r rune) bool {
		return r == '='
	})

	maxLen := base64.RawURLEncoding.DecodedLen(len(text))
	out := make(urlSafeBytes, maxLen)

	n, err := base64.RawURLEncoding.Decode(out, text)

	*k = out[:n]

	return err
}

func (p *PublicKey) MarshalBinary() ([]byte, error) {
	if p.X == nil {
		return nil, errors.New("webpush: invalid public key")
	}

	return elliptic.Marshal(p256, p.X, p.Y), nil
}

func (p *PublicKey) UnmarshalBinary(data []byte) error {
	p.X, p.Y = elliptic.Unmarshal(p256, data)

	if p.X == nil {
		return errors.New("webpush: invalid public key")
	}

	return nil
}

func UnmarshalSubscription(data []byte) (*Subscription, error) {
	subJSON := &subscriptionJSON{}
	err := json.Unmarshal(data, subJSON)
	if err != nil {
		return nil, err
	}

	if length := len(subJSON.Keys.Auth); length != 16 {
		return nil, fmt.Errorf("webpush: invalid auth length %d", length)
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
