/*
Package webpush implements the message encryption required by the Web Push protocol
*/
package webpush

import (
	"net/http"
)

// Subscription is a User Agent's push message subscription
//
//  - https://www.w3.org/TR/push-api/#dom-pushsubscription
type Subscription struct {
	// The push endpoint URL, unique to the given push subscription
	Endpoint string
	// 16 random bytes generated by the user agent, called auth_secret in the
	// RFC 8291 encryption summary
	Auth []byte
	// The P-256 public key generated by the User Agent
	P256DH *PublicKey
}

// New encrypts the message and creates a HTTP request that will submit it to
// the push endpoint
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