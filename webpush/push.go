package webpush

import (
	"bytes"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

var (
	p256 = elliptic.P256()
)

func randBytes(len int) ([]byte, error) {
	buf := make([]byte, len)

	_, err := rand.Read(buf)

	return buf, err
}

// Subscription is a User Agent's push message subscription
//
// - https://www.w3.org/TR/push-api/#dom-pushsubscription
type Subscription struct {
	Endpoint string

	Auth   []byte
	P256DH *PublicKey
}

// PublicKey is a point (X, Y) on the P-256 curve
type PublicKey struct {
	X, Y *big.Int
}

type KeyPair struct {
	Pub  *PublicKey
	Priv []byte
}

// Encrypt a ...
//
// - https://tools.ietf.org/html/rfc8291#section-3.4
func Encrypt(sub *Subscription) error {
	// auth_secret = <from user agent>
	authSecret := sub.Auth

	if length := len(authSecret); length != 16 {
		return fmt.Errorf("webpush: invalid auth length %d", length)
	}

	uaPub := sub.P256DH

	as, err := generateKeyPair(p256)
	if err != nil {
		return err
	}

	// ecdh_secret = ECDH(as_private, ua_public)
	ecdhSecret := ecdh(as.Priv, uaPub.X, uaPub.Y)

	// salt = random(16)
	salt, err := randBytes(16)
	if err != nil {
		return err
	}

	keyInfo := combineSecrets(authSecret, ecdhSecret, uaPub, as.Pub)

	// TODO: got to about here
	// Read: https://github.com/web-push-libs/ecec#what-is-encrypted-content-coding

	// HKDF-Extract(salt=auth_secret, IKM=ecdh_secret)
	prkKey := hmacSha256(authSecret, ecdhSecret)

	// HKDF-Expand(PRK_key, key_info, L_key=32)
	ikm := hmacSha256(prkKey, append(keyInfo, 0x01))

	fmt.Println(salt, ikm)

	return nil
}

func generateKeyPair(curve elliptic.Curve) (*KeyPair, error) {
	priv, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	pub := &PublicKey{x, y}

	return &KeyPair{pub, priv}, err
}

// Establish a shared secret between the given public key (publicX, publicY)
// and secret
//
// - https://tools.ietf.org/html/rfc8291#section-3.1
// - https://en.wikipedia.org/wiki/Elliptic-curve_Diffie–Hellman
func ecdh(secret []byte, publicX, publicY *big.Int) []byte {
	sharedX, _ := p256.ScalarMult(publicX, publicY, secret)

	return sharedX.Bytes()
}

// https://tools.ietf.org/html/rfc8291#section-3.3
func combineSecrets(authSecret, echdSecret []byte, uaPub, asPub *PublicKey) []byte {
	// "WebPush: info" || 0x00
	keyInfo := bytes.NewBuffer([]byte("WebPush: info\x00"))

	// ua_public
	uaPubBytes := elliptic.Marshal(p256, uaPub.X, uaPub.Y)
	keyInfo.Write(uaPubBytes)

	// as_public
	asPubBytes := elliptic.Marshal(p256, asPub.X, asPub.Y)
	keyInfo.Write(asPubBytes)

	return keyInfo.Bytes()
}

func hmacSha256(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)

	return mac.Sum(nil)
}
