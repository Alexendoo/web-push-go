package webpush

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"time"
)

type claims struct {
	Audience string `json:"aud"`
	Expiry   int64  `json:"exp"`
	// TODO
	// Subject  string `json:"sub,omitempty"`
}

func GenerateSigningKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(p256, rand.Reader)
}

func vapidHeader(url *url.URL, priv *ecdsa.PrivateKey) (string, error) {
	buf := &bytes.Buffer{}

	// Token parameter || header || field seperator
	// 't=' || base64('{"alg":"ES256"}') || '.'
	// https://tools.ietf.org/html/rfc7515#appendix-A.3.1
	buf.Write([]byte("t=eyJhbGciOiJFUzI1NiJ9."))

	// Claims
	c := &claims{
		Audience: getOrigin(url),
		Expiry:   time.Now().Add(1 * time.Hour).Unix(),
	}

	claimsJSON, err := json.Marshal(c)
	if err != nil {
		return "", err
	}

	claimsB64 := make([]byte, base64.RawURLEncoding.EncodedLen(len(claimsJSON)))
	base64.RawURLEncoding.Encode(claimsB64, claimsJSON)

	buf.Write(claimsB64)

	// Signature
	sum := sha256.Sum256(buf.Bytes())
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		return "", err
	}

	sig := append(r.Bytes(), s.Bytes()...)

	sigB64 := make([]byte, base64.RawURLEncoding.EncodedLen(len(sig)))
	base64.RawURLEncoding.Encode(sigB64, sig)

	buf.WriteByte('.') // second field seperator
	buf.Write(sigB64)

	// Public key parameter
	buf.Write([]byte(" k="))

	// public key
	buf.Write(elliptic.Marshal(p256, priv.X, priv.Y))

	return buf.String(), nil
}

func getOrigin(url *url.URL) string {
	return url.Scheme + "://" + url.Host
}
