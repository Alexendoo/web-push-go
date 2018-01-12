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

// https://tools.ietf.org/html/rfc8292
func vapidHeader(url *url.URL, priv *ecdsa.PrivateKey) (string, error) {
	buf := &bytes.Buffer{}
	buf.Write([]byte("vapid t="))

	jwt, err := buildJWT(url, priv)
	if err != nil {
		return "", err
	}
	jwt.WriteTo(buf)

	// Public key parameter
	buf.Write([]byte(",k="))

	// public key
	pub := elliptic.Marshal(p256, priv.X, priv.Y)

	pubB64 := make([]byte, base64.RawURLEncoding.EncodedLen(len(pub)))
	base64.RawURLEncoding.Encode(pubB64, pub)

	buf.Write(pubB64)

	return buf.String(), nil
}

// https://tools.ietf.org/html/rfc8292#section-2
func buildJWT(url *url.URL, priv *ecdsa.PrivateKey) (*bytes.Buffer, error) {
	jwt := &bytes.Buffer{}

	// base64({"alg":"ES256"}) || .
	// https://tools.ietf.org/html/rfc7515#appendix-A.3.1
	jwt.Write([]byte("eyJhbGciOiJFUzI1NiJ9."))

	// Claims
	c := &claims{
		Audience: getOrigin(url),
		Expiry:   time.Now().Add(1 * time.Hour).Unix(),
	}

	claimsJSON, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}

	claimsB64 := make([]byte, base64.RawURLEncoding.EncodedLen(len(claimsJSON)))
	base64.RawURLEncoding.Encode(claimsB64, claimsJSON)

	jwt.Write(claimsB64)

	// Signature
	sum := sha256.Sum256(jwt.Bytes())
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		return nil, err
	}

	sig := append(r.Bytes(), s.Bytes()...)

	sigB64 := make([]byte, base64.RawURLEncoding.EncodedLen(len(sig)))
	base64.RawURLEncoding.Encode(sigB64, sig)

	jwt.WriteByte('.') // second field seperator
	jwt.Write(sigB64)

	return jwt, nil
}

func getOrigin(url *url.URL) string {
	return url.Scheme + "://" + url.Host
}
