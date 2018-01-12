package webpush

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
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

// We have to implement the expired draft-01, since Chrome does not support the
// current specification
// https://tools.ietf.org/html/draft-ietf-webpush-vapid-01
// https://bugs.chromium.org/p/chromium/issues/detail?id=712776
func vapidHeader(req *http.Request, priv *ecdsa.PrivateKey) error {
	buf := &bytes.Buffer{}
	buf.Write([]byte("WebPush "))

	jwt, err := buildJWT(req.URL, priv)
	if err != nil {
		return err
	}
	jwt.WriteTo(buf)

	req.Header.Set("Authorization", buf.String())

	// public key
	buf.Reset()
	buf.Write([]byte("p256ecdsa="))

	pub := elliptic.Marshal(p256, priv.X, priv.Y)

	pubB64 := make([]byte, base64.RawURLEncoding.EncodedLen(len(pub)))
	base64.RawURLEncoding.Encode(pubB64, pub)

	buf.Write(pubB64)

	req.Header.Set("Crypto-Key", buf.String())

	return nil
}

// https://tools.ietf.org/html/rfc8292#section-2
func buildJWT(url *url.URL, priv *ecdsa.PrivateKey) (*bytes.Buffer, error) {
	jwt := &bytes.Buffer{}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256"}`))
	jwt.WriteString(header)

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

	jwt.WriteByte('.')
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

	jwt.WriteByte('.')
	jwt.Write(sigB64)

	return jwt, nil
}

func getOrigin(url *url.URL) string {
	return url.Scheme + "://" + url.Host
}
