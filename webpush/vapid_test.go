package webpush

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/dgrijalva/jwt-go.v3"
)

func TestVapid(t *testing.T) {
	assert := assert.New(t)

	req := httptest.NewRequest(http.MethodPost, "https://example.org/abc", nil)
	p, err := GenerateSigningKey()
	assert.NoError(err)

	err = vapidHeader(req, p)
	assert.NoError(err)

	tokenString := strings.Split(req.Header.Get("Authorization"), " ")[1]
	assert.NotEmpty(tokenString)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		assert.Equal(jwt.SigningMethodES256, token.Method)

		pubString := strings.Split(req.Header.Get("Crypto-Key"), "=")[1]
		assert.NotEmpty(pubString)

		x, y := elliptic.Unmarshal(p256, atob(pubString))
		assert.NotNil(x)

		pub := &ecdsa.PublicKey{
			Curve: p256,
			X:     x, Y: y,
		}

		return pub, nil
	})
	assert.NoError(err)

	assert.EqualValues("https://example.org", token.Claims.(jwt.MapClaims)["aud"])

	assert.True(token.Valid)
	assert.NoError(token.Claims.Valid())
}
