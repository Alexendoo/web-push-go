package webpush

import "testing"
import "encoding/base64"
import "github.com/stretchr/testify/assert"

func atob(a string) []byte {
	out, err := base64.RawURLEncoding.DecodeString(a)
	if err != nil {
		panic(err)
	}

	return out
}

func btoa(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func Test_getEceInfo(t *testing.T) {
	assert := assert.New(t)

	asPub := &PublicKey{}
	asPub.UnmarshalBinary(atob("BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"))

	as := &KeyPair{
		Pub:  asPub,
		Priv: atob("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"),
	}

	uaPub := &PublicKey{}
	uaPub.UnmarshalBinary(atob("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"))
	sub := &Subscription{
		Auth:     atob("BTBZMqHH6r4Tts7J_aSIgg"),
		Endpoint: "https://example.org/push",
		P256DH:   uaPub,
	}

	salt := atob("DGv6ra1nlYgDCS1FRnbzlw")

	h := getEceInfo(sub, as, salt)

	assert.Equal(atob("oIhVW04MRdy2XN9CiKLxTg"), h.cek)
	assert.Equal(atob("4h_95klXJ5E_qnoN"), h.nonce)
}
