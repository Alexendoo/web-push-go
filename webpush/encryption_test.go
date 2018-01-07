package webpush

import (
	"encoding/base64"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

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

// Test data from:
// - https://tools.ietf.org/html/rfc8291#section-5
// - https://tools.ietf.org/html/rfc8291#appendix-A
func Test_encryption(t *testing.T) {

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
		Endpoint: "https://push.example.net/push/JzLQ3raZJfFBR0aqvOMsLrt54w4rJUsV",
		P256DH:   uaPub,
	}

	salt := atob("DGv6ra1nlYgDCS1FRnbzlw")
	message := atob("V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24")

	reader, err := encrypt(sub, as, message, salt, nil)
	assert.NoError(err)

	body, err := ioutil.ReadAll(reader)
	assert.NoError(err)

	expected := atob("DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN")
	assert.EqualValues(expected, body)
}
