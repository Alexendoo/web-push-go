package webpush

import "testing"

import "github.com/stretchr/testify/assert"

import "math/big"

var exampleSubJSON = []byte(`{
	"endpoint": "https://push.example.org/send/9c9e16f1f0fbaa72681f0b493fe4bbc8",
	"expirationTime": null,
	"keys": {
		"p256dh": "BFAbUTdWu_gXM-57azWgWzYRTNDdP7v4QvEc63EkwXXgjGqEmUr7JxJHzYHN4EC-lKtVGr-JGuoqqLoGhKiZGmE=",
		"auth": "om_SqHkOn12XnvA6TpUTyQ=="
	}
}`)

func exampleSub() *Subscription {
	y, _ := new(big.Int).SetString("63511999753809847319446335364963394696607820190280135457451840012629443156577", 10)
	x, _ := new(big.Int).SetString("36233293290795667263549011760586720844885702477498546711317445295524628493792", 10)

	return &Subscription{
		Endpoint: "https://push.example.org/send/9c9e16f1f0fbaa72681f0b493fe4bbc8",
		Auth:     []byte{162, 111, 210, 168, 121, 14, 159, 93, 151, 158, 240, 58, 78, 149, 19, 201},
		P256DH:   &PublicKey{x, y},
	}
}

func TestUnmarshalSubscription(t *testing.T) {
	assert := assert.New(t)

	actual, err := UnmarshalSubscription(exampleSubJSON)
	assert.NoError(err)

	assert.Equal(exampleSub(), actual)
}
