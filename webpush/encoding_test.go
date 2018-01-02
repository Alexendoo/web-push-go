package webpush

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnmarshalSubscription(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		subJSON := []byte(`{
			"endpoint": "https://push.example.org/send/9c9e16f1f0fbaa72681f0b493fe4bbc8",
			"expirationTime": null,
			"keys": {
				"p256dh": "BFAbUTdWu_gXM-57azWgWzYRTNDdP7v4QvEc63EkwXXgjGqEmUr7JxJHzYHN4EC-lKtVGr-JGuoqqLoGhKiZGmE=",
				"auth": "om_SqHkOn12XnvA6TpUTyQ=="
			}
		}`)

		y, _ := new(big.Int).SetString("63511999753809847319446335364963394696607820190280135457451840012629443156577", 10)
		x, _ := new(big.Int).SetString("36233293290795667263549011760586720844885702477498546711317445295524628493792", 10)

		expected := &Subscription{
			Endpoint: "https://push.example.org/send/9c9e16f1f0fbaa72681f0b493fe4bbc8",
			Auth:     []byte{162, 111, 210, 168, 121, 14, 159, 93, 151, 158, 240, 58, 78, 149, 19, 201},
			P256DH:   &PublicKey{x, y},
		}

		actual, err := UnmarshalSubscription(subJSON)
		assert.NoError(t, err)

		assert.Equal(t, expected, actual)
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		subJSON := []byte(`{`)

		sub, err := UnmarshalSubscription(subJSON)
		assert.Nil(t, sub)
		assert.Error(t, err)
	})

	t.Run("InvalidAuth", func(t *testing.T) {
		// 15 byte auth, wants 16
		subJSON := []byte(`{
			"endpoint": "https://push.example.org/send/8b905737d1017a93f93e32837fe1e010",
			"expirationTime": null,
			"keys": {
				"p256dh": "BOucsUUmOQbDJpb18pmk1SqFdtfz2a0RCptX-6iBcIIeIn6Oy2hLJW0nhDLLbd-NzagSu3C9u2T-LVATsLDJG4U=",
				"auth": "_8IrmZy3zZ3o7MyDsLXr"
			}
		}`)

		sub, err := UnmarshalSubscription(subJSON)
		assert.Nil(t, sub)
		assert.Error(t, err)
	})

	t.Run("InvalidP256", func(t *testing.T) {
		subJSON := []byte(`{
			"endpoint": "https://push.example.org/send/c1d7c374fd0197522a41c0331ca8cfbb",
			"expirationTime": null,
			"keys": {
				"auth": "aBhowTaKPIeMWjjBy_xNWA=="
			}
		}`)

		sub, err := UnmarshalSubscription(subJSON)
		assert.Nil(t, sub)
		assert.Error(t, err)
	})
}
