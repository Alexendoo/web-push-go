package webpush

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	assert := assert.New(t)

	endpoint := "http://example.org/push/a43c6e6090e9c2fcdbfe"
	auth, err := randomBytes(16)
	assert.NoError(err)

	kp, err := generateKey(p256)
	assert.NoError(err)

	sub := &Subscription{endpoint, auth, kp.Pub}

	message := []byte("hello world!")

	req, err := New(sub, message)
	assert.NoError(err)
	assert.NotNil(req)

	assert.Equal("example.org", req.Host)
	assert.Equal("POST", req.Method)
	assert.Equal(endpoint, req.URL.String())

	// 86 header bytes, 1 padding byte, 16 from AED_AES_128_GCM
	// https://tools.ietf.org/html/rfc8291#section-4
	assert.EqualValues(len(message)+86+1+16, req.ContentLength)
}
