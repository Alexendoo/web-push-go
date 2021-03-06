package webpush

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math/big"
)

var (
	p256 = elliptic.P256()
)

// PublicKey is a point (X, Y) on the P-256 curve
type PublicKey struct {
	X, Y *big.Int
}

type KeyPair struct {
	Pub  *PublicKey
	Priv []byte
}

type eceInfo struct {
	salt  []byte
	cek   []byte
	nonce []byte
}

// - https://tools.ietf.org/html/rfc8291#section-3.4
func getEceInfo(sub *Subscription, as *KeyPair, salt []byte) *eceInfo {
	ecdhSecret := ecdh(as.Priv, sub.P256DH.X, sub.P256DH.Y)

	ikm := combineSecrets(sub.Auth, ecdhSecret, sub.P256DH, as.Pub)

	// HKDF-Extract(salt, IKM)
	prk := hmacSha256(salt, ikm)

	// HKDF-Expand(PRK, cek_info, L_cek=16)
	cekInfo := []byte("Content-Encoding: aes128gcm\x00\x01")
	cek := hmacSha256(prk, cekInfo)[:16]

	// HKDF-Expand(PRK, nonce_info, L_nonce=12)
	nonceInfo := []byte("Content-Encoding: nonce\x00\x01")
	nonce := hmacSha256(prk, nonceInfo)[:12]

	return &eceInfo{
		salt:  salt,
		cek:   cek,
		nonce: nonce,
	}
}

func randomBytes(len int) ([]byte, error) {
	buf := make([]byte, len)

	_, err := rand.Read(buf)

	return buf, err
}

func generateKey(curve elliptic.Curve) (*KeyPair, error) {
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

	// HKDF-Extract(salt=auth_secret, IKM=ecdh_secret)
	prkKey := hmacSha256(authSecret, echdSecret)

	// HKDF-Expand(PRK_key, key_info, L_key=32)
	keyInfo.WriteByte(0x01)
	ikm := hmacSha256(prkKey, keyInfo.Bytes())

	return ikm
}

func hmacSha256(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)

	return mac.Sum(nil)
}

func aes128gcm(plaintext []byte, info *eceInfo) ([]byte, error) {
	block, err := aes.NewCipher(info.cek)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// padding delimeter
	plaintext = append(plaintext, 0x02)

	ciphertext := aesgcm.Seal(nil, info.nonce, plaintext, nil)

	return ciphertext, nil
}

func encrypt(sub *Subscription, keypair *KeyPair, message, salt []byte, opts *Options) (io.Reader, error) {
	pubBytes, err := keypair.Pub.MarshalBinary()
	if err != nil {
		return nil, err
	}

	info := getEceInfo(sub, keypair, salt)

	ciphertext, err := aes128gcm(message, info)
	if err != nil {
		return nil, err
	}

	buf := &bytes.Buffer{}

	// Header - https://tools.ietf.org/html/rfc8188#section-2.1
	buf.Write(info.salt)

	rs := make([]byte, 4)
	rsLen := uint32(max(4096, len(ciphertext)))
	binary.BigEndian.PutUint32(rs, rsLen)
	buf.Write(rs)

	buf.WriteByte(65)
	buf.Write(pubBytes)

	// Body
	buf.Write(ciphertext)

	return buf, nil
}
