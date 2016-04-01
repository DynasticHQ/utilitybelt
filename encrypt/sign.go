package encrypt

import (
	"crypto/hmac"
	"crypto/sha256"
)

//Sign will create a signature off of the secret and message.
func Sign(payload, secret string) []byte {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(payload))
	return h.Sum(nil)
}

//Verify will return True if the message signature is validated.
func Verify(payload, secret string, signature []byte) bool {
	payloadSignature := Sign(payload, secret)
	return hmac.Equal(payloadSignature, signature)
}
