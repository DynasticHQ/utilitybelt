package encryption

import (
	"crypto/rand"
	"crypto/rsa"
)

//GenerateKeyPair will generate an RSA Private/Public Key Pair.
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	var privateKey *rsa.PrivateKey
	var publicKey *rsa.PublicKey
	var err error

	privateKey, err = rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return privateKey, publicKey, err
	}

	publicKey = &privateKey.PublicKey

	return privateKey, publicKey, err
}
