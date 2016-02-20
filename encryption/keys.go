package encryption

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type Key struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Bits       int
}

func (key *Key) Sign(payLoad []byte) ([]byte, error) {
	rng := rand.Reader
	signedPayload := sha256.Sum256(payLoad)

	signature, err := rsa.SignPKCS1v15(rng, key.PrivateKey, crypto.SHA256, signedPayload[:])
	return signature, err
}

//EncodePrivateKey Returns the PEM encoded format in bytes.
//Ready to write to disk
//-----BEGIN Type-----
//Headers
//base64-encoded Bytes
//-----END Type-----
func (key *Key) EncodePrivateKey() []byte {
	privASN1 := x509.MarshalPKCS1PrivateKey(key.PrivateKey)
	pemData := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privASN1,
		},
	)
	return pemData
}

//EncodePublicKey Returns the PEM encoded format in bytes.
//Ready to write to disk
//-----BEGIN Type-----
//Headers
//base64-encoded Bytes
//-----END Type-----
func (key *Key) EncodePublicKey() ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(key.PublicKey)
	if err != nil {
		return pubASN1, err
	}
	pemData := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubASN1,
		},
	)
	return pemData, err
}

//DecodePrivateKey will decode an ASN1 der encoded form into a Private and Public key
func DecodePem(asn1Der []byte) (*Key, error) {
	key := &Key{}
	var decodedBlock *pem.Block
	var err error

	decodedBlock, _ = pem.Decode(asn1Der)
	if decodedBlock == nil || decodedBlock.Type != "RSA PRIVATE KEY" {
		err = errors.New("No valid PEM data found")
		return key, err
	}

	key.PrivateKey, err = x509.ParsePKCS1PrivateKey(decodedBlock.Bytes)
	if err != nil {
		return key, err
	}

	key.PublicKey = &key.PrivateKey.PublicKey

	return key, err
}

//GenerateKeyPair will generate an RSA Private/Public Key Pair.
func GenerateKeyPair(bits int) (*Key, error) {
	key := &Key{
		Bits: bits,
	}
	var err error

	key.PrivateKey, err = rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return key, err
	}

	key.PublicKey = &key.PrivateKey.PublicKey

	return key, err
}
