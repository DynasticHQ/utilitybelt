package encryption

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

//EncodePrivateKey Returns the PEM encoded format in bytes.
//Ready to write to disk
//-----BEGIN Type-----
//Headers
//base64-encoded Bytes
//-----END Type-----
func EncodePrivateKey(privateKey *rsa.PrivateKey) []byte {
	privASN1 := x509.MarshalPKCS1PrivateKey(privateKey)
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
func EncodePublicKey(publicKey *rsa.PublicKey) ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(publicKey)
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
func DecodePem(asn1Der []byte) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	var privateKey *rsa.PrivateKey
	var publicKey *rsa.PublicKey
	var decodedBlock *pem.Block
	var err error

	decodedBlock, _ = pem.Decode(asn1Der)
	if decodedBlock == nil || decodedBlock.Type != "RSA PRIVATE KEY" {
		err = errors.New("No valid PEM data found")
		return privateKey, publicKey, err
	}

	privateKey, err = x509.ParsePKCS1PrivateKey(decodedBlock.Bytes)
	if err != nil {
		return privateKey, publicKey, err
	}

	publicKey = &privateKey.PublicKey

	return privateKey, publicKey, err
}
