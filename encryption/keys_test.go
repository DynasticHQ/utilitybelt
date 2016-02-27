package encryption

import (
	"reflect"
	"testing"
)

func TestGeneratedEncodingDecoding(t *testing.T) {
	key, err := GenerateKeyPair(2048)
	if err != nil {
		t.Error(err)
	}
	encodedPrivate := key.EncodePrivateKey()
	//encodedPublic, err := EncodePublicKey(publicKey)
	if err != nil {
		t.Error(err)
	}

	decodedKey, decodedErr := DecodePem(encodedPrivate)

	switch {

	case !reflect.DeepEqual(decodedKey.PrivateKey, key.PrivateKey):
		t.Error("Decoded Pem does not matched orginal privateKey")

	case !reflect.DeepEqual(decodedKey.PublicKey, key.PublicKey):
		t.Error("Decoded Pem does not matched orginal publicKey")

	case decodedErr != nil:
		t.Error("Decoding failed", decodedErr)
	}

}

func TestDecodeOfPublicKeyOnly(t *testing.T) {
	key, err := GenerateKeyPair(2048)
	if err != nil {
		t.Error(err)
	}
	encodedPublic, err := key.EncodePublicKey()
	if err != nil {
		t.Error(err)
	}

	decodedKey, decodedErr := DecodePublicKey(encodedPublic)

	switch {

	case !reflect.DeepEqual(decodedKey.PublicKey, key.PublicKey):
		t.Error("Decoded PublicKey does not matched orginal key.PublicKey")

	case decodedKey.PrivateKey != nil:
		t.Error("PrivateKey was also decoded")

	case decodedErr != nil:
		t.Error("Decoding failed", decodedErr)
	}
}

func TestInvalidBitkeyGeneration(t *testing.T) {
	_, err := GenerateKeyPair(1)
	if err != nil {
	} else {
		t.Error(err)
	}
}

func TestMessageSigningAndValidation(t *testing.T) {
	key, err := GenerateKeyPair(2048)
	if err != nil {
		t.Error(err)
	}

	goodPayload := []byte("This is a good test")
	badPayload := []byte("This is a bad test")

	goodSignature, goodSigErr := key.Sign(goodPayload)

	switch {

	case goodSigErr != nil:
		t.Error(goodSigErr)

	case !key.VerifySignature(goodSignature, goodPayload):
		t.Error("InvalidSignature")

	case key.VerifySignature(goodSignature, badPayload):
		t.Error("Validated incorrect signature")
	}

}
