package encryption

import (
	"reflect"
	"testing"
)

func TestGeneratedEncodingDecoding(t *testing.T) {
	privateKey, publicKey, err := GenerateKeyPair(2048)
	if err != nil {
		t.Error(err)
	}
	encodedPrivate := EncodePrivateKey(privateKey)
	//encodedPublic, err := EncodePublicKey(publicKey)
	if err != nil {
		t.Error(err)
	}

	decodedPrivateKey, decodedPublicKey, decodedErr := DecodePem(encodedPrivate)

	if !reflect.DeepEqual(decodedPrivateKey, privateKey) {
		t.Error("Decoded Pem does not matched orginal privateKey")
	}
	if !reflect.DeepEqual(decodedPublicKey, publicKey) {
		t.Error("Decoded Pem does not matched orginal publicKey")
	}
	if decodedErr != nil {
		t.Error("Decoding failed", decodedErr)
	}

}

func TestInvalidBitkeyGeneration(t *testing.T) {
	_, _, err := GenerateKeyPair(1)
	if err != nil {
	} else {
		t.Error(err)
	}
}
