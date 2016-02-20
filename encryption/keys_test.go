package encryption

import (
	"fmt"
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

	if !reflect.DeepEqual(decodedKey.PrivateKey, key.PrivateKey) {
		t.Error("Decoded Pem does not matched orginal privateKey")
	}
	if !reflect.DeepEqual(decodedKey.PublicKey, key.PublicKey) {
		t.Error("Decoded Pem does not matched orginal publicKey")
	}
	if decodedErr != nil {
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

	if !reflect.DeepEqual(decodedKey.PublicKey, key.PublicKey) {
		t.Error("Decoded PublicKey does not matched orginal key.PublicKey")
	}
	if decodedKey.PrivateKey != nil {
		t.Error("PrivateKey was also decoded")
	}
	if decodedErr != nil {
		t.Error("Decoding failed", decodedErr)
	}
	fmt.Println(decodedKey.PrivateKey)
}

func TestInvalidBitkeyGeneration(t *testing.T) {
	_, err := GenerateKeyPair(1)
	if err != nil {
	} else {
		t.Error(err)
	}
}
