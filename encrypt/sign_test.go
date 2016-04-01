package encrypt

import "testing"

const sharedSecret = "this is cool"

func TestMessageSigningAndVerify(t *testing.T) {
	payload := "I need to be signed"
	signature := Sign(payload, sharedSecret)
	badPayload := "I dont want to be signed"

	switch {
	//Fail if this does not return True.
	case !Verify(payload, sharedSecret, signature):
		t.Error("Signature is invalid")

	//Compare a badPayload to a good signature and fail if the Verify function succeeds.
	case Verify(badPayload, sharedSecret, signature):
		t.Error("This signature definitely should not match")
	}
}
