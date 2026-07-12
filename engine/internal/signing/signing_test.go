package signing

import "testing"

func TestSignVerifyRoundTrip(t *testing.T) {
	s, v, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("id=cmd-1;exp=0;set_mode=3")
	sig := s.Sign(msg)
	if !v.Verify(msg, sig) {
		t.Fatal("valid signature must verify")
	}
	if v.Verify([]byte("tampered"), sig) {
		t.Fatal("signature over different bytes must not verify")
	}
}

func TestWrongKeyFails(t *testing.T) {
	s1, _, _ := GenerateKey()
	_, v2, _ := GenerateKey()
	msg := []byte("hello")
	if v2.Verify(msg, s1.Sign(msg)) {
		t.Fatal("signature from a different key must not verify")
	}
}

func TestZeroVerifierFailsClosed(t *testing.T) {
	var v Verifier // no key
	if v.Verify([]byte("x"), []byte("y")) {
		t.Fatal("zero verifier must fail closed")
	}
}

func TestVerifierFromPublicKeyRoundTrip(t *testing.T) {
	s, v, _ := GenerateKey()
	v2, err := VerifierFromPublicKey(v.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("payload")
	if !v2.Verify(msg, s.Sign(msg)) {
		t.Fatal("rebuilt verifier must verify")
	}
	if _, err := VerifierFromPublicKey([]byte("too-short")); err == nil {
		t.Fatal("short key must error")
	}
}
