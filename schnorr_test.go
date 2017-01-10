package main

import (
	"fmt"

	"github.com/dedis/crypto/config"
	"testing"
)

func TestSignatureAllGood(t *testing.T) {

	keyPair := config.NewKeyPair(cryptoSuite)
	x := keyPair.Secret
	Y := keyPair.Public

	m := "message"

	S := SignMessage(m, x)
	check := VerifySignature(m, S, Y)

	if (check != true) {
		t.Errorf("FATAL ERROR : Can't verify a message properly sign.")
	}
}

func TestSignMessageWithWrongKey(t *testing.T) {

	keyPair := config.NewKeyPair(cryptoSuite)
	x := keyPair.Secret
	x = cryptoSuite.Scalar().Add(x, cryptoSuite.Scalar().SetInt64(2)) // x2 = x + 2
	Y := keyPair.Public

	m := "message"

	S := SignMessage(m, x)
	check := VerifySignature(m, S, Y)

	if (check != false) {
		t.Errorf("Error: Message was signed with wrong secret key, but verified with success!")
	}
}

func TestVerifySignatureWithWrongKey(t *testing.T) {

	keyPair := config.NewKeyPair(cryptoSuite)
	x := keyPair.Secret
	Y := keyPair.Public
	Y = cryptoSuite.Point().Mul(Y, cryptoSuite.Scalar().SetInt64(10)) // Y = 10*Y

	m := "message"

	S := SignMessage(m, x)
	check := VerifySignature(m, S, Y)

	if (check != false) {
		t.Errorf("Error: Message was properly signed, and verified with the wrong key with success!")
	}
}

func TestVerifySignatureOnWrongMessage(t *testing.T) {

	keyPair := config.NewKeyPair(cryptoSuite)
	x := keyPair.Secret
	Y := keyPair.Public

	m := "message"
	m2 := "not this one!"

	S := SignMessage(m, x)
	check := S.Verify(m2, Y)

	if (check != false) {
		t.Errorf("Error: Signature of the message m was verified with success upon another message!")
	}
}

func TestSignOrVerifyEmptyMessage(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic on signing or verifying an empty message!")
		}
	}()

	keyPair := config.NewKeyPair(cryptoSuite)
	x := keyPair.Secret
	Y := keyPair.Public

	m := ""

	S := SignMessage(m, x)
	S.Verify(m, Y)

}

func TestSignWithNullKey(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic on signing with a null private key!")
		}
	}()

	x := cryptoSuite.Scalar().Zero()
	m := "message"
	SignMessage(m, x)
}

func TestVerifyWithNullKey(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic on verifying with a null public key!")
		}
	}()

	keyPair := config.NewKeyPair(cryptoSuite)

	x := keyPair.Secret
	m := "message"
	Y := cryptoSuite.Point().Null()

	S := SignMessage(m, x)
	S.Verify(m, Y)
}

func TestVerifyAnIncompleteSignature(t *testing.T) {

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic on verifying an incomplete signature!")
		}
	}()

	keyPair := config.NewKeyPair(cryptoSuite)

	Y := keyPair.Public

	m := "message"

	S := Signature{R:cryptoSuite.Point(), s:cryptoSuite.Scalar()}
	VerifySignature(m, S, Y)

	S2 := Signature{R:cryptoSuite.Point().Base()}
	VerifySignature(m, S2, Y)

	S3 := Signature{s:cryptoSuite.Scalar().SetInt64(123)}
	VerifySignature(m, S3, Y)

	S4 := Signature{}
	VerifySignature(m, S4, Y)
}

func ExampleSignature_String() {

	S := Signature{R:cryptoSuite.Point().Base(), s:cryptoSuite.Scalar().SetInt64(123)}

	fmt.Println(S)
	// Output: (R=5866666666666666666666666666666666666666666666666666666666666666, s=7b)
}

func ExampleSignature_MarshalBinary() {

	S := Signature{R:cryptoSuite.Point().Base(), s:cryptoSuite.Scalar().SetInt64(44)}

	data, _ := S.MarshalBinary()
	fmt.Println(data)
	// Output: [88 102 102 102 102 102 102 102 102 102 102 102 102 102 102 102 102 102 102 102 102 102 102 102 102 102 102 102 102 102 102 102 44 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]

}

func ExampleSignature_UnmarshalBinary() {

	S := Signature{R:cryptoSuite.Point().Base(), s:cryptoSuite.Scalar().SetInt64(44)}

	data := []byte{88,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,102,44,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}

	sig := Signature{cryptoSuite.Point(), cryptoSuite.Scalar().SetInt64(0)}
	sig.UnmarshalBinary(data)

	fmt.Println(sig.R.Equal(S.R))
	fmt.Println(sig.s.Equal(S.s))
	// Output:
	// true
	// true
}

// Example of multiple cases struct for unit testing :

//func TestBaseexample(t *testing.T) {
//	var fibTests = []struct {
//		n        int  // input (in)
//		expected int  // expected result (want)
//	}{
//		{1, 1},
//		{2, 1},
//		{3, 2},
//		{4, 3},
//		{5, 5},
//		{6, 8},
//		{7, 13},
//	}
//
//
//	for _, tt := range fibTests {
//		actual := Fib(tt.n)
//		if actual != tt.expected {
//			t.Errorf("Fib(%d): expected %d, actual %d", tt.n, tt.expected, actual)
//		}
//	}
//
//}