package main

import (
	"fmt"

	"github.com/dedis/crypto/abstract"
	"github.com/dedis/crypto/ed25519"
	"github.com/dedis/crypto/random"
)

// Global Variables :
var cryptoSuite = ed25519.NewAES128SHA256Ed25519(false)
var hashFunction = cryptoSuite.Hash()

type Signature struct {
	R abstract.Point
	s abstract.Scalar
}

// Implement the BinaryMarshaler interface :
func (S *Signature) MarshalBinary() ([]byte, error) {

	// Use the MarshalBinary() implementation of abstract.Scalar and abstract.Point
	bytes_R, _ := S.R.MarshalBinary()
	bytes_s, _ := S.s.MarshalBinary()

	// Append the byte-slice of R to the byte-slice of s and returns it
	bytes_Rs := append(bytes_R, bytes_s...)

	return bytes_Rs, nil

}

// Implement the BinaryUnmarshaler interface :
func (S *Signature) UnmarshalBinary(data []byte) error {

	// Retrieve the first half of the byte-slice which is the byte-slice of R
	// And the second half which is the byte-slice of s
	n := len(data)
	bytes_R := data[:n/2]
	bytes_s := data[n/2:]

	// Use the UnmarshalBinary() implementation of abstract.Scalar and abstract.Point
	S.R.UnmarshalBinary(bytes_R)
	S.s.UnmarshalBinary(bytes_s)

	return nil
}

// Implements the String() function for a nicer print, in Println() or Printf("%s") functions
func (S Signature) String() string {
	return fmt.Sprintf("(R=%s, s=%s)", S.R, S.s)
}

/*
Hash a string s and returns its scalar representation in the group
INPUT:
  s - the string to be hashed
OUTPUT:
  elem - the abstract.Scalar value of the hashed string
*/
func HashString(s string) abstract.Scalar {
	hashFunction.Reset()
	hashFunction.Write([]byte(s))
	hm := hashFunction.Sum(nil)
	// hm is a byte-slice, we wanna convert it into a scalar
	elem := cryptoSuite.Scalar().SetBytes(hm)
	return elem
}

/*
Sign a message m with the private key x, and returns the Signature S=(R,s)
INPUT:
  m - the message to be signed
  x - the private key of the signer
OUTPUT:
  S - the signature
*/
func SignMessage(m string, x abstract.Scalar) Signature {

	// Argument Checking //
	if m == "" {
		panic("Error! Cannot sign an empty string (security reasons)!")
	}
	if x.Equal(cryptoSuite.Scalar().Zero()) {
		panic("Error! Invalid private key x (=0)!")
	}
	///////////////////////

	// Pick a random scalar in the group :
	k := cryptoSuite.Scalar().Pick(random.Stream)
	R := cryptoSuite.Point().Mul(nil, k) // R = k*G <-- G the base point

	concatMessage := m + R.String() // Append "m || R"

	e := HashString(concatMessage) // Hash(m || R)

	s := cryptoSuite.Scalar().Add(k, cryptoSuite.Scalar().Mul(x, e)) // s = k + x*e

	S := Signature{R: R, s: s}
	return S
}

/*
Verify the signature S of a message m with the public key Y, and returns whether the signature is Valid or not
INPUT:
  m - the message to be authenticated
  S - the signature of the message
  Y - the public key of the signer
OUTPUT:
  check - the boolean representation of the validity of the signature
*/
func VerifySignature(m string, S Signature, Y abstract.Point) bool {

	// Argument Checking //
	if m == "" {
		panic("Error! Cannot verify an empty string (security reasons)!")
	}
	if S.R == nil || S.s == nil || S.R.Equal(cryptoSuite.Point()) || S.s.Equal(cryptoSuite.Scalar()) {
		panic("Error! Incomplete Signature!")
	}
	if Y.Equal(cryptoSuite.Point().Null()) {
		panic("Error! Invalid public key Y (=Neutral element)!")
	}
	///////////////////////

	concatMessage := m + S.R.String() // Append "m || R"

	e := HashString(concatMessage) // Hash(m || R)

	sg_v := cryptoSuite.Point().Add(S.R, cryptoSuite.Point().Mul(Y, e)) // sg_v = S.R + e*Y

	sg := cryptoSuite.Point().Mul(nil, S.s) // sg = s*G <-- The base point

	return sg_v.Equal(sg)
}

/*
Verify this signature upon the message m with the public key Y, and returns whether the signature is Valid or not
INPUT:
  m - the message to be authenticated
  S - the signature of the message
  Y - the public key of the signer
OUTPUT:
  check - the boolean representation of the validity of the signature
*/
func (S Signature) Verify(m string, Y abstract.Point) bool {
	return VerifySignature(m, S, Y)
}
