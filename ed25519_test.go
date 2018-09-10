// Copyright 2016 The Go Authors
// Copyright 2018 The Hyperspace Developers
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ed25519

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/HyperspaceApp/ed25519/internal/edwards25519"
)

type zeroReader struct{}

func (zeroReader) Read(buf []byte) (int, error) {
	for i := range buf {
		buf[i] = 0
	}
	return len(buf), nil
}

type oneReader struct{}

func (oneReader) Read(buf []byte) (int, error) {
	for i := range buf {
		buf[i] = 1
	}
	return len(buf), nil
}

type twoReader struct{}

func (twoReader) Read(buf []byte) (int, error) {
	for i := range buf {
		buf[i] = 2
	}
	return len(buf), nil
}

func TestUnmarshalMarshal(t *testing.T) {
	pub, _, _ := GenerateKey(rand.Reader)

	var A edwards25519.ExtendedGroupElement
	var pubBytes [32]byte
	copy(pubBytes[:], pub)
	if !A.FromBytes(&pubBytes) {
		t.Fatalf("ExtendedGroupElement.FromBytes failed")
	}

	var pub2 [32]byte
	A.ToBytes(&pub2)

	if pubBytes != pub2 {
		t.Errorf("FromBytes(%v)->ToBytes does not round-trip, got %x\n", pubBytes, pub2)
	}
}

func TestSignVerify(t *testing.T) {
	var zero zeroReader
	public, private, _ := GenerateKey(zero)

	message := []byte("test message")
	sig := Sign(private, message)
	if !Verify(public, message, sig) {
		t.Errorf("valid signature rejected")
	}

	wrongMessage := []byte("wrong message")
	if Verify(public, wrongMessage, sig) {
		t.Errorf("signature of different message accepted")
	}
}

func TestCryptoSigner(t *testing.T) {
	var zero zeroReader
	public, private, _ := GenerateKey(zero)

	signer := crypto.Signer(private)

	publicInterface := signer.Public()
	public2, ok := publicInterface.(PublicKey)
	if !ok {
		t.Fatalf("expected PublicKey from Public() but got %T", publicInterface)
	}

	if !bytes.Equal(public, public2) {
		t.Errorf("public keys do not match: original:%x vs Public():%x", public, public2)
	}

	message := []byte("message")
	var noHash crypto.Hash
	signature, err := signer.Sign(zero, message, noHash)
	if err != nil {
		t.Fatalf("error from Sign(): %s", err)
	}

	if !Verify(public, message, signature) {
		t.Errorf("Verify failed on signature from Sign()")
	}
}

func TestGolden(t *testing.T) {
	// sign.input.gz is a selection of test cases from
	// https://ed25519.cr.yp.to/python/sign.input
	testDataZ, err := os.Open("testdata/sign.input.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer testDataZ.Close()
	testData, err := gzip.NewReader(testDataZ)
	if err != nil {
		t.Fatal(err)
	}
	defer testData.Close()

	scanner := bufio.NewScanner(testData)
	lineNo := 0

	for scanner.Scan() {
		lineNo++

		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) != 5 {
			t.Fatalf("bad number of parts on line %d", lineNo)
		}

		privBytes, _ := hex.DecodeString(parts[0])
		pubKey, _ := hex.DecodeString(parts[1])
		msg, _ := hex.DecodeString(parts[2])
		sig, _ := hex.DecodeString(parts[3])
		// The signatures in the test vectors also include the message
		// at the end, but we just want R and S.
		sig = sig[:SignatureSize]

		if l := len(pubKey); l != PublicKeySize {
			t.Fatalf("bad public key length on line %d: got %d bytes", lineNo, l)
		}

		var priv [PrivateKeySize]byte
		copy(priv[:], privBytes)
		copy(priv[32:], pubKey)

		sig2 := Sign(priv[:], msg)
		if !bytes.Equal(sig, sig2[:]) {
			t.Errorf("different signature result on line %d: %x vs %x", lineNo, sig, sig2)
		}

		if !Verify(pubKey, msg, sig2) {
			t.Errorf("signature failed to verify on line %d", lineNo)
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("error reading test data: %s", err)
	}
}

func BenchmarkKeyGeneration(b *testing.B) {
	var zero zeroReader
	for i := 0; i < b.N; i++ {
		if _, _, err := GenerateKey(zero); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSigning(b *testing.B) {
	var zero zeroReader
	_, priv, err := GenerateKey(zero)
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sign(priv, message)
	}
}

func BenchmarkVerification(b *testing.B) {
	var zero zeroReader
	pub, priv, err := GenerateKey(zero)
	if err != nil {
		b.Fatal(err)
	}
	message := []byte("Hello, world!")
	signature := Sign(priv, message)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(pub, message, signature)
	}
}

func TestJointSignVerify(t *testing.T) {
	var zero zeroReader
	var one oneReader
	public0, private0, _ := GenerateKey(zero)
	public1, private1, _ := GenerateKey(one)
	var jointPrivate0, jointPrivate1 PrivateKey
	var err error
	pubkeys := []PublicKey{public0, public1}
	jointPrivate0, err = GenerateJointPrivateKey(pubkeys, private0, 0)
	if err != nil {
		t.Fatal(err)
	}
	jointPrivate1, err = GenerateJointPrivateKey(pubkeys, private1, 1)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("Hello, world!")
	noncePoint0 := GenerateNoncePoint(private0, message)
	noncePoint1 := GenerateNoncePoint(private1, message)
	noncePoints := []CurvePoint{noncePoint0, noncePoint1}
	s0 := JointSign(private0, jointPrivate0, noncePoints, message)
	s1 := JointSign(private1, jointPrivate1, noncePoints, message)
	sig := AddSignature(s0, s1)
	jointPublicKey := make([]byte, PublicKeySize)
	jointPublicKeyBackup := make([]byte, PublicKeySize)
	copy(jointPublicKey[:], jointPrivate0[32:])
	copy(jointPublicKeyBackup[:], jointPrivate1[32:])
	if !bytes.Equal(jointPublicKey, jointPublicKeyBackup) {
		t.Fatal("created 2 different joint public keys")
	}

	// secondary test
	_, primeKeys, _ := GenerateJointKey(pubkeys)
	prime0 := primeKeys[0]
	prime1 := primeKeys[1]
	// P_A' should equal x_A' * G
	var jointPrivateKey0Bytes, prime0CheckBuffer [32]byte
	copy(jointPrivateKey0Bytes[:], jointPrivate0[:32])
	prime0Bytes := make([]byte, PublicKeySize)
	prime0CheckBytes := make([]byte, PublicKeySize)
	copy(prime0Bytes[:], prime0[:])
	var Prime0Check edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&Prime0Check, &jointPrivateKey0Bytes)
	Prime0Check.ToBytes(&prime0CheckBuffer)
	copy(prime0CheckBytes[:], prime0CheckBuffer[:])
	if !bytes.Equal(prime0Bytes, prime0CheckBytes) {
		t.Fatalf("prime 0 key improperly generated\n%v\n%v\n", prime0Bytes, prime0CheckBytes)
	}
	// P_B' should equal x_B' * G
	var jointPrivateKey1Bytes, prime1CheckBuffer [32]byte
	copy(jointPrivateKey1Bytes[:], jointPrivate1[:32])
	prime1Bytes := make([]byte, PublicKeySize)
	prime1CheckBytes := make([]byte, PublicKeySize)
	copy(prime1Bytes[:], prime1[:])
	var Prime1Check edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&Prime1Check, &jointPrivateKey1Bytes)
	Prime1Check.ToBytes(&prime1CheckBuffer)
	copy(prime1CheckBytes[:], prime1CheckBuffer[:])
	if !bytes.Equal(prime1Bytes, prime1CheckBytes) {
		t.Fatalf("prime 1 key improperly generated\n%v\n%v\n", prime1Bytes, prime1CheckBytes)
	}
	var JCheck edwards25519.ExtendedGroupElement
	// J(A, B) should equal P_A' + P_B'
	edwards25519.GeAdd(&JCheck, &Prime0Check, &Prime1Check)
	var jCheckBytesBuffer [32]byte
	jCheckBytes := make([]byte, PublicKeySize)
	JCheck.ToBytes(&jCheckBytesBuffer)
	copy(jCheckBytes[:], jCheckBytesBuffer[:])
	if !bytes.Equal(jCheckBytes, jointPublicKey) {
		t.Fatalf("joint public key improperly generated\n%v\n%v\n", jointPublicKey, jCheckBytes)
	}

	// s_agg should equal r_A + r_B + e(x_A' + x_B')
	var e, encodedR [32]byte
	var messageDigest [64]byte
	var R edwards25519.ExtendedGroupElement
	noncePoint0Element := noncePoint0.toElement()
	noncePoint1Element := noncePoint1.toElement()
	edwards25519.GeAdd(&R, &noncePoint0Element, &noncePoint1Element)
	R.ToBytes(&encodedR)
	h := sha512.New()
	h.Write(encodedR[:])
	h.Write(jointPublicKey[:])
	h.Write(message)
	h.Sum(messageDigest[:0])
	edwards25519.ScReduce(&e, &messageDigest)

	// check s_0
	r0 := GenerateNonce(private0, message)
	var checkS0Bytes [32]byte
	checkS0 := make([]byte, SignatureSize)
	edwards25519.ScMulAdd(&checkS0Bytes, &e, &jointPrivateKey0Bytes, &r0)
	copy(checkS0[32:], checkS0Bytes[:])

	// check the signatures
	if !bytes.Equal(checkS0[32:], s0[32:]) {
		t.Fatalf("signature 0 improperly generated\n%v\n%v\n", s0[32:], checkS0[32:])
	}
	var checkR0Buffer [32]byte
	checkR0 := make([]byte, 32)
	noncePoint0Element.ToBytes(&checkR0Buffer)
	copy(checkR0[:], checkR0Buffer[:])
	// check the noncepoints
	if !bytes.Equal(checkR0[:], s0[:32]) {
		t.Fatalf("signature 0 nonce point improperly generated\n%v\n%v\n", s0[:32], checkR0[:])
	}

	// check s_1
	r1 := GenerateNonce(private1, message)
	var checkS1Bytes [32]byte
	checkS1 := make([]byte, SignatureSize)
	edwards25519.ScMulAdd(&checkS1Bytes, &e, &jointPrivateKey1Bytes, &r1)
	copy(checkS1[32:], checkS1Bytes[:])

	// check the signatures
	if !bytes.Equal(checkS1[32:], s1[32:]) {
		t.Fatalf("signature 1 improperly generated\n%v\n%v\n", s1[32:], checkS1[32:])
	}
	var checkR1Buffer [32]byte
	checkR1 := make([]byte, 32)
	noncePoint1Element.ToBytes(&checkR1Buffer)
	copy(checkR1[:], checkR1Buffer[:])
	// check the noncepoints
	if !bytes.Equal(checkR1[:], s1[:32]) {
		t.Fatalf("signature 1 nonce point improperly generated\n%v\n%v\n", s1[:32], checkR1[:])
	}

	// check s_0 + s_1 == s
	var sBuffer, s0Buffer, s1Buffer [32]byte
	s := make([]byte, 32)
	copy(s0Buffer[:], s0[32:])
	copy(s1Buffer[:], s1[32:])
	edwards25519.ScAdd(&sBuffer, &s0Buffer, &s1Buffer)
	copy(s[:], sBuffer[:])
	if !bytes.Equal(sig[32:], s[:]) {
		t.Fatalf("s0 + s1 != s\n%v\n%v\n", s[:], sig[32:])
	}

	// check (r0 + r_1)B == rB
	var rBuffer, r0Buffer, r1Buffer [32]byte
	r := make([]byte, 32)
	copy(r0Buffer[:], r0[:])
	copy(r1Buffer[:], r1[:])
	edwards25519.ScAdd(&rBuffer, &r0Buffer, &r1Buffer)
	copy(r[:], rBuffer[:])
	var rB edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&rB, &rBuffer)
	var rBBuffer [32]byte
	rBBytes := make([]byte, 32)
	rB.ToBytes(&rBBuffer)
	copy(rBBytes[:], rBBuffer[:])
	if !bytes.Equal(rBBytes[:], encodedR[:]) {
		t.Fatalf("rB != R\n%v\n%v\n", rBBytes[:], encodedR[:])
	}

	// check (x0 + x1)B == A
	var x, xBBuffer [32]byte
	var xB edwards25519.ExtendedGroupElement
	edwards25519.ScAdd(&x, &jointPrivateKey0Bytes, &jointPrivateKey1Bytes)
	edwards25519.GeScalarMultBase(&xB, &x)
	xB.ToBytes(&xBBuffer)
	xBBytes := make([]byte, 32)
	copy(xBBytes[:], xBBuffer[:])
	if !bytes.Equal(xBBytes[:], jointPublicKey[:]) {
		t.Fatalf("xB != A\n%v\n%v\n", xBBytes[:], jointPublicKey[:])
	}

	// check e * A
	var hramA edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMult(&hramA, &e, &JCheck)
	var hramABuffer [32]byte
	hramA.ToBytes(&hramABuffer)
	// check sB == R + hramA
	var sB edwards25519.ExtendedGroupElement
	var sBBuffer [32]byte
	sBBytes := make([]byte, 32)
	edwards25519.GeScalarMultBase(&sB, &sBuffer)
	sB.ToBytes(&sBBuffer)
	copy(sBBytes[:], sBBuffer[:])
	var checkSB edwards25519.ExtendedGroupElement
	var checkSBBuffer [32]byte
	checkSBBytes := make([]byte, 32)
	edwards25519.GeAdd(&checkSB, &hramA, &R)
	checkSB.ToBytes(&checkSBBuffer)
	copy(checkSBBytes[:], checkSBBuffer[:])
	if !bytes.Equal(sBBytes[:], checkSBBytes[:]) {
		t.Fatalf("sB != R + hramA\n%v\n%v", sBBytes[:], checkSBBytes[:])
	}

	if !Verify(jointPublicKey, message, sig) {
		t.Fatal("Failed JointSignVerify")
	}

}

func TestJointSignWithAdaptor(t *testing.T) {
	var zero zeroReader
	var one oneReader
	var two twoReader
	public0, private0, _ := GenerateKey(zero)
	public1, private1, _ := GenerateKey(one)
	var jointPrivate0, jointPrivate1 PrivateKey
	var err error
	pubkeys := []PublicKey{public0, public1}
	jointPrivate0, err = GenerateJointPrivateKey(pubkeys, private0, 0)
	if err != nil {
		t.Fatal(err)
	}
	jointPrivate1, err = GenerateJointPrivateKey(pubkeys, private1, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, primeKeys, _ := GenerateJointKey(pubkeys)
	jointPublic1 := primeKeys[1]
	jointPublicKey := make([]byte, PublicKeySize)
	copy(jointPublicKey[:], jointPrivate0[32:])
	message := []byte("Hello, world!")
	noncePoint0 := GenerateNoncePoint(private0, message)
	noncePoint1 := GenerateNoncePoint(private1, message)
	adaptor, T, _ := GenerateAdaptor(two)
	s_0 := JointSignWithAdaptor(private0, jointPrivate0, noncePoint0, noncePoint1, T, message)
	s_1 := JointSignWithAdaptor(private1, jointPrivate1, noncePoint0, noncePoint1, T, message)
	if !VerifyAdaptorSignature(jointPublic1, jointPublicKey, noncePoint0, noncePoint1, T, message, s_1) {
		t.Fatal("Failed VerifyAdaptorSignature")
	}
	var sig0Buffer, sig1Buffer, adaptorBuffer, sigAggBuffer, rAggBuffer [32]byte
	copy(sig0Buffer[:], s_0[32:])
	copy(sig1Buffer[:], s_1[32:])
	copy(adaptorBuffer[:], adaptor[:])
	edwards25519.ScAdd(&sigAggBuffer, &sig0Buffer, &sig1Buffer)
	edwards25519.ScAdd(&sigAggBuffer, &sigAggBuffer, &adaptorBuffer)
	var buffer [64]byte
	var reducedAdaptor [32]byte
	copy(buffer[:32], adaptor[:])
	edwards25519.ScReduce(&reducedAdaptor, &buffer)
	var R, noncePoint0Element, noncePoint1Element, adaptorPointElement edwards25519.ExtendedGroupElement
	noncePoint0Element = noncePoint0.toElement()
	noncePoint1Element = noncePoint1.toElement()
	adaptorPointElement = T.toElement()
	edwards25519.GeAdd(&R, &noncePoint0Element, &noncePoint1Element)
	edwards25519.GeAdd(&R, &R, &adaptorPointElement)
	R.ToBytes(&rAggBuffer)
	aggSignature := make([]byte, SignatureSize)
	copy(aggSignature[:32], rAggBuffer[:])
	copy(aggSignature[32:], sigAggBuffer[:])
	if !Verify(jointPublicKey, message, aggSignature) {
		t.Fatal("Failed verifying the joint signature for an adaptor signature")
	}
	var checkAdaptorBuffer [32]byte
	edwards25519.ScSub(&checkAdaptorBuffer, &sigAggBuffer, &sig0Buffer)
	edwards25519.ScSub(&checkAdaptorBuffer, &checkAdaptorBuffer, &sig1Buffer)
	if !bytes.Equal(checkAdaptorBuffer[:], reducedAdaptor[:]) {
		t.Fatal("Failed to deduce adaptor from signature components")
	}
}

func TestScSub(t *testing.T) {
	var a, b, sum, result [32]byte
	var reducedA [32]byte
	var buffer [64]byte
	a[0] = 1
	b[0] = 2
	copy(buffer[:32], a[:])
	edwards25519.ScReduce(&reducedA, &buffer)
	edwards25519.ScAdd(&sum, &a, &b)
	edwards25519.ScSub(&result, &sum, &b)
	if !bytes.Equal(result[:], reducedA[:]) {
		t.Fatal("Failed ScSub")
	}
}

func TestAdaptor(t *testing.T) {
	adaptor0, adaptorPoint0, _ := GenerateAdaptor(rand.Reader)
	adaptor1, adaptorPoint1, _ := GenerateAdaptor(rand.Reader)
	var adaptor0Sc, adaptor1Sc Scalar
	adaptor0Sc = make([]byte, ScalarSize)
	adaptor1Sc = make([]byte, ScalarSize)
	copy(adaptor0Sc[:], adaptor0[:])
	copy(adaptor1Sc[:], adaptor1[:])
	scSum := adaptor0Sc.Add(adaptor1Sc)
	sumB := scSum.ToCurvePoint()
	Sum := adaptorPoint0.Add(adaptorPoint1)
	if !bytes.Equal(sumB[:], Sum[:]) {
		t.Fatal("Failed adaptor summation test")
	}
}

func TestSimpleSubtraction(t *testing.T) {
	var one oneReader
	var two twoReader
	var adaptor0Sc, adaptor1Sc, sum Scalar
	adaptor0, _, _ := GenerateAdaptor(one)
	adaptor1, _, _ := GenerateAdaptor(two)
	adaptor0Sc = make([]byte, ScalarSize)
	adaptor1Sc = make([]byte, ScalarSize)
	sum = make([]byte, ScalarSize)
	copy(adaptor0Sc[:], adaptor0[:])
	copy(adaptor1Sc[:], adaptor1[:])
	sum = adaptor0Sc.Add(adaptor1Sc)
	check := sum.Subtract(adaptor1Sc)
	if !bytes.Equal(check[:], adaptor0Sc[:]) {
		t.Fatal("Failed simple subtraction test")
	}
}

func TestAdaptorSubtraction(t *testing.T) {
	adaptor0, _, _ := GenerateAdaptor(rand.Reader)
	adaptor1, _, _ := GenerateAdaptor(rand.Reader)
	var adaptor0Sc, adaptor1Sc, sum Scalar
	adaptor0Sc = make([]byte, ScalarSize)
	adaptor1Sc = make([]byte, ScalarSize)
	sum = make([]byte, ScalarSize)
	copy(adaptor0Sc[:], adaptor0[:])
	copy(adaptor1Sc[:], adaptor1[:])
	sum = adaptor0Sc.Add(adaptor1Sc)
	check := sum.Subtract(adaptor1Sc)
	if !bytes.Equal(check[:], adaptor0Sc[:]) {
		t.Fatal("Failed subtraction test")
	}
}
