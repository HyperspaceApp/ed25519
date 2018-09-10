// Copyright 2016 The Go Authors
// Copyright 2018 The Hyperspace Developers
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ed25519 implements the Ed25519 signature algorithm. See
// https://ed25519.cr.yp.to/.
//
// These functions are also compatible with the “Ed25519” function defined in
// RFC 8032.
package ed25519

// This code is a port of the public domain, “ref10” implementation of ed25519
// from SUPERCOP.

import (
	"bytes"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/sha512"
	"errors"
	"io"
	"strconv"

	"github.com/HyperspaceApp/ed25519/internal/edwards25519"
)

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 32
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 64
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = 64
	// AdaptorSize is the size, in bytes, of secret adaptors used in adaptor signatures
	AdaptorSize = 32
	// CurvePointSize is the size, in bytes, of points on the elliptic curve
	CurvePointSize = 32
	// CurvePointSize is the size, in bytes, of a large scalar
	ScalarSize = 32
)

// PublicKey is the type of Ed25519 public keys.
type PublicKey []byte

// PrivateKey is the type of Ed25519 private keys. It implements crypto.Signer.
type PrivateKey []byte

// Adaptor is the type of secret adaptors used in adaptor signatures
type Adaptor []byte

// CurvePoint is the byte representation of a point on the elliptic curve
type CurvePoint []byte

// Scalar is the byte represenation of a large scalar
type Scalar []byte

// Public returns the PublicKey corresponding to priv.
func (priv PrivateKey) Public() crypto.PublicKey {
	publicKey := make([]byte, PublicKeySize)
	copy(publicKey, priv[32:])
	return PublicKey(publicKey)
}

// Sign signs the given message with priv.
// Ed25519 performs two passes over messages to be signed and therefore cannot
// handle pre-hashed messages. Thus opts.HashFunc() must return zero to
// indicate the message hasn't been hashed. This can be achieved by passing
// crypto.Hash(0) as the value for opts.
func (priv PrivateKey) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("ed25519: cannot sign hashed message")
	}

	return Sign(priv, message), nil
}

func (cp CurvePoint) toElement() edwards25519.ExtendedGroupElement {
	var element edwards25519.ExtendedGroupElement
	var pointBytes [32]byte
	copy(pointBytes[:], cp[:])
	if !element.FromBytes(&pointBytes) {
		panic("ed25519: unable to parse nonce point")
	}
	return element
}

func (cp CurvePoint) Add(point CurvePoint) CurvePoint {
	var newPointElement edwards25519.ExtendedGroupElement
	var newPoint CurvePoint
	cpElem1 := cp.toElement()
	cpElem2 := point.toElement()
	edwards25519.GeAdd(&newPointElement, &cpElem1, &cpElem2)
	newPoint = make([]byte, CurvePointSize)
	var newPointBuffer [CurvePointSize]byte
	newPointElement.ToBytes(&newPointBuffer)
	copy(newPoint[:], newPointBuffer[:])
	return newPoint
}

func (sc Scalar) Add(scalar Scalar) Scalar {
	var newScalar Scalar
	var s, s1, s2 [ScalarSize]byte
	copy(s1[:], sc[:])
	copy(s2[:], scalar[:])
	edwards25519.ScAdd(&s, &s1, &s2)
	newScalar = make([]byte, ScalarSize)
	copy(newScalar[:], s[:])
	return newScalar
}

func (sc Scalar) Subtract(scalar Scalar) Scalar {
	var newScalar Scalar
	var s, s1, s2 [ScalarSize]byte
	copy(s1[:], sc[:])
	copy(s2[:], scalar[:])
	edwards25519.ScSub(&s, &s1, &s2)
	newScalar = make([]byte, ScalarSize)
	copy(newScalar[:], s[:])
	return newScalar
}

func (sc Scalar) ToCurvePoint() CurvePoint {
	var newElem edwards25519.ExtendedGroupElement
	var newCurvePoint CurvePoint
	var scBuffer [ScalarSize]byte
	copy(scBuffer[:], sc[:])
	edwards25519.GeScalarMultBase(&newElem, &scBuffer)
	var newCurvePointBuffer [CurvePointSize]byte
	newElem.ToBytes(&newCurvePointBuffer)
	newCurvePoint = make([]byte, CurvePointSize)
	copy(newCurvePoint[:], newCurvePointBuffer[:])
	return newCurvePoint
}

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (publicKey PublicKey, privateKey PrivateKey, err error) {
	if rand == nil {
		rand = cryptorand.Reader
	}

	privateKey = make([]byte, PrivateKeySize)
	publicKey = make([]byte, PublicKeySize)
	_, err = io.ReadFull(rand, privateKey[:32])
	if err != nil {
		return nil, nil, err
	}

	// https://tools.ietf.org/html/rfc8032#page-13
	// Prune the buffer: The lowest three bits of the first octet are
	// cleared, the highest bit of the last octet is cleared, and the
	// second highest bit of the last octet is set.
	digest := sha512.Sum512(privateKey[:32])
	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	var A edwards25519.ExtendedGroupElement
	var hBytes [32]byte
	copy(hBytes[:], digest[:])
	edwards25519.GeScalarMultBase(&A, &hBytes)
	var publicKeyBytes [32]byte
	A.ToBytes(&publicKeyBytes)

	copy(privateKey[32:], publicKeyBytes[:])
	copy(publicKey, publicKeyBytes[:])

	return publicKey, privateKey, nil
}

// Sign signs the message with privateKey and returns a signature. It will
// panic if len(privateKey) is not PrivateKeySize.

// Signature is calculated: s = r + H(R,A,m)a
// The signature is encoded as: R || s
func Sign(privateKey PrivateKey, message []byte) []byte {
	if l := len(privateKey); l != PrivateKeySize {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}

	h := sha512.New()
	h.Write(privateKey[:32])

	var digest1, messageDigest, hramDigest [64]byte
	var expandedSecretKey [32]byte
	// hash the private key
	h.Sum(digest1[:0])
	copy(expandedSecretKey[:], digest1[:])
	// grab the first 32 bytes of the hashed private key and prune them
	// this is equivalent to the pruning above
	expandedSecretKey[0] &= 248
	// this clears the highest and second highest bit, then sets
	// the second highest bit.
	expandedSecretKey[31] &= 63
	expandedSecretKey[31] |= 64

	h.Reset()
	// take the remaining 32 bytes of the hashed private key and
	// concatenate the message to generate our random nonce
	h.Write(digest1[32:])
	h.Write(message)
	h.Sum(messageDigest[:0])

	// first do nonce % p so as to optimize multiplication
	var messageDigestReduced [32]byte
	edwards25519.ScReduce(&messageDigestReduced, &messageDigest)
	// then multiply by base point B to get the nonce point, R
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &messageDigestReduced)

	var encodedR [32]byte
	R.ToBytes(&encodedR)

	h.Reset()
	// now hash R || A || m
	h.Write(encodedR[:])
	h.Write(privateKey[32:])
	h.Write(message)
	h.Sum(hramDigest[:0])
	// take the hash result % p
	var hramDigestReduced [32]byte
	edwards25519.ScReduce(&hramDigestReduced, &hramDigest)

	var s [32]byte
	// s = H(R,A,m) * a + r
	edwards25519.ScMulAdd(&s, &hramDigestReduced, &expandedSecretKey, &messageDigestReduced)

	signature := make([]byte, SignatureSize)
	copy(signature[:], encodedR[:])
	copy(signature[32:], s[:])

	return signature
}

func GenerateNonce(privateKey PrivateKey, message []byte) [32]byte {
	if l := len(privateKey); l != PrivateKeySize {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}

	h := sha512.New()
	h.Write(privateKey[:32])

	var digest1, messageDigest [64]byte
	h.Sum(digest1[:0])

	h.Reset()
	h.Write(digest1[32:])
	h.Write(message)
	h.Sum(messageDigest[:0])

	var messageDigestReduced [32]byte
	edwards25519.ScReduce(&messageDigestReduced, &messageDigest)

	return messageDigestReduced
}

func GenerateNoncePoint(privateKey PrivateKey, message []byte) CurvePoint {
	var r [32]byte
	r = GenerateNonce(privateKey, message)
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &r)

	var curvePointBuffer [32]byte
	R.ToBytes(&curvePointBuffer)
	curvePoint := make([]byte, CurvePointSize)
	copy(curvePoint[:], curvePointBuffer[:])
	return CurvePoint(curvePoint)
}

func GenerateCurvePoint(scalar []byte) CurvePoint {
	var scalarBytes [32]byte
	var P edwards25519.ExtendedGroupElement
	copy(scalarBytes[:], scalar[:])
	edwards25519.GeScalarMultBase(&P, &scalarBytes)
	var encodedPoint [32]byte
	P.ToBytes(&encodedPoint)
	curve := make([]byte, CurvePointSize)
	copy(curve[:], encodedPoint[:])
	return CurvePoint(curve)
}

// Verify reports whether sig is a valid signature of message by publicKey. It
// will panic if len(publicKey) is not PublicKeySize.

// Verification requires sB = R + H(R,A,m)A = S
// So R = S - H(R,A,m)A
func Verify(publicKey PublicKey, message, sig []byte) bool {
	if l := len(publicKey); l != PublicKeySize {
		panic("ed25519: bad public key length: " + strconv.Itoa(l))
	}

	if len(sig) != SignatureSize || sig[63]&224 != 0 {
		return false
	}

	var A edwards25519.ExtendedGroupElement
	var publicKeyBytes [32]byte
	copy(publicKeyBytes[:], publicKey)
	if !A.FromBytes(&publicKeyBytes) {
		return false
	}
	edwards25519.FeNeg(&A.X, &A.X)
	edwards25519.FeNeg(&A.T, &A.T)

	// H(R,A,m)
	h := sha512.New()
	h.Write(sig[:32])
	h.Write(publicKey[:])
	h.Write(message)
	var digest [64]byte
	h.Sum(digest[:0])

	var hReduced [32]byte
	edwards25519.ScReduce(&hReduced, &digest)
	var hramA edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMult(&hramA, &hReduced, &A)
	var hramABuffer [32]byte
	hramA.ToBytes(&hramABuffer)

	var R edwards25519.ProjectiveGroupElement
	// b is little s
	var b [32]byte
	copy(b[:], sig[32:])
	// R = - H(R,A,m)A + sB
	edwards25519.GeDoubleScalarMultVartime(&R, &hReduced, &A, &b)

	var checkR [32]byte
	R.ToBytes(&checkR)
	return bytes.Equal(sig[:32], checkR[:])
}

// Takes n pubkeys: P1, P2, ..., Pn
// Returns n+1 pubkeys: an aggregate joint key, J, as well as
// n modified pubkeys: P'1, P'2, ..., P'n
// Implemented as described in:
// https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures.html
func GenerateJointKey(publicKeys []PublicKey) (jointKey PublicKey, primeKeys []PublicKey, err error) {
	for _, publicKey := range publicKeys {
		if l := len(publicKey); l != PublicKeySize {
			panic("ed25519: bad public key length: " + strconv.Itoa(l))
		}
	}
	var jointHash [64]byte
	primeDigests := make([][64]byte, len(publicKeys))
	h := sha512.New()

	// L = H(P1 || P2 || ... || Pn)
	for _, publicKey := range publicKeys {
		h.Write(publicKey[:])
	}
	h.Sum(jointHash[:0])

	// P'i = H(L || Pi) * Pi - here we calculate
	// primeDigests[i] = H(L || Pi)
	for i, publicKey := range publicKeys {
		h.Reset()
		h.Write(jointHash[:])
		h.Write(publicKey[:])
		h.Sum(primeDigests[i][:0])
	}

	// reduce our primeDigests to proper scalars
	primeBytesList := make([][32]byte, len(publicKeys))
	for i, primeDigest := range primeDigests {
		edwards25519.ScReduce(&primeBytesList[i], &primeDigest)
	}

	publicKeyBytesList := make([][32]byte, len(publicKeys))
	for i, publicKey := range publicKeys {
		copy(publicKeyBytesList[i][:], publicKey)
	}

	keyPrimeBytesList := make([][32]byte, len(publicKeys))
	keyPrimeList := make([]PublicKey, 0, len(publicKeys))
	// P'i = H(L || Pi) * Pi - here we calculate P'i
	// as well as J = Sum(P'i)
	PubkeyElems := make([]edwards25519.ExtendedGroupElement, len(publicKeys))
	PubkeyPrimeElems := make([]edwards25519.ExtendedGroupElement, len(publicKeys))
	for i, publicKeyBytes := range publicKeyBytesList {
		if !PubkeyElems[i].FromBytes(&publicKeyBytes) {
			return nil, nil, errors.New("ed25519: cannot build pubkey from bytes")
		}
		edwards25519.GeScalarMult(&PubkeyPrimeElems[i], &primeBytesList[i], &PubkeyElems[i])
		// convert everything to PublicKeys for return
		PubkeyPrimeElems[i].ToBytes(&keyPrimeBytesList[i])
		keyPrime := make([]byte, PublicKeySize)
		copy(keyPrime[:], keyPrimeBytesList[i][:])
		keyPrimeList = append(keyPrimeList, keyPrime)
	}

	var J edwards25519.ExtendedGroupElement
	var jointKeyBytes [32]byte
	edwards25519.GeAdd(&J, &PubkeyPrimeElems[0], &PubkeyPrimeElems[1])
	for i := 2; i < len(publicKeys); i++ {
		edwards25519.GeAdd(&J, &J, &PubkeyPrimeElems[i])
		J.ToBytes(&jointKeyBytes)
	}

	J.ToBytes(&jointKeyBytes)
	jointKey = make([]byte, PublicKeySize)
	copy(jointKey[:], jointKeyBytes[:])

	return jointKey, keyPrimeList, err
}

func GenerateJointPrivateKey(publicKeys []PublicKey, privateKey PrivateKey, n int) (jointPrivateKey PrivateKey, err error) {
	var jointHash, primeDigest [64]byte
	h := sha512.New()

	// L = H(P1 || P2 || ... || Pn)
	for _, publicKey := range publicKeys {
		h.Write(publicKey[:])
	}
	h.Sum(jointHash[:0])

	// x'i = H(L || Pi) * xi
	// this calculates H(L || Pi)
	h.Reset()
	h.Write(jointHash[:])
	h.Write(publicKeys[n][:])
	h.Sum(primeDigest[:0])

	var privateKeyBytes, primeBytes [32]byte
	// here we reduce to a proper scalar
	edwards25519.ScReduce(&primeBytes, &primeDigest)

	// here we calculate H(L || Pi) * xi
	digest := sha512.Sum512(privateKey[:32])
	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64
	copy(privateKeyBytes[:], digest[:])

	var jointX [32]byte
	edwards25519.ScMul(&jointX, &primeBytes, &privateKeyBytes)
	jointPrivateKey = make([]byte, PrivateKeySize)
	copy(jointPrivateKey[:32], jointX[:])

	jointPublicKey, _, err := GenerateJointKey(publicKeys)
	copy(jointPrivateKey[32:], jointPublicKey[:])
	return jointPrivateKey, err
}

// H(R1 + R2 + ... + Rn || J(P1, P2, ..., Pn) || m) = e
// si = ri + e * x'i
func JointSign(privateKey, jointPrivateKey PrivateKey, noncePoints []CurvePoint, message []byte) []byte {
	if l := len(privateKey); l != PrivateKeySize {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}
	if l := len(jointPrivateKey); l != PrivateKeySize {
		panic("ed25519: bad joint private key length: " + strconv.Itoa(l))
	}
	if len(noncePoints) < 2 {
		panic("ed25519: need at least 2 nonce points to create a joint signature")
	}

	h := sha512.New()
	var secretKey [32]byte
	copy(secretKey[:], jointPrivateKey[:32])
	var messageDigest [64]byte

	// R = Sum(Ri)
	var summedR edwards25519.ExtendedGroupElement
	noncePointElements := make([]edwards25519.ExtendedGroupElement, len(noncePoints))
	noncePointBytesList := make([][32]byte, len(noncePoints))
	for i, noncePoint := range noncePoints {
		copy(noncePointBytesList[i][:], noncePoint[:])
		if !noncePointElements[i].FromBytes(&noncePointBytesList[i]) {
			panic("ed25519: unable to parse nonce point")
		}
	}
	edwards25519.GeAdd(&summedR, &noncePointElements[0], &noncePointElements[1])
	for i := 2; i < len(noncePoints); i++ {
		edwards25519.GeAdd(&summedR, &summedR, &noncePointElements[i])
	}
	var encodedR [32]byte
	summedR.ToBytes(&encodedR)

	h.Reset()
	h.Write(encodedR[:])
	// J(P1, P2, ..., Pn)
	h.Write(jointPrivateKey[32:])
	// m
	h.Write(message)
	h.Sum(messageDigest[:0])

	// e = H(R1 + R2 + ... + Rn || J(P1, P2, ..., Pn) || m)
	var e [32]byte
	edwards25519.ScReduce(&e, &messageDigest)

	var r [32]byte
	r = GenerateNonce(privateKey, message)

	var s [32]byte
	edwards25519.ScMulAdd(&s, &e, &secretKey, &r)

	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &r)
	var encodedNonce [32]byte
	R.ToBytes(&encodedNonce)

	signature := make([]byte, SignatureSize)
	copy(signature[:], encodedNonce[:])
	copy(signature[32:], s[:])

	return signature
}

// s_agg = s_A + s_B
// R_agg = R_A + R_B
func AddSignature(signature1, signature2 []byte) []byte {
	var s1, s2, R1Bytes, R2Bytes, RBytes [32]byte
	copy(s1[:], signature1[32:])
	copy(s2[:], signature2[32:])
	copy(R1Bytes[:], signature1[:32])
	copy(R2Bytes[:], signature2[:32])
	var s, one [32]byte
	one[0] = 1
	// s1 * 1 + s2 = s1 + s2
	edwards25519.ScMulAdd(&s, &s1, &one, &s2)

	var R, R1, R2 edwards25519.ExtendedGroupElement
	R1.FromBytes(&R1Bytes)
	R2.FromBytes(&R2Bytes)
	edwards25519.GeAdd(&R, &R1, &R2)
	R.ToBytes(&RBytes)

	signature := make([]byte, SignatureSize)
	copy(signature[:], RBytes[:])
	copy(signature[32:], s[:])
	return signature
}

func GenerateAdaptor(rand io.Reader) (Adaptor, CurvePoint, error) {
	adaptor := make([]byte, AdaptorSize)
	_, err := io.ReadFull(rand, adaptor[:])
	var A edwards25519.ExtendedGroupElement
	adaptorPoint := make([]byte, CurvePointSize)
	if err != nil {
		return nil, adaptorPoint, err
	}

	adaptor[0] &= 248
	adaptor[31] &= 127
	adaptor[31] |= 64
        var buffer [64]byte
        var reducedAdaptor [32]byte
        copy(buffer[:32], adaptor[:])
        edwards25519.ScReduce(&reducedAdaptor, &buffer)
	copy(adaptor[:], reducedAdaptor[:])
	var adaptorBytes, adaptorPointBytes [32]byte
	copy(adaptorBytes[:], adaptor[:])
	copy(adaptorBytes[:], reducedAdaptor[:])
	edwards25519.GeScalarMultBase(&A, &adaptorBytes)
	A.ToBytes(&adaptorPointBytes)
	copy(adaptorPoint[:], adaptorPointBytes[:])
	return adaptor, adaptorPoint, nil
}

// e = H(R_A + R_B + T || J(A, B) || m)
// s_A = r_A + e * x_A'
// s_B' = r_B + e * x_B'
func JointSignWithAdaptor(privateKey, jointPrivateKey PrivateKey, noncePoint1, noncePoint2, adaptorPoint CurvePoint, message []byte) []byte {
	if l := len(privateKey); l != PrivateKeySize {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}
	if l := len(jointPrivateKey); l != PrivateKeySize {
		panic("ed25519: bad joint private key length: " + strconv.Itoa(l))
	}

	h := sha512.New()
	var secretKey [32]byte
	copy(secretKey[:], jointPrivateKey[:32])
	var messageDigest [64]byte

	h.Reset()
	// R_A + R_B + T
	var summedR edwards25519.ExtendedGroupElement
	noncePoint1Element := noncePoint1.toElement()
	noncePoint2Element := noncePoint2.toElement()
	adaptorPointElement := adaptorPoint.toElement()
	edwards25519.GeAdd(&summedR, &noncePoint1Element, &noncePoint2Element)
	edwards25519.GeAdd(&summedR, &summedR, &adaptorPointElement)
	var encodedR [32]byte
	summedR.ToBytes(&encodedR)
	h.Write(encodedR[:])
	// J(A, B)
	h.Write(jointPrivateKey[32:])
	// m
	h.Write(message)
	h.Sum(messageDigest[:0])

	// e = H(R_A + R_B + T || J(A, B) || m)
	var e [32]byte
	edwards25519.ScReduce(&e, &messageDigest)

	var r [32]byte
	r = GenerateNonce(privateKey, message)

	var s [32]byte
	edwards25519.ScMulAdd(&s, &e, &secretKey, &r)

	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &r)
	var encodedNonce [32]byte
	R.ToBytes(&encodedNonce)

	signature := make([]byte, SignatureSize)
	copy(signature[:], encodedNonce[:])
	copy(signature[32:], s[:])

	return signature
}

// e = H(R_A + R_B + T || J(A, B) || m)
// s_B' * G ?= R_B + e * P_B'
// So R_B ?= S_B' - e * P_B'?
func VerifyAdaptorSignature(publicKey, jointPublicKey PublicKey, noncePoint1, noncePoint2, adaptorPoint CurvePoint, message, sig []byte) bool {
	if l := len(publicKey); l != PublicKeySize {
		panic("ed25519: bad public key length: " + strconv.Itoa(l))
	}

	if l := len(jointPublicKey); l != PublicKeySize {
		panic("ed25519: bad joint public key length: " + strconv.Itoa(l))
	}

	if len(sig) != SignatureSize || sig[63]&224 != 0 {
		return false
	}

	var A edwards25519.ExtendedGroupElement
	var publicKeyBytes [32]byte
	copy(publicKeyBytes[:], publicKey)
	if !A.FromBytes(&publicKeyBytes) {
		return false
	}
	edwards25519.FeNeg(&A.X, &A.X)
	edwards25519.FeNeg(&A.T, &A.T)

	h := sha512.New()

	// R_A + R_B + T
	var messageDigest [64]byte
	var summedR, noncePoint1Element, noncePoint2Element, adaptorPointElement edwards25519.ExtendedGroupElement
	var noncePoint1Bytes, noncePoint2Bytes, adaptorPointBytes [32]byte
	copy(noncePoint1Bytes[:], noncePoint1[:])
	copy(noncePoint2Bytes[:], noncePoint2[:])
	copy(adaptorPointBytes[:], adaptorPoint[:])
	if !noncePoint1Element.FromBytes(&noncePoint1Bytes) {
		panic("ed25519: unable to parse nonce point")
	}
	if !noncePoint2Element.FromBytes(&noncePoint2Bytes) {
		panic("ed25519: unable to parse nonce point")
	}
	if !adaptorPointElement.FromBytes(&adaptorPointBytes) {
		panic("ed25519: unable to parse adaptor point")
	}
	edwards25519.GeAdd(&summedR, &noncePoint1Element, &noncePoint2Element)
	edwards25519.GeAdd(&summedR, &summedR, &adaptorPointElement)
	var encodedR [32]byte
	summedR.ToBytes(&encodedR)
	h.Write(encodedR[:])
	// J(A, B)
	h.Write(jointPublicKey[:])
	// m
	h.Write(message)
	h.Sum(messageDigest[:0])

	// e = H(R_A + R_B + T || J(A, B) || m)
	var e [32]byte
	edwards25519.ScReduce(&e, &messageDigest)

	// e * -P_B'
	var hramA edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMult(&hramA, &e, &A)
	var hramABuffer [32]byte
	hramA.ToBytes(&hramABuffer)

	var R edwards25519.ProjectiveGroupElement
	// b is little s
	var b [32]byte
	copy(b[:], sig[32:])
	// R_B = - H(R_A+R_B+T,P_B',m)P_B' + s_b'*BASE_POINT
	edwards25519.GeDoubleScalarMultVartime(&R, &e, &A, &b)

	var checkR [32]byte
	R.ToBytes(&checkR)
	var RBBytes [32]byte
	copy(RBBytes[:], sig[:32])
	return bytes.Equal(RBBytes[:], checkR[:])

}
