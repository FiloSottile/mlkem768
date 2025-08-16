// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package mlkem768 implements the quantum-resistant key encapsulation method
// ML-KEM (formerly known as Kyber), as specified in [NIST FIPS 203].
//
// Only the recommended ML-KEM-768 parameter set is provided.
//
// [NIST FIPS 203]: https://doi.org/10.6028/NIST.FIPS.203
package mlkem768

// This implementation moved to the standard library as crypto/mlkem in Go 1.24.

import "crypto/mlkem"

const (
	CiphertextSize       = mlkem.CiphertextSize768
	EncapsulationKeySize = mlkem.EncapsulationKeySize768
	SharedKeySize        = mlkem.SharedKeySize
	SeedSize             = mlkem.SeedSize
)

// A DecapsulationKey is the secret key used to decapsulate a shared key from a
// ciphertext. It includes various precomputed values.
type DecapsulationKey struct {
	k mlkem.DecapsulationKey768
}

// Bytes returns the decapsulation key as a 64-byte seed in the "d || z" form.
func (dk *DecapsulationKey) Bytes() []byte {
	return dk.k.Bytes()
}

// EncapsulationKey returns the public encapsulation key necessary to produce
// ciphertexts.
func (dk *DecapsulationKey) EncapsulationKey() []byte {
	return dk.k.EncapsulationKey().Bytes()
}

// GenerateKey generates a new decapsulation key, drawing random bytes from
// crypto/rand. The decapsulation key must be kept secret.
func GenerateKey() (*DecapsulationKey, error) {
	k, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	return &DecapsulationKey{k: *k}, nil
}

// NewKeyFromSeed deterministically generates a decapsulation key from a 64-byte
// seed in the "d || z" form. The seed must be uniformly random.
func NewKeyFromSeed(seed []byte) (*DecapsulationKey, error) {
	k, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, err
	}
	return &DecapsulationKey{k: *k}, nil
}

// Encapsulate generates a shared key and an associated ciphertext from an
// encapsulation key, drawing random bytes from crypto/rand.
// If the encapsulation key is not valid, Encapsulate returns an error.
//
// The shared key must be kept secret.
func Encapsulate(encapsulationKey []byte) (ciphertext, sharedKey []byte, err error) {
	k, err := mlkem.NewEncapsulationKey768(encapsulationKey)
	if err != nil {
		return nil, nil, err
	}
	sharedKey, ciphertext = k.Encapsulate()
	return ciphertext, sharedKey, nil
}

// Decapsulate generates a shared key from a ciphertext and a decapsulation key.
// If the ciphertext is not valid, Decapsulate returns an error.
//
// The shared key must be kept secret.
func Decapsulate(dk *DecapsulationKey, ciphertext []byte) (sharedKey []byte, err error) {
	return dk.k.Decapsulate(ciphertext)
}
