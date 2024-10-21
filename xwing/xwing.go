// Package xwing implements the hybrid quantum-resistant key encapsulation
// method X-Wing, which combines X25519, ML-KEM-768, and SHA3-256 as specified
// in [draft-connolly-cfrg-xwing-kem].
//
// [draft-connolly-cfrg-xwing-kem]: https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-05.html
package xwing

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"

	"filippo.io/mlkem768"
	"golang.org/x/crypto/sha3"
)

const (
	CiphertextSize       = mlkem768.CiphertextSize + 32
	EncapsulationKeySize = mlkem768.EncapsulationKeySize + 32
	SharedKeySize        = 32
	SeedSize             = 32
)

// A DecapsulationKey is the secret key used to decapsulate a shared key from a
// ciphertext. It includes various precomputed values.
type DecapsulationKey struct {
	sk  [SeedSize]byte
	skM *mlkem768.DecapsulationKey
	skX *ecdh.PrivateKey
	pk  [EncapsulationKeySize]byte
}

// Bytes returns the decapsulation key as a 32-byte seed.
func (dk *DecapsulationKey) Bytes() []byte {
	return bytes.Clone(dk.sk[:])
}

// EncapsulationKey returns the public encapsulation key necessary to produce
// ciphertexts.
func (dk *DecapsulationKey) EncapsulationKey() []byte {
	return bytes.Clone(dk.pk[:])
}

// GenerateKey generates a new decapsulation key, drawing random bytes from
// crypto/rand. The decapsulation key must be kept secret.
func GenerateKey() (*DecapsulationKey, error) {
	sk := make([]byte, SeedSize)
	if _, err := rand.Read(sk); err != nil {
		return nil, err
	}
	return NewKeyFromSeed(sk)
}

// NewKeyFromSeed deterministically generates a decapsulation key from a 32-byte
// seed. The seed must be uniformly random.
func NewKeyFromSeed(sk []byte) (*DecapsulationKey, error) {
	if len(sk) != SeedSize {
		return nil, errors.New("xwing: invalid seed length")
	}

	s := sha3.NewShake256()
	s.Write(sk)
	expanded := make([]byte, mlkem768.SeedSize+32)
	if _, err := s.Read(expanded); err != nil {
		return nil, err
	}

	skM, err := mlkem768.NewKeyFromSeed(expanded[:mlkem768.SeedSize])
	if err != nil {
		return nil, err
	}
	pkM := skM.EncapsulationKey()

	skX := expanded[mlkem768.SeedSize:]
	x, err := ecdh.X25519().NewPrivateKey(skX)
	if err != nil {
		return nil, err
	}
	pkX := x.PublicKey().Bytes()

	dk := &DecapsulationKey{}
	copy(dk.sk[:], sk)
	dk.skM = skM
	dk.skX = x
	copy(dk.pk[:], append(pkM, pkX...))
	return dk, nil
}

const xwingLabel = (`` +
	`\./` +
	`/^\`)

func combiner(ssM, ssX, ctX, pkX []byte) []byte {
	h := sha3.New256()
	h.Write(ssM)
	h.Write(ssX)
	h.Write(ctX)
	h.Write(pkX)
	h.Write([]byte(xwingLabel))
	return h.Sum(nil)
}

// Encapsulate generates a shared key and an associated ciphertext from an
// encapsulation key, drawing random bytes from crypto/rand.
// If the encapsulation key is not valid, Encapsulate returns an error.
//
// The shared key must be kept secret.
func Encapsulate(encapsulationKey []byte) (ciphertext, sharedKey []byte, err error) {
	if len(encapsulationKey) != EncapsulationKeySize {
		return nil, nil, errors.New("xwing: invalid encapsulation key size")
	}

	pkM := encapsulationKey[:mlkem768.EncapsulationKeySize]
	pkX := encapsulationKey[mlkem768.EncapsulationKeySize:]

	ephemeralKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	peerKey, err := ecdh.X25519().NewPublicKey(pkX)
	if err != nil {
		return nil, nil, err
	}
	ctX := ephemeralKey.PublicKey().Bytes()
	ssX, err := ephemeralKey.ECDH(peerKey)
	if err != nil {
		return nil, nil, err
	}

	ctM, ssM, err := mlkem768.Encapsulate(pkM)
	if err != nil {
		return nil, nil, err
	}

	ss := combiner(ssM, ssX, ctX, pkX)
	ct := append(ctM, ctX...)
	return ct, ss, nil
}

// Decapsulate generates a shared key from a ciphertext and a decapsulation key.
// If the ciphertext is not valid, Decapsulate returns an error.
//
// The shared key must be kept secret.
func Decapsulate(dk *DecapsulationKey, ciphertext []byte) (sharedKey []byte, err error) {
	if len(ciphertext) != CiphertextSize {
		return nil, errors.New("xwing: invalid ciphertext length")
	}

	ctM := ciphertext[:mlkem768.CiphertextSize]
	ctX := ciphertext[mlkem768.CiphertextSize:]
	pkX := dk.pk[mlkem768.EncapsulationKeySize:]

	ssM, err := mlkem768.Decapsulate(dk.skM, ctM)
	if err != nil {
		return nil, err
	}

	peerKey, err := ecdh.X25519().NewPublicKey(ctX)
	if err != nil {
		return nil, err
	}
	ssX, err := dk.skX.ECDH(peerKey)
	if err != nil {
		return nil, err
	}

	ss := combiner(ssM, ssX, ctX, pkX)
	return ss, nil
}
