// Package xwing implements the hybrid quantum-resistant key encapsulation
// method X-Wing, which combines X25519, ML-KEM-768, and SHA3-256 as specified
// in [draft-connolly-cfrg-xwing-kem-01].
//
// Future v0 versions of this package might introduce backwards incompatible
// changes to implement changes to draft-connolly-cfrg-xwing-kem or FIPS 203.
//
// [draft-connolly-cfrg-xwing-kem-01]: https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-01.html
package xwing

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"

	"filippo.io/mlkem768"
	"golang.org/x/crypto/sha3"
)

const (
	CiphertextSize       = mlkem768.CiphertextSize + 32
	EncapsulationKeySize = mlkem768.EncapsulationKeySize + 32
	DecapsulationKeySize = mlkem768.DecapsulationKeySize + 32 + 32
	SharedKeySize        = 32
	SeedSize             = mlkem768.SeedSize + 32
)

// GenerateKey generates an encapsulation key and a corresponding decapsulation
// key, drawing random bytes from crypto/rand.
//
// The decapsulation key must be kept secret.
func GenerateKey() (encapsulationKey, decapsulationKey []byte, err error) {
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	skX := x.Bytes()
	pkX := x.PublicKey().Bytes()

	pkM, skM, err := mlkem768.GenerateKey()
	if err != nil {
		return nil, nil, err
	}

	return append(pkM, pkX...), append(append(skM, skX...), pkX...), nil
}

// NewKeyFromSeed deterministically generates an encapsulation key and a
// corresponding decapsulation key from a 96-byte seed. The seed must be
// uniformly random.
func NewKeyFromSeed(seed []byte) (encapsulationKey, decapsulationKey []byte, err error) {
	if len(seed) != SeedSize {
		return nil, nil, errors.New("xwing: invalid seed length")
	}

	skX := seed[mlkem768.SeedSize:]
	x, err := ecdh.X25519().NewPrivateKey(skX)
	if err != nil {
		return nil, nil, err
	}
	pkX := x.PublicKey().Bytes()

	pkM, skM, err := mlkem768.NewKeyFromSeed(seed[:mlkem768.SeedSize])
	if err != nil {
		return nil, nil, err
	}

	return append(pkM, pkX...), append(append(skM, skX...), pkX...), nil
}

const xwingLabel = (`` +
	`\./` +
	`/^\`)

func combiner(ssM, ssX, ctX, pkX []byte) []byte {
	h := sha3.New256()
	h.Write([]byte(xwingLabel))
	h.Write(ssM)
	h.Write(ssX)
	h.Write(ctX)
	h.Write(pkX)
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
// If the decapsulation key or the ciphertext are not valid, Decapsulate returns
// an error.
//
// The shared key must be kept secret.
func Decapsulate(decapsulationKey, ciphertext []byte) (sharedKey []byte, err error) {
	if len(decapsulationKey) != DecapsulationKeySize {
		return nil, errors.New("xwing: invalid decapsulation key length")
	}
	if len(ciphertext) != CiphertextSize {
		return nil, errors.New("xwing: invalid ciphertext length")
	}

	ctM := ciphertext[:mlkem768.CiphertextSize]
	ctX := ciphertext[mlkem768.CiphertextSize:]
	skM := decapsulationKey[:mlkem768.DecapsulationKeySize]
	skX := decapsulationKey[mlkem768.DecapsulationKeySize : mlkem768.DecapsulationKeySize+32]
	pkX := decapsulationKey[mlkem768.DecapsulationKeySize+32:]

	ssM, err := mlkem768.Decapsulate(skM, ctM)
	if err != nil {
		return nil, err
	}

	peerKey, err := ecdh.X25519().NewPublicKey(ctX)
	if err != nil {
		return nil, err
	}
	x25519Key, err := ecdh.X25519().NewPrivateKey(skX)
	if err != nil {
		return nil, err
	}
	ssX, err := x25519Key.ECDH(peerKey)
	if err != nil {
		return nil, err
	}

	ss := combiner(ssM, ssX, ctX, pkX)
	return ss, nil
}
