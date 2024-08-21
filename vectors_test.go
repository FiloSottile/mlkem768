// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mlkem768

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"golang.org/x/crypto/sha3"
)

//go:embed testdata/vectors.json
var vectorsJSON []byte
var vectors map[string]map[string]string

func init() {
	if err := json.Unmarshal(vectorsJSON, &vectors); err != nil {
		panic(err)
	}
}

func vector(group, name string) []byte {
	h := vectors[group][name]
	v, _ := hex.DecodeString(h)
	return v
}

func EncapsulateDerand(ek, m []byte) (c, K []byte, err error) {
	if len(m) != messageSize {
		return nil, nil, errors.New("bad message length")
	}
	return kemEncaps(nil, ek, (*[messageSize]byte)(m))
}

func DecapsulateFromBytes(dkBytes, c []byte) ([]byte, error) {
	if len(c) != CiphertextSize {
		return nil, errors.New("bad ciphertext length")
	}
	if len(dkBytes) != DecapsulationKeySize {
		return nil, errors.New("bad key length")
	}
	dk := &DecapsulationKey{}
	dk.ρ = [32]byte(dkBytes[len(dkBytes)-96 : len(dkBytes)-64])
	dk.h = [32]byte(dkBytes[len(dkBytes)-64 : len(dkBytes)-32])
	dk.z = [32]byte(dkBytes[len(dkBytes)-32:])
	dkPKE := dkBytes[:decryptionKeySize]
	for i := range dk.s {
		f, err := polyByteDecode[nttElement](dkPKE[:encodingSize12])
		if err != nil {
			return nil, err
		}
		dk.s[i] = f
		dkPKE = dkPKE[encodingSize12:]
	}
	ekPKE := dkBytes[decryptionKeySize : decryptionKeySize+encryptionKeySize]
	if err := parseEK(&dk.encryptionKey, ekPKE); err != nil {
		return nil, err
	}
	if sha3.Sum256(ekPKE) != dk.h {
		return nil, errors.New("bad ek hash")
	}
	return kemDecaps(dk, (*[CiphertextSize]byte)(c)), nil
}

func TestNISTVectors(t *testing.T) {
	t.Run("KeyGen", func(t *testing.T) {
		// Note that d == z in the vectors, which is unfortunate because—aside from
		// being confusing, as this would NOT be possible in practice—it makes it
		// impossible to detect e.g. a mistake swapping the two.
		d := vector("NIST Key Generation", "d")
		z := vector("NIST Key Generation", "z")
		ekExp := vector("NIST Key Generation", "ek")

		dk := kemKeyGen(nil, (*[32]byte)(d), (*[32]byte)(z))
		ek := dk.EncapsulationKey()
		if !bytes.Equal(ek, ekExp) {
			t.Errorf("ek: got %x, expected %x", ek, ekExp)
		}
	})

	t.Run("Encaps", func(t *testing.T) {
		ek := vector("NIST Encapsulation", "ek")
		msg := vector("NIST Encapsulation", "msg")
		ctExp := vector("NIST Encapsulation", "ct")
		kExp := vector("NIST Encapsulation", "k")

		ct, k, err := EncapsulateDerand(ek, msg)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ct, ctExp) {
			t.Errorf("ct: got %x, expected %x", ct, ctExp)
		}
		if !bytes.Equal(k, kExp) {
			t.Errorf("k: got %x, expected %x", k, kExp)
		}
	})

	t.Run("Decaps", func(t *testing.T) {
		dk := vector("NIST Decapsulation", "dk")
		ct := vector("NIST Decapsulation", "ct")
		kExp := vector("NIST Decapsulation", "k")

		k, err := DecapsulateFromBytes(dk, ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(k, kExp) {
			t.Errorf("k: got %x, expected %x", k, kExp)
		}
	})
}
