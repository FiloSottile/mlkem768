// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore

package mlkem768

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
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
	dk.dk = [DecapsulationKeySize]byte(dkBytes)
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
	H := sha3.Sum256(ekPKE)
	h := dkBytes[decryptionKeySize+encryptionKeySize : decryptionKeySize+encryptionKeySize+32]
	if !bytes.Equal(H[:], h) {
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
		dkExp := vector("NIST Key Generation", "dk")

		ek, dk := GenerateKeyDerand(t, d, z)
		if !bytes.Equal(ek, ekExp) {
			t.Errorf("ek: got %x, expected %x", ek, ekExp)
		}
		if !bytes.Equal(dk.Bytes(), dkExp) {
			t.Errorf("dk: got %x, expected %x", dk, dkExp)
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

func TestPQCrystalsVector(t *testing.T) {
	d := vector("PQCrystals", "Coins")[:32]
	z := vector("PQCrystals", "Coins")[32:]
	ekExp := vector("PQCrystals", "Public Key")
	dkExp := vector("PQCrystals", "Secret Key")

	ek, dk := GenerateKeyDerand(t, d, z)
	if !bytes.Equal(ek, ekExp) {
		t.Errorf("ek: got %x, expected %x", ek, ekExp)
	}
	if !bytes.Equal(dk.Bytes(), dkExp) {
		t.Errorf("dk: got %x, expected %x", dk, dkExp)
	}

	msg := vector("PQCrystals", "Message")
	ctExp := vector("PQCrystals", "Ciphertext")
	kExp := vector("PQCrystals", "Shared Secret")

	ct, k, err := EncapsulateDerand(ek, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ct, ctExp) {
		t.Errorf("ct: got %x, expected %x", ct, ctExp)
	}
	if !bytes.Equal(k, kExp) {
		t.Errorf("k (encaps): got %x, expected %x", k, kExp)
	}

	k, err = Decapsulate(dk, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k, kExp) {
		t.Errorf("k (decaps): got %x, expected %x", k, kExp)
	}

	ct = vector("PQCrystals", "Pseudorandom Ciphertext")
	kExp = vector("PQCrystals", "Pseudorandom Shared Secret")

	k, err = Decapsulate(dk, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k, kExp) {
		t.Errorf("k (random): got %x, expected %x", k, kExp)
	}
}

func TestPQCKATVector(t *testing.T) {
	d := vector("post-quantum-cryptography/KAT", "d")
	z := vector("post-quantum-cryptography/KAT", "z")
	ekExp := vector("post-quantum-cryptography/KAT", "pk")
	dkExp := vector("post-quantum-cryptography/KAT", "sk")

	ek, dk := GenerateKeyDerand(t, d, z)
	if !bytes.Equal(ek, ekExp) {
		t.Errorf("ek: got %x, expected %x", ek, ekExp)
	}
	if !bytes.Equal(dk.Bytes(), dkExp) {
		t.Errorf("dk: got %x, expected %x", dk, dkExp)
	}

	msg := vector("post-quantum-cryptography/KAT", "msg")
	ctExp := vector("post-quantum-cryptography/KAT", "ct")
	kExp := vector("post-quantum-cryptography/KAT", "ss")

	ct, k, err := EncapsulateDerand(ek, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ct, ctExp) {
		t.Errorf("ct: got %x, expected %x", ct, ctExp)
	}
	if !bytes.Equal(k, kExp) {
		t.Errorf("k (encaps): got %x, expected %x", k, kExp)
	}

	k, err = Decapsulate(dk, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k, kExp) {
		t.Errorf("k (decaps): got %x, expected %x", k, kExp)
	}

	ct = vector("post-quantum-cryptography/KAT", "ct_n")
	kExp = vector("post-quantum-cryptography/KAT", "ss_n")

	k, err = Decapsulate(dk, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k, kExp) {
		t.Errorf("k (random): got %x, expected %x", k, kExp)
	}
}

func TestUnluckyVector(t *testing.T) {
	d := vector("unlucky", "d")
	z := vector("unlucky", "z")
	ekExp := vector("unlucky", "pk")
	dkExp := vector("unlucky", "sk")

	ek, dk := GenerateKeyDerand(t, d, z)
	if !bytes.Equal(ek, ekExp) {
		t.Errorf("ek: got %x, expected %x", ek, ekExp)
	}
	if !bytes.Equal(dk.Bytes(), dkExp) {
		t.Errorf("dk: got %x, expected %x", dk, dkExp)
	}

	msg := vector("unlucky", "msg")
	ctExp := vector("unlucky", "ct")
	kExp := vector("unlucky", "ss")

	ct, k, err := EncapsulateDerand(ek, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ct, ctExp) {
		t.Errorf("ct: got %x, expected %x", ct, ctExp)
	}
	if !bytes.Equal(k, kExp) {
		t.Errorf("k (encaps): got %x, expected %x", k, kExp)
	}

	k, err = Decapsulate(dk, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k, kExp) {
		t.Errorf("k (decaps): got %x, expected %x", k, kExp)
	}
}

func TestStrcmpVector(t *testing.T) {
	dk := vector("strcmp", "sk")
	ct := vector("strcmp", "ct")
	kExp := vector("strcmp", "ss")

	k, err := DecapsulateFromBytes(dk, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k, kExp) {
		t.Errorf("k: got %x, expected %x", k, kExp)
	}
}

func TestNegativeEncaps(t *testing.T) {
	gzipFile, err := os.Open("testdata/negative.txt.gz")
	if err != nil {
		t.Fatal(err)
	}
	gzipReader, err := gzip.NewReader(gzipFile)
	if err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(gzipReader)
	for scanner.Scan() {
		line := scanner.Text()
		ek, err := hex.DecodeString(line)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := Encapsulate(ek); err == nil {
			t.Errorf("expected error for %s", line)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestWycheproofDecaps(t *testing.T) {
	// https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/aCAX-2QrUFw/m/hy5gwcESAAAJ
	gzipFile, err := os.Open("testdata/decaps768draft.gz")
	if err != nil {
		t.Fatal(err)
	}
	gzipReader, err := gzip.NewReader(gzipFile)
	if err != nil {
		t.Fatal(err)
	}
	var comment string
	var dk, ct, kExp []byte
	var expErr bool
	scanner := bufio.NewScanner(gzipReader)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			ss, err := DecapsulateFromBytes(dk, ct)
			if err != nil && !expErr {
				t.Errorf("unexpected error for %s: %v", comment, err)
			}
			if err == nil && expErr {
				t.Errorf("expected error for %s", comment)
			}
			if err == nil && !bytes.Equal(ss, kExp) {
				t.Errorf("k: got %x, expected %x", ss, kExp)
			}
			continue
		}

		key, value, _ := strings.Cut(line, " = ")
		switch key {
		case "comment":
			comment = value
		case "private_key":
			dk, err = hex.DecodeString(value)
		case "ciphertext":
			ct, err = hex.DecodeString(value)
		case "expected_shared_secret":
			if value != "" {
				kExp, err = hex.DecodeString(value)
			} else {
				kExp = nil
			}
		case "expected_result":
			switch value {
			case "pass":
				expErr = false
			case "fail":
				expErr = true
			default:
				t.Fatalf("unknown expected_result %q", value)
			}
		default:
			t.Fatalf("unknown key %q", key)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestWycheproofEncaps(t *testing.T) {
	// https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/aCAX-2QrUFw/m/hy5gwcESAAAJ
	gzipFile, err := os.Open("testdata/encaps768draft.gz")
	if err != nil {
		t.Fatal(err)
	}
	gzipReader, err := gzip.NewReader(gzipFile)
	if err != nil {
		t.Fatal(err)
	}
	var comment string
	var ek, m, ctExp, kExp []byte
	var expErr bool
	scanner := bufio.NewScanner(gzipReader)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			ct, k, err := EncapsulateDerand(ek, m)
			if err != nil && !expErr {
				t.Errorf("unexpected error for %s: %v", comment, err)
			}
			if err == nil && expErr {
				t.Errorf("expected error for %s", comment)
			}
			if err == nil && !bytes.Equal(ct, ctExp) {
				t.Errorf("ct for %s: got %x, expected %x", comment, ct, ctExp)
			}
			if err == nil && !bytes.Equal(k, kExp) {
				t.Errorf("k for %s: got %x, expected %x", comment, k, kExp)
			}
			continue
		}

		key, value, _ := strings.Cut(line, " = ")
		switch key {
		case "comment":
			comment = value
		case "public_key":
			ek, err = hex.DecodeString(value)
		case "entropy":
			m, err = hex.DecodeString(value)
		case "expected_shared_secret":
			if value != "" {
				kExp, err = hex.DecodeString(value)
			} else {
				kExp = nil
			}
		case "expected_ciphertext":
			if value != "" {
				ctExp, err = hex.DecodeString(value)
			} else {
				ctExp = nil
			}
		case "expected_result":
			switch value {
			case "pass":
				expErr = false
			case "fail":
				expErr = true
			default:
				t.Fatalf("unknown expected_result %q", value)
			}
		default:
			t.Fatalf("unknown key %q", key)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}
