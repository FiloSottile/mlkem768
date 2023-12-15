// Copyright (c) 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mlkem768

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"
)

func TestFieldAdd(t *testing.T) {
	for a := fieldElement(0); a < q; a++ {
		for b := fieldElement(0); b < q; b++ {
			got := fieldAdd(a, b)
			exp := (a + b) % q
			if got != exp {
				t.Fatalf("%d + %d = %d, expected %d", a, b, got, exp)
			}
		}
	}
}

func TestFieldSub(t *testing.T) {
	for a := fieldElement(0); a < q; a++ {
		for b := fieldElement(0); b < q; b++ {
			got := fieldSub(a, b)
			exp := (a - b + q) % q
			if got != exp {
				t.Fatalf("%d - %d = %d, expected %d", a, b, got, exp)
			}
		}
	}
}

func TestFieldMul(t *testing.T) {
	for a := fieldElement(0); a < q; a++ {
		for b := fieldElement(0); b < q; b++ {
			got := fieldMul(a, b)
			exp := fieldElement((uint32(a) * uint32(b)) % q)
			if got != exp {
				t.Fatalf("%d * %d = %d, expected %d", a, b, got, exp)
			}
		}
	}
}

func TestDecompressCompress(t *testing.T) {
	for _, bits := range []uint8{1, 4, 10} {
		for a := uint16(0); a < 1<<bits; a++ {
			f := decompress(a, bits)
			if f >= q {
				t.Fatalf("decompress(%d, %d) = %d >= q", a, bits, f)
			}
			got := compress(f, bits)
			if got != a {
				t.Fatalf("compress(decompress(%d, %d), %d) = %d", a, bits, bits, got)
			}
		}

		for a := fieldElement(0); a < q; a++ {
			c := compress(a, bits)
			if c >= 1<<bits {
				t.Fatalf("compress(%d, %d) = %d >= 2^bits", a, bits, c)
			}
		}
	}
}

func BitRev7(n uint8) uint8 {
	if n>>7 != 0 {
		panic("not 7 bits")
	}
	var r uint8
	r |= n >> 6 & 0b0000_0001
	r |= n >> 4 & 0b0000_0010
	r |= n >> 2 & 0b0000_0100
	r |= n /**/ & 0b0000_1000
	r |= n << 2 & 0b0001_0000
	r |= n << 4 & 0b0010_0000
	r |= n << 6 & 0b0100_0000
	return r
}

func TestZetas(t *testing.T) {
	ζ := big.NewInt(17)
	q := big.NewInt(q)
	for k, zeta := range zetas {
		// ζ^BitRev7(k) mod q
		exp := new(big.Int).Exp(ζ, big.NewInt(int64(BitRev7(uint8(k)))), q)
		if big.NewInt(int64(zeta)).Cmp(exp) != 0 {
			t.Errorf("zetas[%d] = %v, expected %v", k, zeta, exp)
		}
	}
}

func TestGammas(t *testing.T) {
	ζ := big.NewInt(17)
	q := big.NewInt(q)
	for k, gamma := range gammas {
		// ζ^2BitRev7(i)+1
		exp := new(big.Int).Exp(ζ, big.NewInt(int64(BitRev7(uint8(k)))*2+1), q)
		if big.NewInt(int64(gamma)).Cmp(exp) != 0 {
			t.Errorf("gammas[%d] = %v, expected %v", k, gamma, exp)
		}
	}
}

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

func TestNISTVectors(t *testing.T) {
	t.Run("KeyGen", func(t *testing.T) {
		// Note that d == z in the vectors, which is unfortunate because—aside from
		// being confusing, as this would NOT be possible in practice—it makes it
		// impossible to detect e.g. a mistake swapping the two.
		d := vector("NIST Key Generation", "d")
		z := vector("NIST Key Generation", "z")
		ekExp := vector("NIST Key Generation", "ek")
		dkExp := vector("NIST Key Generation", "dk")

		ek, dk := kemKeyGen(d, z)
		if !bytes.Equal(ek, ekExp) {
			t.Errorf("ek: got %x, expected %x", ek, ekExp)
		}
		if !bytes.Equal(dk, dkExp) {
			t.Errorf("dk: got %x, expected %x", dk, dkExp)
		}
	})

	t.Run("Encaps", func(t *testing.T) {
		ek := vector("NIST Encapsulation", "ek")
		msg := vector("NIST Encapsulation", "msg")
		ctExp := vector("NIST Encapsulation", "ct")
		kExp := vector("NIST Encapsulation", "k")

		ct, k, err := kemEncaps(ek, msg)
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

		k, err := kemDecaps(dk, ct)
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

	ek, dk := kemKeyGen(d, z)
	if !bytes.Equal(ek, ekExp) {
		t.Errorf("ek: got %x, expected %x", ek, ekExp)
	}
	if !bytes.Equal(dk, dkExp) {
		t.Errorf("dk: got %x, expected %x", dk, dkExp)
	}

	msg := vector("PQCrystals", "Message")
	ctExp := vector("PQCrystals", "Ciphertext")
	kExp := vector("PQCrystals", "Shared Secret")

	ct, k, err := kemEncaps(ek, msg)
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

	ek, dk := kemKeyGen(d, z)
	if !bytes.Equal(ek, ekExp) {
		t.Errorf("ek: got %x, expected %x", ek, ekExp)
	}
	if !bytes.Equal(dk, dkExp) {
		t.Errorf("dk: got %x, expected %x", dk, dkExp)
	}

	msg := vector("post-quantum-cryptography/KAT", "msg")
	ctExp := vector("post-quantum-cryptography/KAT", "ct")
	kExp := vector("post-quantum-cryptography/KAT", "ss")

	ct, k, err := kemEncaps(ek, msg)
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

var sinkElement fieldElement

func BenchmarkSampleNTT(b *testing.B) {
	for i := 0; i < b.N; i++ {
		sinkElement ^= sampleNTT(bytes.Repeat([]byte("A"), 32), '4', '2')[0]
	}
}

var sink byte

func BenchmarkKeyGen(b *testing.B) {
	d := make([]byte, 32)
	rand.Read(d)
	z := make([]byte, 32)
	rand.Read(z)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ek, dk := kemKeyGen(d, z)
		sink ^= ek[0] ^ dk[0]
	}
}

func BenchmarkEncaps(b *testing.B) {
	d := make([]byte, 32)
	rand.Read(d)
	z := make([]byte, 32)
	rand.Read(z)
	m := make([]byte, 32)
	rand.Read(m)
	ek, _ := kemKeyGen(d, z)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, K, err := kemEncaps(ek, m)
		if err != nil {
			b.Fatal(err)
		}
		sink ^= c[0] ^ K[0]
	}
}

func BenchmarkDecaps(b *testing.B) {
	d := make([]byte, 32)
	rand.Read(d)
	z := make([]byte, 32)
	rand.Read(z)
	m := make([]byte, 32)
	rand.Read(m)
	ek, dk := kemKeyGen(d, z)
	c, _, err := kemEncaps(ek, m)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		K, err := kemDecaps(dk, c)
		if err != nil {
			b.Fatal(err)
		}
		sink ^= K[0]
	}
}

func BenchmarkRoundTrip(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ek, dk := GenerateKey()
		c, Ke, err := Encapsulate(ek)
		if err != nil {
			b.Fatal(err)
		}
		Kd, err := Decapsulate(dk, c)
		if err != nil {
			b.Fatal(err)
		}
		if !bytes.Equal(Ke, Kd) {
			b.Fail()
		}
	}
}
