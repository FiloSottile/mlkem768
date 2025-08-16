// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mlkem768

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	dk, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	c, Ke, err := Encapsulate(dk.EncapsulationKey())
	if err != nil {
		t.Fatal(err)
	}
	Kd, err := Decapsulate(dk, c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Ke, Kd) {
		t.Fail()
	}

	dk1, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(dk.EncapsulationKey(), dk1.EncapsulationKey()) {
		t.Fail()
	}
	if bytes.Equal(dk.Bytes(), dk1.Bytes()) {
		t.Fail()
	}

	c1, Ke1, err := Encapsulate(dk.EncapsulationKey())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c, c1) {
		t.Fail()
	}
	if bytes.Equal(Ke, Ke1) {
		t.Fail()
	}
}

func TestBadLengths(t *testing.T) {
	dk, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ek := dk.EncapsulationKey()

	for i := 0; i < len(ek)-1; i++ {
		if _, _, err := Encapsulate(ek[:i]); err == nil {
			t.Errorf("expected error for ek length %d", i)
		}
	}
	ekLong := ek
	for i := 0; i < 100; i++ {
		ekLong = append(ekLong, 0)
		if _, _, err := Encapsulate(ekLong); err == nil {
			t.Errorf("expected error for ek length %d", len(ekLong))
		}
	}

	c, _, err := Encapsulate(ek)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < len(c)-1; i++ {
		if _, err := Decapsulate(dk, c[:i]); err == nil {
			t.Errorf("expected error for c length %d", i)
		}
	}
	cLong := c
	for i := 0; i < 100; i++ {
		cLong = append(cLong, 0)
		if _, err := Decapsulate(dk, cLong); err == nil {
			t.Errorf("expected error for c length %d", len(cLong))
		}
	}
}
