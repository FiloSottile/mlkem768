package mlkem768

import (
	"errors"

	"golang.org/x/crypto/sha3"
)

const (
	// ML-KEM global constants.
	n = 256
	q = 3329

	// ML-KEM-768 parameters. The code makes assumptions based on these values,
	// they can't be changed blindly.
	k  = 3
	η  = 2
	du = 10
	dv = 4

	// encodingSizeX is the byte size of a ringElement or nttElement encoded by
	// ByteEncode_X.
	encodingSize12 = n * 12 / 8
	encodingSize10 = n * 10 / 8
	encodingSize4  = n * 4 / 8
	encodingSize1  = n * 1 / 8

	messageSize       = encodingSize1
	decryptionKeySize = k * encodingSize12
	encryptionKeySize = k*encodingSize12 + 32
	ciphertextSize    = k*encodingSize10 + encodingSize4
)

// pkeKeyGen generates a key pair for the underlying PKE from a 32-byte random seed.
//
// It implements K-PKE.KeyGen according to FIPS 203 (DRAFT), Algorithm 12.
func pkeKeyGen(d []byte) (ek, dk []byte) {
	G := sha3.Sum512(d)
	ρ, σ := G[:32], G[32:]

	A := make([]nttElement, k*k)
	for i := byte(0); i < k; i++ {
		for j := byte(0); j < k; j++ {
			// Note that this is consistent with Kyber round 3, rather than with
			// the initial draft of FIPS 203, because NIST signaled that the
			// change was involuntary and will be reverted.
			A[i*k+j] = sampleNTT(ρ, j, i)
		}
	}

	var N byte
	s, e := make([]nttElement, k), make([]nttElement, k)
	for i := range s {
		s[i] = ntt(samplePolyCBD(σ, N))
		N++
	}
	for i := range e {
		e[i] = ntt(samplePolyCBD(σ, N))
		N++
	}

	t := make([]nttElement, k) // A ◦ s + e
	for i := range t {
		t[i] = e[i]
		for j := range s {
			t[i] = polyAdd(t[i], nttMul(A[i*k+j], s[j]))
		}
	}

	ek = make([]byte, 0, encryptionKeySize)
	for i := range t {
		ek = polyByteEncode(ek, t[i])
	}
	ek = append(ek, ρ...)

	dk = make([]byte, 0, decryptionKeySize)
	for i := range s {
		dk = polyByteEncode(dk, s[i])
	}

	return ek, dk
}

// pkeEncrypt encrypt a plaintext message. It expects ek (the encryption key) to
// be 1184 bytes, and m (the message) and rnd (the randomness) to be 32 bytes.
//
// It implements K-PKE.Encrypt according to FIPS 203 (DRAFT), Algorithm 13.
func pkeEncrypt(ek, m, rnd []byte) ([]byte, error) {
	if len(ek) != encryptionKeySize {
		return nil, errors.New("mlkem768: invalid encryption key length")
	}
	if len(m) != messageSize {
		return nil, errors.New("mlkem768: invalid messages length")
	}

	t := make([]nttElement, k)
	for i := range t {
		var err error
		t[i], err = polyByteDecode[nttElement](ek[:encodingSize12])
		if err != nil {
			return nil, err
		}
		ek = ek[encodingSize12:]
	}
	ρ := ek

	AT := make([]nttElement, k*k)
	for i := byte(0); i < k; i++ {
		for j := byte(0); j < k; j++ {
			// Note that i and j are inverted, as we need the transposed of A.
			AT[i*k+j] = sampleNTT(ρ, i, j)
		}
	}

	var N byte
	r, e1 := make([]nttElement, k), make([]ringElement, k)
	for i := range r {
		r[i] = ntt(samplePolyCBD(rnd, N))
		N++
	}
	for i := range e1 {
		e1[i] = samplePolyCBD(rnd, N)
		N++
	}
	e2 := samplePolyCBD(rnd, N)

	u := make([]ringElement, k) // NTT⁻¹(AT ◦ r) + e1
	for i := range u {
		u[i] = e1[i]
		for j := range r {
			u[i] = polyAdd(u[i], inverseNTT(nttMul(AT[i*k+j], r[j])))
		}
	}

	μ, err := ringDecodeAndDecompress1(m)
	if err != nil {
		return nil, err
	}

	var vNTT nttElement // t⊺ ◦ r
	for i := range t {
		vNTT = polyAdd(vNTT, nttMul(t[i], r[i]))
	}
	v := polyAdd(polyAdd(inverseNTT(vNTT), e2), μ)

	c := make([]byte, 0, ciphertextSize)
	for _, f := range u {
		c = ringCompressAndEncode10(c, f)
	}
	c = ringCompressAndEncode4(c, v)

	return c, nil
}

// pkeDecrypt decrypts a ciphertext. It expects dk (the decryption key) to
// be 1152 bytes, and c (the ciphertext) to be 1088 bytes.
//
// It implements K-PKE.Decrypt according to FIPS 203 (DRAFT), Algorithm 14.
func pkeDecrypt(dk, c []byte) ([]byte, error) {
	if len(dk) != decryptionKeySize {
		return nil, errors.New("mlkem768: invalid decryption key length")
	}
	if len(c) != ciphertextSize {
		return nil, errors.New("mlkem768: invalid ciphertext length")
	}

	u := make([]ringElement, k)
	for i := range u {
		f, err := ringDecodeAndDecompress10(c[:encodingSize10])
		if err != nil {
			return nil, err
		}
		u[i] = f
		c = c[encodingSize10:]
	}

	v, err := ringDecodeAndDecompress4(c)
	if err != nil {
		return nil, err
	}

	s := make([]nttElement, k)
	for i := range s {
		f, err := polyByteDecode[nttElement](dk[:encodingSize12])
		if err != nil {
			return nil, err
		}
		s[i] = f
		dk = dk[encodingSize12:]
	}

	var v1NTT nttElement // s⊺ ◦ NTT(u)
	for i := range s {
		v1NTT = polyAdd(v1NTT, nttMul(s[i], ntt(u[i])))
	}
	w := polySub(v, inverseNTT(v1NTT))

	return ringCompressAndEncode1(nil, w), nil
}

// fieldElement is an integer modulo q, an element of ℤ_q. It is always reduced.
type fieldElement uint16

// fieldReduceOnce reduces a value a < 2q.
func fieldReduceOnce(a uint16) fieldElement {
	x := a - q
	// If x underflowed, then x >= 2¹⁶ - q > 2¹⁵, so the top bit is set.
	x += (x >> 15) * q
	return fieldElement(x)
}

func fieldAdd(a, b fieldElement) fieldElement {
	x := uint16(a + b)
	return fieldReduceOnce(x)
}

func fieldSub(a, b fieldElement) fieldElement {
	x := uint16(a - b + q)
	return fieldReduceOnce(x)
}

const (
	barrettMultiplier = 5039 // 4¹² / q
	barrettShift      = 24   // log₂(4¹²)
)

// fieldReduce reduces a value a < q² using Barrett reduction, to avoid
// potentially variable-time division.
func fieldReduce(a uint32) fieldElement {
	quotient := uint32((uint64(a) * barrettMultiplier) >> barrettShift)
	return fieldReduceOnce(uint16(a - quotient*q))
}

func fieldMul(a, b fieldElement) fieldElement {
	x := uint32(a) * uint32(b)
	return fieldReduce(x)
}

// compress maps a field element uniformly to the range 0 to 2ᵈ-1, according to
// FIPS 203 (DRAFT), Definition 4.5.
func compress(x fieldElement, d uint8) uint16 {
	// We want to compute (x * 2ᵈ) / q, rounded to nearest integer, with 1/2
	// rounding up (see FIPS 203 (DRAFT), Section 2.3).

	// Barrett reduction produces a quotient and a remainder in the range [0, 2q),
	// such that dividend = quotient * q + remainder.
	dividend := uint32(x) << d // x * 2ᵈ
	quotient := uint32(uint64(dividend) * barrettMultiplier >> barrettShift)
	remainder := dividend - quotient*q

	// Since the remainder is in the range [0, 2q), not [0, q), we need to
	// portion it into three spans for rounding.
	//
	//     [ 0,       q/2     ) -> round to 0
	//     [ q/2,     q + q/2 ) -> round to 1
	//     [ q + q/2, 2q      ) -> round to 2
	//
	// We can convert that to the following logic: add 1 if remainder > q/2,
	// then add 1 again if remainder > q + q/2.
	//
	// Note that if remainder > x, then ⌊x⌋ - remainder underflows, and the top
	// bit of the difference will be set.
	quotient += (q/2 - remainder) >> 31 & 1
	quotient += (q + q/2 - remainder) >> 31 & 1

	// quotient might have overflowed at this point, so reduce it by masking.
	var mask uint32 = (1 << d) - 1
	return uint16(quotient & mask)
}

// decompress maps a number x between 0 and 2ᵈ-1 uniformly to the full range of
// field elements, according to FIPS 203 (DRAFT), Definition 4.6.
func decompress(y uint16, d uint8) fieldElement {
	// We want to compute (y * q) / 2ᵈ, rounded to nearest integer, with 1/2
	// rounding up (see FIPS 203 (DRAFT), Section 2.3).

	dividend := uint32(y) * q
	quotient := dividend >> d // (y * q) / 2ᵈ

	// The d'th least-significant bit of the dividend (the most significant bit
	// of the remainder) is 1 for the top half of the values that divide to the
	// same quotient, which are the ones that round up.
	quotient += dividend >> (d - 1) & 1

	// quotient is at most (2¹¹-1) * q / 2¹¹ + 1 = 3328, so it didn't overflow.
	return fieldElement(quotient)
}

// ringElement is a polynomial, an element of R_q, represented as an array
// according to FIPS 203 (DRAFT), Section 2.4.
type ringElement [n]fieldElement

// polyAdd adds two ringElements or nttElements.
func polyAdd[T ~[n]fieldElement](a, b T) T {
	var s T
	for i := range s {
		s[i] = fieldAdd(a[i], b[i])
	}
	return s
}

// polySub subtracts two ringElements or nttElements.
func polySub[T ~[n]fieldElement](a, b T) T {
	var s T
	for i := range s {
		s[i] = fieldSub(a[i], b[i])
	}
	return s
}

// polyByteEncode appends the 384-byte encoding of f to b.
//
// It implements ByteEncode₁₂, according to FIPS 203 (DRAFT), Algorithm 4.
func polyByteEncode[T ~[n]fieldElement](b []byte, f T) []byte {
	out, B := sliceForAppend(b, encodingSize12)
	for i := 0; i < n; i += 2 {
		x := uint32(f[i]) | uint32(f[i+1])<<12
		B[0] = uint8(x)
		B[1] = uint8(x >> 8)
		B[2] = uint8(x >> 16)
		B = B[3:]
	}
	return out
}

// polyByteDecode decodes the 384-byte encoding of a polynomial.
//
// It implements ByteDecode₁₂, according to FIPS 203 (DRAFT), Algorithm 5.
func polyByteDecode[T ~[n]fieldElement](b []byte) (T, error) {
	if len(b) != encodingSize12 {
		return T{}, errors.New("mlkem768: invalid encoding length")
	}
	var f T
	for i := 0; i < n; i += 2 {
		d := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
		const mask12 = 0b1111_1111_1111
		f[i] = fieldReduceOnce(uint16(d & mask12))
		f[i+1] = fieldReduceOnce(uint16(d >> 12))
		b = b[3:]
	}
	return f, nil
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

// ringCompressAndEncode1 appends a 32-byte encoding of a ring element to s,
// compressing one coefficients per bit.
//
// It implements Compress₁, according to FIPS 203 (DRAFT), Definition 4.5,
// followed by ByteEncode₁, according to FIPS 203 (DRAFT), Algorithm 4.
func ringCompressAndEncode1(s []byte, f ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize1)
	for i := range b {
		b[i] = 0
	}
	for i := range f {
		b[i/8] |= uint8(compress(f[i], 1) << (i % 8))
	}
	return s
}

// ringDecodeAndDecompress1 decodes a 32-byte slice to a ring element where each
// bit is mapped to 0 or ⌈q/2⌋.
//
// It implements ByteDecode₁, according to FIPS 203 (DRAFT), Algorithm 5,
// followed by Decompress₁, according to FIPS 203 (DRAFT), Definition 4.6.
func ringDecodeAndDecompress1(b []byte) (ringElement, error) {
	if len(b) != encodingSize1 {
		return ringElement{}, errors.New("mlkem768: invalid message length")
	}
	var f ringElement
	for i := range f {
		b_i := b[i/8] >> (i % 8) & 1
		f[i] = fieldElement(b_i) * 1665 // 0 decompresses to 0, and 1 to 1665
	}
	return f, nil
}

// ringCompressAndEncode4 appends a 128-byte encoding of a ring element to s,
// compressing two coefficients per byte.
//
// It implements Compress₄, according to FIPS 203 (DRAFT), Definition 4.5,
// followed by ByteEncode₄, according to FIPS 203 (DRAFT), Algorithm 4.
func ringCompressAndEncode4(s []byte, f ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize4)
	for i := 0; i < n; i += 2 {
		b[i/2] = uint8(compress(f[i], 4) | compress(f[i+1], 4)<<4)
	}
	return s
}

// ringDecodeAndDecompress4 decodes a 128-byte encoding of a ring element where
// each four bits are mapped to an equidistant distribution.
//
// It implements ByteDecode₄, according to FIPS 203 (DRAFT), Algorithm 5,
// followed by Decompress₄, according to FIPS 203 (DRAFT), Definition 4.6.
func ringDecodeAndDecompress4(b []byte) (ringElement, error) {
	if len(b) != encodingSize4 {
		return ringElement{}, errors.New("mlkem768: invalid encoding length")
	}
	var f ringElement
	for i := 0; i < n; i += 2 {
		f[i] = fieldElement(decompress(uint16(b[i/2]&0b1111), 4))
		f[i+1] = fieldElement(decompress(uint16(b[i/2]>>4), 4))
	}
	return f, nil
}

// ringCompressAndEncode10 appends a 320-byte encoding of a ring element to s,
// compressing four coefficients per five bytes.
//
// It implements Compress₁₀, according to FIPS 203 (DRAFT), Definition 4.5,
// followed by ByteEncode₁₀, according to FIPS 203 (DRAFT), Algorithm 4.
func ringCompressAndEncode10(s []byte, f ringElement) []byte {
	s, b := sliceForAppend(s, encodingSize10)
	for i := 0; i < n; i += 4 {
		var x uint64
		x |= uint64(compress(f[i+0], 10))
		x |= uint64(compress(f[i+1], 10)) << 10
		x |= uint64(compress(f[i+2], 10)) << 20
		x |= uint64(compress(f[i+3], 10)) << 30
		b[0] = uint8(x)
		b[1] = uint8(x >> 8)
		b[2] = uint8(x >> 16)
		b[3] = uint8(x >> 24)
		b[4] = uint8(x >> 32)
		b = b[5:]
	}
	return s
}

// ringDecodeAndDecompress10 decodes a 320-byte encoding of a ring element where
// each ten bits are mapped to an equidistant distribution.
//
// It implements ByteDecode₁₀, according to FIPS 203 (DRAFT), Algorithm 5,
// followed by Decompress₁₀, according to FIPS 203 (DRAFT), Definition 4.6.
func ringDecodeAndDecompress10(b []byte) (ringElement, error) {
	if len(b) != encodingSize10 {
		return ringElement{}, errors.New("mlkem768: invalid encoding length")
	}
	var f ringElement
	for i := 0; i < n; i += 4 {
		x := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 | uint64(b[4])<<32
		b = b[5:]
		f[i] = fieldElement(decompress(uint16(x>>0&0b11_1111_1111), 10))
		f[i+1] = fieldElement(decompress(uint16(x>>10&0b11_1111_1111), 10))
		f[i+2] = fieldElement(decompress(uint16(x>>20&0b11_1111_1111), 10))
		f[i+3] = fieldElement(decompress(uint16(x>>30&0b11_1111_1111), 10))
	}
	return f, nil
}

// samplePolyCBD draws a ringElement from the special Dη distribution given a
// stream of random bytes generated by the PRF function, according to FIPS 203
// (DRAFT), Algorithm 7 and Definition 4.1.
func samplePolyCBD(s []byte, b byte) ringElement {
	prf := sha3.NewShake256()
	prf.Write(s)
	prf.Write([]byte{b})
	B := make([]byte, 128)
	prf.Read(B)

	// SamplePolyCBD simply draws four (2η) bits for each coefficient, and adds
	// the first two and subtracts the last two.

	var f ringElement
	for i := 0; i < n; i += 2 {
		b := B[i/2]
		b_7, b_6, b_5, b_4 := b>>7, b>>6&1, b>>5&1, b>>4&1
		b_3, b_2, b_1, b_0 := b>>3&1, b>>2&1, b>>1&1, b&1
		f[i] = fieldSub(fieldElement(b_0+b_1), fieldElement(b_2+b_3))
		f[i+1] = fieldSub(fieldElement(b_4+b_5), fieldElement(b_6+b_7))
	}
	return f
}

// nttElement is an NTT representation, an element of T_q, represented as an
// array according to FIPS 203 (DRAFT), Section 2.4.
type nttElement [n]fieldElement

// Performance optimization opportunity: use pointers to ringElements and
// nttElements throughout.

// gammas are the values ζ^2BitRev7(i)+1 mod q for each index i.
var gammas = [128]fieldElement{17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606, 2288, 1041, 1100, 2229, 1409, 1920, 2662, 667, 3281, 48, 233, 3096, 756, 2573, 2156, 1173, 3015, 314, 3050, 279, 1703, 1626, 1651, 1678, 2789, 540, 1789, 1540, 1847, 1482, 952, 2377, 1461, 1868, 2687, 642, 939, 2390, 2308, 1021, 2437, 892, 2388, 941, 733, 2596, 2337, 992, 268, 3061, 641, 2688, 1584, 1745, 2298, 1031, 2037, 1292, 3220, 109, 375, 2954, 2549, 780, 2090, 1239, 1645, 1684, 1063, 2266, 319, 3010, 2773, 556, 757, 2572, 2099, 1230, 561, 2768, 2466, 863, 2594, 735, 2804, 525, 1092, 2237, 403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775, 554, 886, 2443, 1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300, 2110, 1219, 2935, 394, 885, 2444, 2154, 1175}

// nttMul multiplies two nttElements.
//
// It implements MultiplyNTTs, according to FIPS 203 (DRAFT), Algorithm 10.
func nttMul(f, g nttElement) nttElement {
	var h nttElement
	for i := 0; i < 128; i++ {
		a0, a1 := f[2*i], f[2*i+1]
		b0, b1 := g[2*i], g[2*i+1]
		h[2*i] = fieldAdd(fieldMul(a0, b0), fieldMul(fieldMul(a1, b1), gammas[i]))
		h[2*i+1] = fieldAdd(fieldMul(a0, b1), fieldMul(a1, b0))
	}
	return h
}

// zetas are the values ζ^BitRev7(k) mod q for each index k.
var zetas = [128]fieldElement{1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154}

// ntt maps a ringElement to its nttElement representation.
//
// It implements NTT, according to FIPS 203 (DRAFT), Algorithm 8.
func ntt(f ringElement) nttElement {
	k := 1
	for len := 128; len >= 2; len /= 2 {
		for start := 0; start < 256; start += 2 * len {
			zeta := zetas[k]
			k++
			for j := start; j < start+len; j++ {
				t := fieldMul(zeta, f[j+len])
				f[j+len] = fieldSub(f[j], t)
				f[j] = fieldAdd(f[j], t)
			}
		}
	}
	return nttElement(f)
}

// inverseNTT maps a nttElement back to the ringElement it represents.
//
// It implements NTT⁻¹, according to FIPS 203 (DRAFT), Algorithm 9.
func inverseNTT(f nttElement) ringElement {
	k := 127
	for len := 2; len <= 128; len *= 2 {
		for start := 0; start < 256; start += 2 * len {
			zeta := zetas[k]
			k--
			for j := start; j < start+len; j++ {
				t := f[j]
				f[j] = fieldAdd(t, f[j+len])
				f[j+len] = fieldMul(zeta, fieldSub(f[j+len], t))
			}
		}
	}
	for i := range f {
		f[i] = fieldMul(f[i], 3303)
	}
	return ringElement(f)
}

// sampleNTT draws a uniformly random nttElement from a stream of uniformly
// random bytes generated by the XOF function, according to FIPS 203 (DRAFT),
// Algorithm 6 and Definition 4.2.
func sampleNTT(rho []byte, ii, jj byte) nttElement {
	B := sha3.NewShake128()
	B.Write(rho)
	B.Write([]byte{ii, jj})

	// SampleNTT essentially draws 12 bits at a time from r, interprets them in
	// little-endian, and rejects values higher than q, until it drew 256
	// values. (The rejection rate is approximately 19%.)
	//
	// To do this from a bytes stream, it draws three bytes at a time, and
	// splits the second one between the high-order bits of the first value and
	// the low-order bits of the second values.
	//
	//               r₀              r₁              r₂
	//       |- - - - - - - -|- - - - - - - -|- - - - - - - -|
	//
	//                   d₁                      d₂
	//       |- - - - - - - - - - - -|- - - - - - - - - - - -|
	//
	//                         r₁%16   r₁>>4
	//                       |- - - -|- - - -|
	//
	// Note that in little-endian, a modulo operation keeps the "leftmost"
	// least-significant bits, while a right-shift keeps the "rightmost"
	// most-significant bits.

	var a nttElement
	// Performance optimization opportunity: avoid escape via devirtualization.
	var b [3]byte
	var j int
	for {
		// Performance optimization opportunity: estimate the required (or
		// sufficient with overwhelming probability) number of bytes and
		// pre-read a larger buffer.
		B.Read(b[:])
		// Performance optimization opportunity: use binary.LittleEndian.Uint32.
		d := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
		const mask12 = 0b1111_1111_1111
		if d1 := d & mask12; d1 < q {
			a[j] = fieldElement(d1)
			j++
		}
		if j >= len(a) {
			break
		}
		if d2 := d >> 12; d2 < q {
			a[j] = fieldElement(d2)
			j++
		}
		if j >= len(a) {
			break
		}
	}
	return a
}
