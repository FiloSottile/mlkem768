# filippo.io/mlkem768

https://pkg.go.dev/filippo.io/mlkem768

Package mlkem768 implements the quantum-resistant key encapsulation method
ML-KEM (formerly known as Kyber), as specified in [NIST FIPS 203].

Only the recommended ML-KEM-768 parameter set is provided.

[NIST FIPS 203]: https://doi.org/10.6028/NIST.FIPS.203

This code was upstreamed in the standard library in Go 1.24, and as of Go 1.26
it is just a wrapper for the `crypto/mlkem` and `crypto/mlkem/mlkemtest`
packages.

## filippo.io/mlkem768/xwing

https://pkg.go.dev/filippo.io/mlkem768/xwing

The xwing package implements the hybrid quantum-resistant key encapsulation
method X-Wing, which combines X25519, ML-KEM-768, and SHA3-256 as specified
in [draft-connolly-cfrg-xwing-kem].

[draft-connolly-cfrg-xwing-kem]: https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-07.html

Most users will probably be better served by the hybrid KEMs in the
`crypto/hpke` package.
