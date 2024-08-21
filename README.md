# filippo.io/mlkem768

https://pkg.go.dev/filippo.io/mlkem768

Package mlkem768 implements the quantum-resistant key encapsulation method
ML-KEM (formerly known as Kyber), as specified in [NIST FIPS 203].

Only the recommended ML-KEM-768 parameter set is provided.

[NIST FIPS 203]: https://doi.org/10.6028/NIST.FIPS.203

This package targets security, correctness, simplicity, readability, and
reviewability as its primary goals. All critical operations are performed in
constant time.

Variable and function names, as well as code layout, are selected to
facilitate reviewing the implementation against the NIST FIPS 203
document.

Reviewers unfamiliar with polynomials or linear algebra might find the
background at https://words.filippo.io/kyber-math/ useful.

This code is aimed at being upstreamed in the standard library.
