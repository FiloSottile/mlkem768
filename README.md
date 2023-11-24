# filippo.io/mlkem768

https://pkg.go.dev/filippo.io/mlkem768

Package mlkem768 implements the quantum-resistant key encapsulation method
ML-KEM (formerly known as Kyber).

Only the recommended ML-KEM-768 parameter set is provided.

The version currently implemented is the one specified by [NIST FIPS 203 ipd],
with the unintentional transposition of the matrix A reverted to match the
behavior of [Kyber version 3.0]. Future v0 versions of this package might
introduce backwards incompatible changes to implement changes to FIPS 203.

[Kyber version 3.0]: https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
[NIST FIPS 203 ipd]: https://doi.org/10.6028/NIST.FIPS.203.ipd

This package targets security, correctness, simplicity, readability, and
reviewability as its primary goals. All critical operations are performed in
constant time.

Variable and function names, as well as code layout, are selected to
facilitate reviewing the implementation against the NIST FIPS 203 ipd
document.

Reviewers unfamiliar with polynomials or linear algebra might find the
background at https://words.filippo.io/kyber-math/ useful.

This code is aimed at being upstreamed in the standard library.
