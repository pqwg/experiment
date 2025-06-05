# RKEM based on X25519

This is a mock implementation, that computes the following:

Note that this implementation *does not* necessarily meet RKEM security
guarantees!

 * Keygen: x25519 vanilla
 * encapsulation(`pk1`, `pk2`):
     1. generate ephemeral point `e`
     2. `ss = SHAKE256(pk1^e || pk2^e)`
     3. `ct = g^e`
 * decaps(`ct`, `pk1`, `pk2`) follows equivalently:
     1. `ct = g^e`
     2. `ss = SHAKE256(ct^sk1 || ct^sk2)`
