"""
gen_gauss.py
Copyright (c) 2024 Sparrow KEM Team. See LICENSE.

=== Code for re-creating the Gaussian table constants used in gauss_sample.c.
"""

from sage.all import *
from random import randrange

n = 256
k = 3
ell = 2

R = RealField(200)
# sigy = R(0.55)
# sigy = R(2.6)
sigy = R(2^6)

sigy = R(sigy)

bitsec = 72
C = sqrt(log(2) * (2*bitsec + 1))
maxy = ceil(sigy*C)


def gauss(x, sig):
    return exp(-x**2/(2*sig**2))

s = R(1)
for i in range(1, maxy+1):
    s += gauss(i, sigy)

table = []
acc = R(0)
for i in range(maxy, 0, -1):
    acc += gauss(i, sigy)/s
    table.append(acc)

table = table[::-1]
nbbits = 72
inttable = list(map(lambda x: int(round(x * (1<<nbbits))), table))

# drop zeroes in the tail
while inttable[-1] == 0:
    del inttable[-1]

# print table, with 32bits integers per element
for c in inttable:
    # decompose c = v3 + 2**24 * (v2 + 2**24 * v1)
    v3 = c % (1 << 24)
    c >>= 24
    v2 = c % (1 << 24)
    c >>= 24
    v1 = c % (1 << 24)

    print(f"    {v1}u, {v2}u, {v3}u,")