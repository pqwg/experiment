from random import choice, randint

q = 10753
bits_kept = 9

# Compression function in Kyber
def kyber_compress(q, x, d):
    rep = round(((1 << d) / q) * (x % q)) % (1 << d)
    assert (rep < (1 << d))
    return rep

# Decompression function in Kyber
def kyber_decompress(q, y, d):
    rep = round((q / (1 << d)) * (y % q))
    assert (rep < q)
    return rep

# Compute the distribution of the difference of Decompress(rpk)-rpk
Dlow = {}
for x in range(q):
    y = kyber_compress(q, x, bits_kept)
    z = kyber_decompress(q, y, bits_kept)
    diff = ((z - x) + (q >> 1)) % q - (q >> 1)
    if y in Dlow:
        Dlow[y].add(diff)
    else:
        Dlow[y] = set([diff])

# Now, we express this distribution more nicely

Dbis = {}
for i in range(2**bits_kept):
    Dbis[i] = set(range(-10, 11))
    if i == 256:
        Dbis[i].add(-11)

print(Dlow == Dbis)

if Dlow != Dbis:
    for i in set(Dlow.keys()).union(Dbis.keys()):
        for v in Dlow.get(i, set()) - Dbis.get(i, set()):
            print(f"lowbits={i}, diff={v} is in Dlow but not Dbis")
        for v in Dbis.get(i, set()) - Dlow.get(i, set()):
            print(f"lowbits={i}, diff={v} is in Dbis but not Dlow")

# Compute probabilities when using Dbis
probas = [0] * q
for y in Dbis:
    probahighbits = len(Dlow[y]) / q # compute the true probability of the high bits using Dlow
    for diff in Dbis[y]:
        final = kyber_decompress(q, y, bits_kept) - diff
        probas[final] += probahighbits * 1/len(Dbis[y]) # then obtain the probability for the final element

print(all([p*q-1 < 1e-10 for p in probas]))