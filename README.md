# Proxy Crypto

### Definition

$$
s : Secret Key\\
p : PublicKey = s \cdot G\\
m : Message\\
S : Signature
$$

### Basic Signature

$$
Sign: S(m, s) = s \cdot mG\\
Verify: e(p, mG) == e(G, S) \\
== e(sG, mG) == e(G, smG)
$$

### Proxy Re-Signature

$$
a_s : Alice's Secret\\
a_p : Alice's Public\\
b_s : Bob's Secret\\
b_p : Bob's Public\\
\\
dh_{ab} = ECDH(a_s, b_p) = ECDH(b_s, a_s)\\
rk_{ab} = b_s \cdot 1/dh_{ab}\\
\\
Sign_a : S_a = dh_{ab} \cdot m \cdot G\\
Resign_b : S_b = rk_{ab} \cdot S_a = b_s1/dh_{ab} \cdot dh_{ab}mG = b_smG
$$

