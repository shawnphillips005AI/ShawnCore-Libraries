#!/usr/bin/env python3
"""Independent re-derivation of one complete ShawnCore session, printed as `name = hex` lines.

Everything here is computed outside the Rust crates: ML-KEM-1024 by OpenSSL >= 3.5, X25519 by an
RFC 7748 reference ladder, HKDF/HMAC/SHA-384 by Python's hashlib/hmac, and ChaCha20 by OpenSSL.
The protocol layout (transcript, key split, packet MAC framing) is re-implemented from the
documented design, so agreement with the Rust implementation is cross-implementation evidence for
these inputs only. It is not a NIST vector and does not authenticate any peer.
"""
import hashlib
import hmac
import os
import subprocess
import tempfile

P = 2**255 - 19


def x25519(scalar: bytes, u: bytes) -> bytes:
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    scalar_int = int.from_bytes(k, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (scalar_int >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % P
        aa = (a * a) % P
        b = (x2 - z2) % P
        bb = (b * b) % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = (d * a) % P
        cb = (c * b) % P
        x3 = ((da + cb) ** 2) % P
        z3 = (x1 * ((da - cb) ** 2)) % P
        x2 = (aa * bb) % P
        z2 = (e * (aa + 121665 * e)) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def run(*args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, **kwargs).stdout


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, t = b"", b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha384).digest()
        out += t
        counter += 1
    return out[:length]


def chacha20(key: bytes, nonce: bytes, data: bytes) -> bytes:
    iv = (0).to_bytes(4, "little") + nonce
    return run("openssl", "enc", "-chacha20", "-K", key.hex(), "-iv", iv.hex(), input=data)


def seal(key64: bytes, aad: bytes, plaintext: bytes, sequence: int = 0):
    enc_key, mac_key = key64[:32], key64[32:]
    nonce = sequence.to_bytes(8, "little") + bytes(4)
    ciphertext = chacha20(enc_key, nonce, plaintext)
    framed = len(aad).to_bytes(8, "big") + len(ciphertext).to_bytes(8, "big") + nonce + aad + ciphertext
    return ciphertext, hmac.new(mac_key, framed, hashlib.sha384).digest()


def main():
    keygen_entropy = bytes((i * 7 + 3) % 256 for i in range(96))
    encap_entropy = bytes((i * 11 + 5) % 256 for i in range(64))
    salt, info, aad = b"session-salt", b"session-info", b"hdr"
    plain_e2k = b"encap to keygen packet"
    plain_k2e = b"keygen to encap packet"

    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        run("openssl", "genpkey", "-algorithm", "ML-KEM-1024", "-pkeyopt",
            "hexseed:" + keygen_entropy[:64].hex(), "-out", "k.pem")
        run("openssl", "pkey", "-in", "k.pem", "-pubout", "-out", "pub.pem")
        run("openssl", "pkeyutl", "-encap", "-pubin", "-inkey", "pub.pem", "-pkeyopt",
            "hexikme:" + encap_entropy[:32].hex(), "-out", "ct.bin", "-secret", "ss.bin")
        kem_ct = open("ct.bin", "rb").read()
        pq_secret = open("ss.bin", "rb").read()

    base = b"\x09" + bytes(31)
    keygen_x_sk, encap_x_sk = keygen_entropy[64:96], encap_entropy[32:64]
    keygen_x_pk, encap_x_pk = x25519(keygen_x_sk, base), x25519(encap_x_sk, base)
    classical = x25519(encap_x_sk, keygen_x_pk)
    assert classical == x25519(keygen_x_sk, encap_x_pk)

    transcript = hashlib.sha384(b"ShawnCore-v1.3-hybrid-handshake" + kem_ct + encap_x_pk + info).digest()
    prk = hmac.new(salt, pq_secret + classical, hashlib.sha384).digest()
    okm = hkdf_expand(prk, transcript, 128)

    encap_tx = okm[32:96]
    keygen_tx = okm[0:32] + okm[96:128]
    e2k_ct, e2k_tag = seal(encap_tx, aad, plain_e2k)
    k2e_ct, k2e_tag = seal(keygen_tx, aad, plain_k2e)

    for name, value in [
        ("keygen_entropy", keygen_entropy), ("encap_entropy", encap_entropy),
        ("salt", salt), ("info", info), ("aad", aad),
        ("kem_ct", kem_ct), ("encap_x25519_pk", encap_x_pk), ("keygen_x25519_pk", keygen_x_pk),
        ("e2k_plaintext", plain_e2k), ("e2k_ct", e2k_ct), ("e2k_tag", e2k_tag),
        ("k2e_plaintext", plain_k2e), ("k2e_ct", k2e_ct), ("k2e_tag", k2e_tag),
    ]:
        print(f"session.{name} = {value.hex()}")


if __name__ == "__main__":
    main()
