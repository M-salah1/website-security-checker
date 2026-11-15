#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multi-layer encryption for CONAN FRAMEWORK v5.6.

- AES-256-GCM for sensitive local data (pure-Python implementation, verified
  against the FIPS-197 and NIST GCM test vectors; the `cryptography` library
  is used instead when installed, for speed).
- Argon2id for password-based key derivation when argon2-cffi is installed,
  otherwise scrypt (stdlib, memory-hard) as the fallback.
- HMAC-SHA256 integrity is provided by the GCM authentication tag.
- Keys are never hardcoded: derived from a passphrase, or generated into a
  key file with mode 0600. Never claim 100% security — this protects data at
  rest on the local device only.

Stored blob format: b"CN1" + salt(16) + nonce(12) + tag(16) + ciphertext.
"""
import base64
import hashlib
import hmac as hmac_mod
import os

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _CryptoAESGCM
    HAS_CRYPTO = True
except Exception:
    _CryptoAESGCM = None
    HAS_CRYPTO = False

try:
    from argon2.low_level import hash_secret_raw as _argon2_raw, Type as _Argon2Type
    HAS_ARGON2 = True
except Exception:
    _argon2_raw = None
    _Argon2Type = None
    HAS_ARGON2 = False

MAGIC = b"CN1"
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16


# ---------------------------------------------------------------- AES-256
def _gf_mul(a, b):
    """Multiply in GF(2^8), polynomial x^8+x^4+x^3+x+1."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _gf_pow(a, e):
    r = 1
    while e:
        if e & 1:
            r = _gf_mul(r, a)
        a = _gf_mul(a, a)
        e >>= 1
    return r


def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _sbox_byte(x):
    inv = 0 if x == 0 else _gf_pow(x, 254)
    return inv ^ _rotl8(inv, 1) ^ _rotl8(inv, 2) ^ _rotl8(inv, 3) ^ _rotl8(inv, 4) ^ 0x63


_SBOX = [_sbox_byte(i) for i in range(256)]
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
         0x6C, 0xD8, 0xAB, 0x4D]


def _key_expansion(key):
    Nk, Nr = 8, 14
    w = [list(key[4 * i:4 * i + 4]) for i in range(Nk)]
    for i in range(Nk, 4 * (Nr + 1)):
        temp = list(w[i - 1])
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // Nk - 1]
        elif Nk > 6 and i % Nk == 4:
            temp = [_SBOX[b] for b in temp]
        w.append([w[i - Nk][j] ^ temp[j] for j in range(4)])
    return w


def _add_round_key(state, w, rnd):
    for c in range(4):
        for r in range(4):
            state[r][c] ^= w[rnd * 4 + c][r]


def _sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = _SBOX[state[r][c]]


def _shift_rows(state):
    for r in range(1, 4):
        row = [state[r][(c + r) % 4] for c in range(4)]
        for c in range(4):
            state[r][c] = row[c]


def _mix_columns(state):
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        state[0][c] = _gf_mul(a[0], 2) ^ _gf_mul(a[1], 3) ^ a[2] ^ a[3]
        state[1][c] = a[0] ^ _gf_mul(a[1], 2) ^ _gf_mul(a[2], 3) ^ a[3]
        state[2][c] = a[0] ^ a[1] ^ _gf_mul(a[2], 2) ^ _gf_mul(a[3], 3)
        state[3][c] = _gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ _gf_mul(a[3], 2)


def aes256_encrypt_block(key, block):
    """Encrypt one 16-byte block with AES-256."""
    if len(key) != 32 or len(block) != 16:
        raise ValueError("AES-256 needs a 32-byte key and 16-byte block")
    w = _key_expansion(key)
    state = [[block[4 * c + r] for c in range(4)] for r in range(4)]
    _add_round_key(state, w, 0)
    for rnd in range(1, 14):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, w, rnd)
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, w, 14)
    return bytes(state[r][c] for c in range(4) for r in range(4))


# ---------------------------------------------------------------- GCM
def _gf128_mul(x, y):
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ 0xE1000000000000000000000000000000
        else:
            v >>= 1
    return z


def _ghash(h, aad, ct):
    def pad(data):
        if len(data) % 16 == 0:
            return data
        return data + b"\x00" * (16 - len(data) % 16)

    y = 0
    for data in (pad(aad), pad(ct)):
        for i in range(0, len(data), 16):
            block = int.from_bytes(data[i:i + 16], "big")
            y = _gf128_mul(y ^ block, h)
    len_block = (len(aad) * 8) << 64 | (len(ct) * 8)
    return _gf128_mul(y ^ len_block, h)


def _inc32(counter):
    prefix, ctr = counter[:12], int.from_bytes(counter[12:], "big")
    return prefix + ((ctr + 1) & 0xFFFFFFFF).to_bytes(4, "big")


def _gcm_crypt(key, nonce, data, aad=b"", encrypt=True):
    """CTR keystream + GHASH. GHASH always runs over the CIPHERTEXT."""
    h = int.from_bytes(aes256_encrypt_block(key, b"\x00" * 16), "big")
    j0 = nonce + b"\x00\x00\x00\x01"
    out = bytearray()
    ctr = _inc32(j0)
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        ks = aes256_encrypt_block(key, ctr)
        out += bytes(a ^ b for a, b in zip(chunk, ks))
        ctr = _inc32(ctr)
    ct = bytes(out) if encrypt else data
    s = _ghash(h, aad, ct)
    tag = bytes(a ^ b for a, b in zip(aes256_encrypt_block(key, j0),
                                     s.to_bytes(16, "big")))
    return bytes(out), tag


def gcm_encrypt(key, nonce, plaintext, aad=b""):
    return _gcm_crypt(key, nonce, plaintext, aad, encrypt=True)


def gcm_decrypt(key, nonce, ciphertext, tag, aad=b""):
    if HAS_CRYPTO:
        return _CryptoAESGCM(key).decrypt(nonce, ciphertext + tag, aad)
    plain, calc = _gcm_crypt(key, nonce, ciphertext, aad, encrypt=False)
    if not hmac_mod.compare_digest(calc, tag):
        raise ValueError("GCM tag mismatch — wrong key or corrupted data")
    return plain


# ---------------------------------------------------------------- KDF / API
def derive_key(password, salt):
    """Argon2id when available, otherwise scrypt (stdlib, memory-hard)."""
    if isinstance(password, str):
        password = password.encode()
    if HAS_ARGON2:
        return _argon2_raw(password, salt, time_cost=2, memory_cost=65536,
                           parallelism=1, hash_len=32, type=_Argon2Type.ID)
    return hashlib.scrypt(password, salt=salt, n=16384, r=8, p=1, dklen=32)


def encrypt_bytes(password, plaintext, aad=b""):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt)
    if HAS_CRYPTO:
        ct_tag = _CryptoAESGCM(key).encrypt(nonce, plaintext, aad)
        ct, tag = ct_tag[:-TAG_LEN], ct_tag[-TAG_LEN:]
    else:
        ct, tag = gcm_encrypt(key, nonce, plaintext, aad)
    return MAGIC + salt + nonce + tag + ct


def decrypt_bytes(password, blob, aad=b""):
    if not blob.startswith(MAGIC):
        raise ValueError("Not a CONAN encrypted blob")
    rest = blob[len(MAGIC):]
    salt, nonce, tag = rest[:SALT_LEN], rest[SALT_LEN:SALT_LEN + NONCE_LEN], \
        rest[SALT_LEN + NONCE_LEN:SALT_LEN + NONCE_LEN + TAG_LEN]
    ct = rest[SALT_LEN + NONCE_LEN + TAG_LEN:]
    key = derive_key(password, salt)
    if HAS_CRYPTO:
        return _CryptoAESGCM(key).decrypt(nonce, ct + tag, aad)
    return gcm_decrypt(key, nonce, ct, tag, aad)


def encrypt_text(password, text):
    return base64.b64encode(encrypt_bytes(password, text)).decode()


def decrypt_text(password, b64):
    return decrypt_bytes(password, base64.b64decode(b64)).decode()


def generate_key_file(path):
    key = base64.b64encode(os.urandom(32)).decode()
    with open(path, "w", encoding="utf-8") as f:
        f.write(key)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    return key


def self_test():
    """FIPS-197 AES-256 vector + NIST GCM test case 3 (256-bit key)."""
    key = bytes(range(32))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    want_ct = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    if aes256_encrypt_block(key, pt) != want_ct:
        return False, "AES-256 FIPS-197 vector failed"
    zkey = b"\x00" * 32
    ziv = b"\x00" * 12
    zpt = b"\x00" * 16
    ct, tag = gcm_encrypt(zkey, ziv, zpt)
    if ct.hex() != "cea7403d4d606b6e074ec5d3baf39d18":
        return False, "GCM ciphertext vector failed: " + ct.hex()
    if tag.hex() != "d0d1c8a799996bf0265b98b5d48ab919":
        return False, "GCM tag vector failed: " + tag.hex()
    if gcm_decrypt(zkey, ziv, ct, tag) != zpt:
        return False, "GCM decrypt failed"
    rt = encrypt_text("test-pass", "hello conan")
    if decrypt_text("test-pass", rt) != "hello conan":
        return False, "encrypt/decrypt round-trip failed"
    return True, "AES-256-GCM + KDF OK (vectors pass)"
