#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Encryption tests — offline, includes NIST vectors via self_test()."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from conan.core import encryption


class TestEncryption(unittest.TestCase):
    def test_vectors(self):
        ok, msg = encryption.self_test()
        self.assertTrue(ok, msg)

    def test_round_trip(self):
        blob = encryption.encrypt_text("correct horse", "secret report data")
        self.assertEqual(encryption.decrypt_text("correct horse", blob),
                         "secret report data")

    def test_wrong_password_fails(self):
        blob = encryption.encrypt_text("pass1", "data")
        with self.assertRaises(Exception):
            encryption.decrypt_text("pass2", blob)

    def test_tampered_blob_fails(self):
        import base64
        blob = encryption.encrypt_text("pass", "data")
        raw = bytearray(base64.b64decode(blob))
        raw[-1] ^= 0x01
        with self.assertRaises(Exception):
            encryption.decrypt_text("pass", base64.b64encode(bytes(raw)).decode())

    def test_aes_block(self):
        key = bytes(range(32))
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(encryption.aes256_encrypt_block(key, pt).hex(),
                         "8ea2b7ca516745bfeafc49904b496089")


if __name__ == "__main__":
    unittest.main()
