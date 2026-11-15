#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Harmless educational test samples for the malware laboratory.

- EICAR: the industry-standard antivirus test string. It is NOT malware;
  it exists so scanners can prove they detect the pattern.
- A benign "hello world" script.
- An obfuscated-looking but harmless script (base64 of a print statement),
  used to demonstrate obfuscation indicators without any payload.
"""
import base64

EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
EICAR_NAME = "eicar-test.txt"

BENIGN_JS = "console.log('hello conan');\n"

OBFUSCATED_HARMLESS_JS = (
    "eval(atob('%s'));" % base64.b64encode(b"console.log('harmless demo');").decode()
)

SAMPLES = [
    {"name": EICAR_NAME, "kind": "antivirus test string",
     "content": EICAR, "expected": "EICAR test file detected"},
    {"name": "benign.js", "kind": "benign script",
     "content": BENIGN_JS, "expected": "clean"},
    {"name": "obfuscated-demo.js", "kind": "obfuscated demo (harmless)",
     "content": OBFUSCATED_HARMLESS_JS, "expected": "obfuscation indicators"},
]


def get_sample(name):
    for s in SAMPLES:
        if s["name"] == name:
            return s
    return None
