#!/usr/bin/env python

import base64
import sys

key = sys.argv[1]
b64_data = sys.argv[2]

enc_data = base64.b64decode(b64_data)

dec_data = ""
for i, x in enumerate(enc_data):
    k = key[i % len(key) -1]
    dec_data += chr(ord(x) - ord(k))
print
print base64.b64decode(dec_data)
print