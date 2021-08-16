#!/usr/bin/env python

import base64
import sys

b64_data = base64.b64encode(sys.argv[2])
key = sys.argv[1]
enc_data = ""
for i, x in enumerate(b64_data):
    k = key[i % len(key) -1]
    enc_data += chr(ord(x) + ord(k))
print
print base64.b64encode(enc_data)
print