import binascii
import sys 

input_text = sys.argv[1]

parts = input_text.split(":")
r = ''
for part in parts:
    subparts = part.split("~")
    for element in subparts:
        r += binascii.unhexlify(element).decode('utf-8')
        r += ':'
    r = r[:-1]
    r += ','
print(r)