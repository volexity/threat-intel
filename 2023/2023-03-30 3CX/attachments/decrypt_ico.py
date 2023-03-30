# DecryptGCM
# Copyright (C) 2023 Volexity, Inc.

"""Decryptor for UTA0040 base64 blobs embedded in .ico files."""

# builtins
import argparse
import base64
import os
import re

# installables
from Crypto.Cipher import AES

SECRET_BYTES = b'\x21\xA1\xAC\xE1\xE6\x63\xBA\x45\x86\x4D\xF4\x57\xB2\x09\x18\x1E\xBD\x90\x10\x1B\x4A\x51\x28\x40\x38\x7C\xD2\x10\xE5\x8F\xA3\xF1'
NONCE_BYTES = b'\x3B\x8A\x08\xED\x0F\x9E\x08\xCA\x57\x21\x09\xEF'


def decode_blob(blob: bytes) -> str:
    ciphertext_bytes = base64.b64decode(blob)
    ciphertext = ciphertext_bytes[20:]
    aesCipher = AES.new(SECRET_BYTES, AES.MODE_GCM, NONCE_BYTES)
    tag_bytes = ciphertext_bytes[4:20]
    plaintext = aesCipher.decrypt_and_verify(ciphertext, tag_bytes)
    return plaintext.decode('UTF-8')


def identify_blob(file_path: str) -> bytes:
    matches = None
    blob = None
    with open(file_path, "rb") as infile:
        for line in infile:
            matches = re.findall(rb'\$(([A-Za-z0-9+\/]{4}){3,}([A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?)', line)
            if matches:
                blob = matches[0][0]
    return blob


def decode_file(file_path: str) -> None:
    print(f"Decoding file: {file_path}.")
    decoded = ""
    blob = identify_blob(file_path)
    if blob:
        decoded = decode_blob(blob)
        print(f"SUCCESS: {file_path}: {decoded}")
    else:
        print(f"FAILURE: {file_path}: No valid base64 blob identifiable within selected file.")


def _main():
    parser = argparse.ArgumentParser(
        prog="DecryptGCM",
        description="Decrypts base64 blobs embedded in malicious .ico files used by UTA0040."
    )
    parser.add_argument("input", type=str, help="file or folder of files to be decrypted.")
    args = parser.parse_args()

    files = []
    if os.path.isfile(args.input):
        files.append(args.input)
    elif os.path.isdir(args.input):
        for subfile in os.listdir(args.input):
            f = os.path.join(args.input, subfile)
            if os.path.isfile(f):
                files.append(f)
    else:
        exit(f"Couldn't find file or directory: {args.input}")

    for f in files:
        print(f"Attempting to decode file: {f}")
        try:
            decode_file(f)
        except Exception as e:
            print(e)


if __name__ == "__main__":
    _main()
