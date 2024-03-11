#!/usr/bin/python3

from Crypto.Util.RFC1751 import key_to_english
import mnemonic
import binascii
import base62
from base58 import b58encode_check
from os.path import exists
import sys

from hashlib import sha512
from hashlib import sha256
from hashlib import blake2b
from hashlib import sha3_512

if len(sys.argv) > 2:
    print("Too many arguments.")
    quit()
elif len(sys.argv) == 2:
    filename = sys.argv[1]
    if not exists(filename):
        print("File not found.")
        quit()
else:
    print("Filename not specified.")
    quit()

def print_the_digest(digest):

    # we need it also for bitcoin.encode_privkey()
    digest_HEX = binascii.b2a_hex(digest).decode("utf-8")

    print ("Hex:", digest_HEX)

    print ("Base64:", binascii.b2a_base64(digest, newline=False).decode("utf-8"))

    print ("Base62:", base62.encodebytes(digest))

    print ("Base58Check:", b58encode_check(digest).decode("utf-8"))

    if 16 <= len(digest) <= 32:
        print ("BIP39 mnemonic:", mnemonic.Mnemonic('english').to_mnemonic(digest))
    elif len(digest) == 64:
        print ("BIP39 mnemonic (1):", mnemonic.Mnemonic('english').to_mnemonic(digest[:32]))
        print ("BIP39 mnemonic (2):", mnemonic.Mnemonic('english').to_mnemonic(digest[32:]))
        print (" * This digest is 512 bits long, so it's split in two parts")
        print ("   and this way two BIP39 mnemonic codes are produced.")

    print ("RFC1751 mnemonic:", key_to_english(digest))

BLOCKSIZE = 2**16

my_sha_256 = sha256()
my_sha_512 = sha512()
my_sha_3_512 = sha3_512()
my_blake2b_8 = blake2b(digest_size=8)
my_blake2b_16 = blake2b(digest_size=16)

with open(filename, 'rb') as big_file:
    file_buffer = big_file.read(BLOCKSIZE)
    while len(file_buffer) > 0:
        my_sha_256.update(file_buffer)
        my_sha_512.update(file_buffer)
        my_sha_3_512.update(file_buffer)
        my_blake2b_8.update(file_buffer)
        my_blake2b_16.update(file_buffer)
        file_buffer = big_file.read(BLOCKSIZE)
        
digest_sha_256=my_sha_256.digest()
digest_sha_512 = my_sha_512.digest()
digest_sha_3_512 = my_sha_3_512.digest()
digest_blake2b_8= my_blake2b_8.digest()
digest_blake2b_16= my_blake2b_16.digest()

print("\n=== Blake2b-64 hash: ===\n")
print_the_digest(digest_blake2b_8)

print("\n=== Blake2b-128 hash: ===\n")
print_the_digest(digest_blake2b_16)

print("\n=== SHA-256 hash: ===\n")
print_the_digest(digest_sha_256)

print("\n=== SHA-512 hash: ===\n")
print_the_digest(digest_sha_512)

print("\n=== SHA3-512 hash: ===\n")
print_the_digest(digest_sha_3_512)


