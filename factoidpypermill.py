#!/usr/bin/env python
# pypermill -- simple Factom paper wallet generator written in Python
from os import urandom
from hashlib import sha256
import ed25519

FactoidPrefix = b'\x5f\xb1'
FactoidPrivatePrefix = b'\x64\x78'

if str != bytes:  # dummy ord() function for Python 3.X
    def ord(c):
        return c


def SHA256D(bstr):
    return sha256(sha256(bstr).digest()).digest()


def Base58(bstr):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = 0
    p = 1
    for b in bstr[::-1]:
        num += p*ord(b)
        p <<= 8

    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result += alphabet[mod]

    return result[::-1]


def ConvertAddressToUserStr(prefix, addr):
    data = prefix + addr
    return Base58(data + SHA256D(data)[:4])


def GeneratePaperWalletStrings(privatekey):
    # convert private key
    privaddr = ConvertAddressToUserStr(FactoidPrivatePrefix, privatekey)

    # determine public key
    publickey = ed25519.SigningKey(privatekey).get_verifying_key().to_bytes()
    # convert to RCD_1 address format (simple signature)
    publickey = b'\x01' + publickey
    publickey = SHA256D(publickey)
    publicaddr = ConvertAddressToUserStr(FactoidPrefix, publickey)

    return privaddr, publicaddr


def main():
    privaddr, publicaddr = GeneratePaperWalletStrings(urandom(32))
    print("New Factoid Private Key: %s" % privaddr)
    print("New Factoid Address:     %s" % publicaddr)


if __name__ == "__main__":
    main()
