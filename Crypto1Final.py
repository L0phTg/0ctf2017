#!/usr/bin/env python 
#-*- coding: utf-8 -*-
import re
import sys
import hashlib



def KSA(key):
    keylength = len(key)
    S = range(256)
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % keylength]) % 256
        S[i], S[j] = S[j], S[i]  # swap

    return S

def PRGA(S):
    i = 0
    j = 0
    
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # swap

        K = S[(S[i] + S[j]) % 256]
        yield K

def RC4(key):
    S = KSA(key)
    return PRGA(S)

def process(text, keystream):
    li = ['%x' % (ord(c) ^ keystream.next()) for c in hex(text)[2:]]
    res = ''.join(li)
    return int(res[:4], 16)

def cbc(plainBlock, keystream):
    secret = 0x4657
    Cipher = ""
    for p in plainBlock:
        Iv = int(p, 16) ^ secret
        secret = process(Iv, keystream)
        Cipher += hex(secret)[2:]
    return Cipher

if __name__ == '__main__':
    key = 'key'
    def convert_key(s):
        return [ord(c) for c in s]
    key = convert_key(key)
    keystream = RC4(key)

    flag = open('flag.txt').read()[:16]
    assert len(flag) == 16
    print ('flag{%s}' % flag)
    md5 = hashlib.md5()
    md5.update(flag.encode('utf-8'))
    md5Flag = md5.hexdigest()

    plainBlock = re.findall('....', md5Flag)

    Cipher = cbc(plainBlock, keystream)
    f = open('ciphertext1', 'w')
    f.write(Cipher+'\n')