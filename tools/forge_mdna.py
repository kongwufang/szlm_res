#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""复刻 mdna/report：用真实 body JSON + 多种加密构造，观察服务端响应"""
import base64
import json
import time
import uuid
import urllib.request
import urllib.error
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP, AES

P = "F9BD0FBDACFE80FCF34370FBCFEE1A98"
APIKEY = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALxHQz5bfGTMX1+1SNNgar8RiOO9iJ8fDfU3gaGHeFhIAw507PXbGdswW2Vf4xzJ0eh1qm21Y6x2YtsKHv8H2sUCAwEAAQ=="
BU = "087040d4-85c1-4036-be86-510a1ca983b5"
rsa_key = RSA.import_key(base64.b64decode(APIKEY))
UA = "Dalvik/2.1.0 (Linux; U; Android 9; NX809J Build/PI)"


def build(kind, js):
    data = js.encode()
    if kind == "plain":
        return data
    if kind == "aes_only":
        key = hashlib.md5((js + P).encode()).digest()
        pad = 16 - len(data) % 16
        return AES.new(key, AES.MODE_ECB).encrypt(data + bytes([pad]) * pad)
    if kind == "rsa_plus_aes_pkcs1":
        key = uuid.uuid4().bytes
        r = PKCS1_v1_5.new(rsa_key).encrypt(key)
        pad = 16 - len(data) % 16
        a = AES.new(key, AES.MODE_ECB).encrypt(data + bytes([pad]) * pad)
        return r + a
    if kind == "rsa_plus_aes_oaep":
        key = uuid.uuid4().bytes
        r = PKCS1_OAEP.new(rsa_key).encrypt(key)
        pad = 16 - len(data) % 16
        a = AES.new(key, AES.MODE_ECB).encrypt(data + bytes([pad]) * pad)
        return r + a
    if kind == "hdr2_rsa_aes":
        key = uuid.uuid4().bytes
        r = PKCS1_v1_5.new(rsa_key).encrypt(key)
        pad = 16 - len(data) % 16
        a = AES.new(key, AES.MODE_ECB).encrypt(data + bytes([pad]) * pad)
        return b"\x00\xec" + r + a
    if kind == "hdr4_rsa_aes":
        key = uuid.uuid4().bytes
        r = PKCS1_v1_5.new(rsa_key).encrypt(key)
        pad = 16 - len(data) % 16
        a = AES.new(key, AES.MODE_ECB).encrypt(data + bytes([pad]) * pad)
        return b"\x00\xec\x8a\x3f" + r + a
    return data


def post(body, host="auni.telecome.cn", scheme="http"):
    r = uuid.uuid4().hex
    url = "%s://%s/a/mdna/report?v=8.7&t=m&p=%s&r=%s&n=0&l=2&h=0" % (scheme, host, P, r)
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"User-Agent": UA, "Content-Type": "application/json",
                                          "Accept": "application/json"})
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        return resp.status, resp.read()[:300]
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:200]
    except Exception as e:
        return None, repr(e)[:150].encode()


now = int(time.time() * 1000)
js = json.dumps({"s": "1", "r": 0, "w": 1, "t": str(now), "p": 3, "rg": 0, "bu": BU},
                separators=(",", ":"))
print("body JSON:", js)
print()

for kind in ["plain", "aes_only", "rsa_plus_aes_pkcs1", "rsa_plus_aes_oaep", "hdr2_rsa_aes", "hdr4_rsa_aes"]:
    body = build(kind, js)
    st, resp = post(body)
    print("%-22s len=%-5d -> %s %r" % (kind, len(body), st, resp[:120]))
