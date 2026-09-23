#!/usr/bin/env python3
"""Provision a vaultwarden service account for the locator.

Runs inside the locator container (has psycopg2 + cryptography + bao.py).
Creates the user row directly in vaultwarden's Postgres, then files the
credentials into OpenBao at secret/locator/vaultwarden so vaultwarden.py
can log in and mirror secrets as secure notes.

The account's master password and api key are generated here and exist
only in OpenBao after this runs.
"""

import base64, hashlib, json, os, secrets, sys, uuid
from datetime import datetime

import psycopg2
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import bao

EMAIL = os.environ.get("VW_EMAIL", "locator-service@theofficialblacksheepco.online")
NAME = "Locator Secrets Mirror"
PG_DSN = os.environ["VW_PG_DSN"]  # e.g. "host=.. port=5432 user=postgres password=.. dbname=vaultwarden"
BAO_PATH = "locator/vaultwarden"
CLIENT_KDF_ITER = 600000
SERVER_ITER = 600000

def pbkdf2(pw: bytes, salt: bytes, iters: int, n: int = 32) -> bytes:
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=n, salt=salt, iterations=iters).derive(pw)

def hkdf_expand(prk: bytes, info: str, n: int = 32) -> bytes:
    return HKDFExpand(algorithm=hashes.SHA256(), length=n, info=info.encode()).derive(prk)

def encstring(key64: bytes, data: bytes) -> str:
    """Bitwarden encstring type 2: AES-256-CBC + HMAC-SHA256."""
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    ct = Cipher(algorithms.AES(key64[:32]), modes.CBC(iv)).encryptor()
    ct = ct.update(padder.update(data) + padder.finalize()) + ct.finalize()
    mac = __import__("hmac").new(key64[32:], iv + ct, hashlib.sha256).digest()
    return f"2.{base64.b64encode(iv).decode()}|{base64.b64encode(ct).decode()}|{base64.b64encode(mac).decode()}"

def main():
    password = secrets.token_urlsafe(36)
    api_key = secrets.token_urlsafe(32)
    uid = str(uuid.uuid4())

    # client-side: master key -> master password hash -> stretched enc/mac
    master_key = pbkdf2(password.encode(), EMAIL.lower().encode(), CLIENT_KDF_ITER)
    mph = pbkdf2(master_key, password.encode(), 1)
    enc_key = hkdf_expand(master_key, "enc")
    mac_key = hkdf_expand(master_key, "mac")

    # the user's symmetric key, encrypted with the stretched master key
    sym_key = os.urandom(64)
    akey = encstring(enc_key + mac_key, sym_key)

    # RSA-2048 keypair: private key encrypted with the symmetric key
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_der = rsa_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    pub_der = rsa_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    private_key = encstring(sym_key, priv_der)
    public_key = base64.b64encode(pub_der).decode()

    # server-side: vaultwarden hashes the base64 *string* of the client hash
    salt = os.urandom(64)
    password_hash = pbkdf2(base64.b64encode(mph), salt, SERVER_ITER)

    conn = psycopg2.connect(PG_DSN)
    cur = conn.cursor()
    cur.execute("SELECT uuid FROM users WHERE email = %s", (EMAIL,))
    if cur.fetchone():
        print("account already exists — leaving it alone")
        return
    now = datetime.utcnow()
    cur.execute(
        """INSERT INTO users
           (uuid, created_at, updated_at, email, name, verified_at,
            password_hash, salt, password_iterations, password_hint,
            akey, private_key, public_key, security_stamp,
            equivalent_domains, excluded_globals,
            client_kdf_type, client_kdf_iter, enabled, api_key)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (uid, now, now, EMAIL, NAME, now,
         psycopg2.Binary(password_hash), psycopg2.Binary(salt), SERVER_ITER, None,
         akey, private_key, public_key, str(uuid.uuid4()),
         "", "", 0, CLIENT_KDF_ITER, True, api_key))
    conn.commit()
    print(f"created vaultwarden user {EMAIL} ({uid})")

    bao.write_secret("secret", BAO_PATH, {
        "email": EMAIL,
        "password": password,
        "api_key": api_key,
        "url": os.environ.get("VW_URL", "https://vault.theofficialblacksheepco.info"),
    })
    print(f"credentials filed at secret/{BAO_PATH}")

if __name__ == "__main__":
    main()
