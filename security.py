from argon2 import PasswordHasher, exceptions
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
from flask import Flask, request, render_template, redirect, url_for, session, flash
from argon2 import PasswordHasher
import argon2.exceptions
import mysql.connector as connector
import os
import re
import secrets
import hashlib
import base64
import bcrypt


# Secret key
secret_key = secrets.token_hex(32)

# Validation Functions


def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None


def password_policy(password):
    if len(password) < 8:
        flash("Password should be at least 8 characters long")
        return False
    if not any(char.isdigit() for char in password):
        flash("Password should contain at least one number")
        return False
    if not any(char.isupper() for char in password):
        flash("Password should contain at least one uppercase letter")
        return False
    if not any(char.islower() for char in password):
        flash("Password should contain at least one lowercase letter")
        return False
    if not any(char in '!@#$%^&*()_+}{":?><,./;' for char in password):
        flash("Password should contain at least one special character")
        return False
    return True

# Argon2 Hashing


def aragon_hash_password(password: str) -> str:
    ph = PasswordHasher()
    salt = os.urandom(16)
    hashed_password = ph.hash(password.encode('utf-8') + salt)
    return hashed_password



def aragon_verify_password(hashed_password: str, password: str) -> bool:
    ph = PasswordHasher()
    try:
        ph.verify(hashed_password, password)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False

# Scrypt Hashing


def hash_password2(password: str) -> str:
    salt = os.urandom(16)
    backend = default_backend()
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=backend)
    hashed_password = kdf.derive(password.encode())
    return urlsafe_b64encode(salt + hashed_password).decode('utf-8')


def verify_password2(hashed_password: str, password: str) -> bool:
    decoded_hashed_password = urlsafe_b64decode(
        hashed_password.encode('utf-8'))
    salt = decoded_hashed_password[:16]
    stored_hash = decoded_hashed_password[16:]
    backend = default_backend()
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=backend)

    try:
        kdf.verify(password.encode(), stored_hash)
        return True
    except Exception:
        return False

# SHA-256 Hashing


def hash_password_sha256(password: str, salt: str) -> str:
    password_salt = password + salt
    hashed_password = hashlib.sha256(password_salt.encode()).hexdigest()
    return hashed_password


def generate_salt() -> str:
    return base64.b64encode(os.urandom(16)).decode()

# Bcrypt Hashing


def hash_password(password):
    if not password_policy(password):
        return False
    salt = bcrypt.gensalt(rounds=12)
    password_hash = bcrypt.hashpw(password.encode(), salt)
    return password_hash


def verify_password(password, password_hash):
    if bcrypt.checkpw(password.encode(), password_hash):
        return True
    else:
        return False
