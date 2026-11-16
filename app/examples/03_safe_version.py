# The same features written safely. Expect few or no findings.
import ast
import hashlib
import json
import os
import secrets
import sqlite3
import subprocess

DB_PASSWORD = os.environ.get("DB_PASSWORD")


def calculate(expression: str):
    return ast.literal_eval(expression)


def get_user(conn: sqlite3.Connection, username: str):
    return conn.execute("SELECT * FROM users WHERE name = ?", (username,)).fetchall()


def ping(host: str) -> str:
    if not host.replace(".", "").replace("-", "").isalnum():
        raise ValueError("invalid host")
    return subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, check=False).stdout


def load_session(blob: bytes):
    return json.loads(blob)


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1).hex()
