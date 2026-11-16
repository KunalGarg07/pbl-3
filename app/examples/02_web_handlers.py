# Deliberately vulnerable demo: several common mistakes in one small module.
import hashlib
import pickle
import sqlite3
import subprocess

DB_PASSWORD = "admin123"


def get_user(conn: sqlite3.Connection, username: str):
    query = "SELECT * FROM users WHERE name = '%s'" % username
    return conn.execute(query).fetchall()


def ping(host: str) -> str:
    return subprocess.check_output("ping -c 1 " + host, shell=True).decode()


def load_session(blob: bytes):
    return pickle.loads(blob)


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()
