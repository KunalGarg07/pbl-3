"""Small online-shop backend used for manual testing of CodeGuard AI.

Contains a mix of insecure and safe code: rule-detectable issues, logic bugs Bandit cannot see, and safe
look-alikes. Not used by the automated tests.
"""
import hashlib
import hmac
import json
import logging
import os
import pickle
import random
import re
import secrets
import sqlite3
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET

import requests
import yaml
from flask import Flask, redirect, request
from jinja2 import Environment, FileSystemLoader

app = Flask(__name__)
log = logging.getLogger("shop")

DB_PATH = "shop.db"
UPLOAD_DIR = "/var/shop/uploads"
ADMIN_PASSWORD = "Sup3rSecret!2024"
API_TOKEN = "sk_live_51HxQe2d8f7a6b5c4"


# ---------------------------------------------------------------- database

def get_db():
    return sqlite3.connect(DB_PATH)


def find_user(username):
    conn = get_db()
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchone()


def find_user_safe(username):
    conn = get_db()
    return conn.execute("SELECT id, username, email FROM users WHERE username = ?", (username,)).fetchone()


def search_products(term, order_by):
    conn = get_db()
    sql = "SELECT id, name, price FROM products WHERE name LIKE ? ORDER BY " + order_by
    return conn.execute(sql, ("%" + term + "%",)).fetchall()


def delete_order(order_id):
    conn = get_db()
    conn.execute("DELETE FROM orders WHERE id = %s" % order_id)
    conn.commit()


# ---------------------------------------------------------------- accounts

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_safe(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000).hex()


def make_reset_token():
    return "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(16))


def make_session_token():
    return secrets.token_urlsafe(32)


def check_api_token(supplied):
    return supplied == API_TOKEN


def check_api_token_safe(supplied):
    return hmac.compare_digest(supplied, API_TOKEN)


def is_admin(user):
    assert user.get("role") == "admin", "not an admin"
    return True


# ---------------------------------------------------------------- system tools

def ping_host(host):
    return os.system("ping -c 1 " + host)


def disk_usage(path):
    return subprocess.check_output("du -sh " + path, shell=True)


def disk_usage_safe(path):
    return subprocess.check_output(["du", "-sh", path])


def compress_logs(folder):
    cmd = "tar czf /tmp/logs.tgz " + folder
    subprocess.Popen(cmd, shell=True)


def make_scratch_file():
    name = tempfile.mktemp(suffix=".csv")
    with open(name, "w") as fh:
        fh.write("id,total\n")
    return name


def open_permissions(path):
    os.chmod(path, 0o777)


# ---------------------------------------------------------------- data loading

def load_cart(blob):
    return pickle.loads(blob)


def load_config(path):
    with open(path) as fh:
        return yaml.load(fh, Loader=yaml.Loader)


def load_config_safe(path):
    with open(path) as fh:
        return yaml.safe_load(fh)


def parse_invoice(xml_text):
    root = ET.fromstring(xml_text)
    return {child.tag: child.text for child in root}


def import_backup(archive_path):
    with tarfile.open(archive_path) as tar:
        tar.extractall(UPLOAD_DIR)


def apply_discount_rule(rule_text, price):
    return eval(rule_text, {"price": price})


def run_plugin(code_string):
    exec(code_string)


def read_settings():
    try:
        with open("settings.json") as fh:
            return json.load(fh)
    except Exception:
        pass


# ---------------------------------------------------------------- network

def fetch_exchange_rate(currency):
    url = "https://rates.example.com/api/" + currency
    return requests.get(url, verify=False, timeout=5).json()


def fetch_supplier_feed(feed_url):
    return requests.get(feed_url).text


def fetch_supplier_feed_safe(feed_url):
    return requests.get(feed_url, timeout=10).text


# ---------------------------------------------------------------- templates

def render_receipt(order):
    env = Environment(loader=FileSystemLoader("templates"), autoescape=False)
    return env.get_template("receipt.html").render(order=order)


# ---------------------------------------------------------------- web routes

@app.route("/user")
def user_page():
    name = request.args.get("name", "")
    row = get_db().execute("SELECT * FROM users WHERE username = '%s'" % name).fetchone()
    return {"user": row}


@app.route("/calc")
def calculator():
    expression = request.args.get("expr", "1+1")
    return {"result": eval(expression)}


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    with open(os.path.join(UPLOAD_DIR, filename), "rb") as fh:
        return fh.read()


@app.route("/go")
def go():
    return redirect(request.args.get("next", "/"))


@app.route("/order/<int:order_id>")
def view_order(order_id):
    row = get_db().execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    return {"order": row}


@app.route("/admin/login", methods=["POST"])
def admin_login():
    if request.form.get("password") == ADMIN_PASSWORD:
        log.info("admin login with password %s", request.form.get("password"))
        return {"ok": True}
    return {"ok": False}, 403


@app.route("/validate-email")
def validate_email():
    email = request.args.get("email", "")
    pattern = re.compile(r"^([a-zA-Z0-9]+)*@example\.com$")
    return {"valid": bool(pattern.match(email))}


def main():
    calc = input("Enter a discount formula: ")
    print(eval(calc))
    app.run(host="0.0.0.0", port=5000, debug=True)


if __name__ == "__main__":
    main()
