#!/usr/bin/env python3
"""Standalone wallet-balance checker — prints the signed curl command AND runs it live.
Usage: .venv/bin/python check_balance.py
Reads COINSWITCH_API_KEY / COINSWITCH_SECRET_KEY from the environment (source .env first).
"""
import os
import subprocess
import time
import urllib.parse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BASE_URL = "https://coinswitch.co"
API_KEY = os.environ["COINSWITCH_API_KEY"]
SECRET_KEY = os.environ["COINSWITCH_SECRET_KEY"]
private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SECRET_KEY))


def signed_curl(method: str, endpoint: str, params: dict | None = None) -> list[str]:
    path = endpoint
    if params:
        path = endpoint + "?" + urllib.parse.urlencode(params)
    decoded_path = urllib.parse.unquote_plus(path)
    epoch = str(int(time.time() * 1000))
    message = (method.upper() + decoded_path + epoch).encode("utf-8")
    signature = private_key.sign(message).hex()
    return [
        "curl", "-s", "-X", method,
        f"{BASE_URL}{path}",
        "-H", f"X-AUTH-APIKEY: {API_KEY}",
        "-H", f"X-AUTH-SIGNATURE: {signature}",
        "-H", f"X-AUTH-EPOCH: {epoch}",
        "-H", "Content-Type: application/json",
    ]


def run(label: str, method: str, endpoint: str, params: dict | None = None):
    cmd = signed_curl(method, endpoint, params)
    print(f"\n=== {label} ===", flush=True)
    print(" ".join(f"'{c}'" if " " in c else c for c in cmd), flush=True)
    print("--- response ---", flush=True)
    subprocess.run(cmd)
    print(flush=True)


if __name__ == "__main__":
    run("Portfolio (spot / INR / all currency balances)", "GET", "/trade/api/v2/user/portfolio")
    run("Futures wallet balance (EXCHANGE_2, default)", "GET", "/trade/api/v2/futures/wallet_balance")
    run("Futures wallet balance (EXCHANGE_1)", "GET", "/trade/api/v2/futures/wallet_balance", {"exchange": "EXCHANGE_1"})
