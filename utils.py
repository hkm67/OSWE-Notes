#!/usr/bin/env python3
"""
Common utilities shared across all OSWE exploit scripts.
Import with: from utils import *
"""

import random
import re
import string

import requests

# ==============================================================================
# SESSION
# ==============================================================================

requests.packages.urllib3.disable_warnings()

session = requests.Session()
session.verify = False

BURP_PROXIES = {
    "http":  "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

# ==============================================================================
# CONSOLE HELPERS
# ==============================================================================

_ANSI = re.compile(r'\x1b\[[0-9;]*m')

def print_ok(msg: str)   -> None: print(f"  [+] {msg}")
def print_info(msg: str) -> None: print(f"  [*] {msg}")
def print_err(msg: str)  -> None: print(f"  [-] {msg}")

def strip_ansi(text: str) -> str:
    return _ANSI.sub('', text).strip()

def print_banner(title: str) -> None:
    width = 70
    print("=" * width)
    print(f"  {title}")
    print("=" * width)

def print_stage(n: int, description: str) -> None:
    print(f"\n[STAGE {n}] {description}")
    print("-" * 50)

# ==============================================================================
# RANDOM GENERATORS
# ==============================================================================

def generate_password(length: int = 16) -> str:
    """
    Password guaranteed to satisfy common validation policies:
    uppercase + lowercase + digit + special. No shell-breaking chars.
    """
    required = [
        random.choice(string.ascii_uppercase),
        random.choice(string.ascii_lowercase),
        random.choice(string.digits),
        random.choice("!@#$%^&*()_+-="),
    ]
    pool = string.ascii_letters + string.digits + "!@#$%^&*()_+-="
    rest = random.choices(pool, k=length - len(required))
    password = required + rest
    random.shuffle(password)
    return "".join(password)


def generate_random_name(length: int = 10) -> str:
    """Random uppercase alphanumeric identifier (no digits, safe as usernames)."""
    return "".join(random.sample(string.ascii_uppercase, length))

# ==============================================================================
# REGEX EXTRACTION
# ==============================================================================

def extract_between_markers(response_text: str, start: str, end: str) -> str | None:
    """
    Extract the first value between start/end delimiters.
    Works on any response format (HTML, JSON, XML, plaintext).
    Inject the markers into your SQL CONCAT() payload to make data self-delimiting.
    """
    pattern = rf"{re.escape(start)}(.*?){re.escape(end)}"
    match = re.search(pattern, response_text, re.DOTALL)
    return match.group(1) if match else None


def extract_all_between_markers(response_text: str, start: str, end: str) -> list[str]:
    """Extract all matches — use when the response contains multiple rows."""
    pattern = rf"{re.escape(start)}(.*?){re.escape(end)}"
    return re.findall(pattern, response_text, re.DOTALL)

# ==============================================================================
# POWERSHELL ENCODING
# ==============================================================================

def encode_ps1(payload: str) -> str:
    """
    Encode a PowerShell command for use with -EncodedCommand.
    Avoids quoting/escaping issues when injecting PS1 through a webshell or URL param.

    Usage:
        b64 = encode_ps1("whoami")
        cmd = f"powershell.exe -EncodedCommand {b64}"
    """
    import base64
    return base64.b64encode(payload.encode("utf-16le")).decode("utf-8")
