# Simulation guide — exact terminal commands (Windows PowerShell)

Project folder (use this path everywhere):

`C:\Users\ASUS\OneDrive\Desktop\WN\secure-wireless-lwc-cursor`

---

## Pick ONE way to run Python (use the same way for every command)

### Option A — activate venv (then type `python ...`)

Copy-paste **once** per terminal window:

```powershell
cd C:\Users\ASUS\OneDrive\Desktop\WN\secure-wireless-lwc-cursor
.\venv\Scripts\Activate.ps1
```

After that, every command below that starts with `python` will work.

### Option B — no activate (full path every time)

Replace `python` with this (same folder):

```text
C:\Users\ASUS\OneDrive\Desktop\WN\secure-wireless-lwc-cursor\venv\Scripts\python.exe
```

Example:

```powershell
C:\Users\ASUS\OneDrive\Desktop\WN\secure-wireless-lwc-cursor\venv\Scripts\python.exe main.py --help
```

Below, commands are written with **`python`** — use Option A in that terminal, or substitute Option B.

---

## Part 1 — Normal client and server (two terminals)

### Step 0 — open two PowerShell windows

- **Window 1** = server (receiver)  
- **Window 2** = client (sender)

In **both** windows, run:

```powershell
cd C:\Users\ASUS\OneDrive\Desktop\WN\secure-wireless-lwc-cursor
.\venv\Scripts\Activate.ps1
```

---

### Step 1 — create shared key file (run in Window 1 **only**, once)

```powershell
cd C:\Users\ASUS\OneDrive\Desktop\WN\secure-wireless-lwc-cursor
.\venv\Scripts\Activate.ps1
python main.py keygen --out keys\psk.bin
```

Expected line:

```text
Wrote 16-byte PSK to keys\psk.bin
```

---

### Step 2 — start server (Window 1)

**To accept many messages (leave running):**

```powershell
cd C:\Users\ASUS\OneDrive\Desktop\WN\secure-wireless-lwc-cursor
.\venv\Scripts\Activate.ps1
python main.py serve -p 9000 --key keys\psk.bin
```

Expected:

```text
[RECEIVER] Forever mode on port 9000 (Ctrl+C to stop)...
[RECEIVER] Listening on port 9000...
```

**Do not close this window.** Wait until Step 3 runs in Window 2.

**Alternative — accept only ONE message then server exits:**

```powershell
python main.py serve -p 9000 --key keys\psk.bin --once
```

---

### Step 3 — send message from client (Window 2)

Open **Window 2**, then:

```powershell
cd C:\Users\ASUS\OneDrive\Desktop\WN\secure-wireless-lwc-cursor
.\venv\Scripts\Activate.ps1
python main.py send -p 9000 --key keys\psk.bin -m "Hello from client"
```

Expected in Window 2:

```text
[SENDER] Sent message #1 (... bytes)
```

Expected in Window 1 (server):

```text
[RECEIVER] Decrypted: "Hello from client" (seq=1)
[RECEIVER] Listening on port 9000...
```

**Send again** (Window 2, same commands as Step 3, change `-m` text if you want):

```powershell
python main.py send -p 9000 --key keys\psk.bin -m "Second message"
```

---

### Step 4 — stop server (Window 1)

Click Window 1, press:

```text
Ctrl+C
```

Expected:

```text
[RECEIVER] Stopped.
```

---

### Same engine on both sides — exact commands (optional)

**Window 1:**

```powershell
cd C:\Users\ASUS\OneDrive\Desktop\WN\secure-wireless-lwc-cursor
.\venv\Scripts\Activate.ps1
python main.py serve -p 9000 --key keys\psk.bin --engine aes
```

**Window 2:**

```powershell
cd C:\Users\ASUS\OneDrive\Desktop\WN\secure-wireless-lwc-cursor
.\venv\Scripts\Activate.ps1
python main.py send -p 9000 --key keys\psk.bin --engine aes -m "AES test"
```

Allowed `--engine` values: `ascon`, `aes`, `speck`, `present`.

---

### Two PCs on LAN — exact commands (optional)

**PC that listens (server)** — copy `keys\psk.bin` from project folder. Replace `192.168.x.x` with **this PC’s** IPv4.

```powershell
cd C:\Users\ASUS\OneDrive\Desktop\WN\secure-wireless-lwc-cursor
.\venv\Scripts\Activate.ps1
python main.py serve -p 9000 --key keys\psk.bin
```

**Other PC (client)** — put the **same** `psk.bin` in the same relative path `keys\psk.bin` inside the project. Replace `192.168.x.x` with the **server PC** IP.

```powershell
cd C:\Users\ASUS\OneDrive\Desktop\WN\secure-wireless-lwc-cursor
.\venv\Scripts\Activate.ps1
python main.py send --host 192.168.x.x -p 9000 --key keys\psk.bin -m "Hello LAN"
```

---

## Part 2 — Attack simulations (one terminal each; no `serve` needed)

Open **one** PowerShell window:

```powershell
cd C:\Users\ASUS\OneDrive\Desktop\WN\secure-wireless-lwc-cursor
.\venv\Scripts\Activate.ps1
```

### Eavesdrop demo (copy-paste this one line)

```powershell
python main.py demo eavesdrop
```

Look for:

```text
Plaintext in raw?: False
```

---

### Replay demo (copy-paste this one line)

```powershell
python main.py demo replay
```

Look for:

```text
Connection 1: status='OK' ...
Connection 2: status='REPLAY_REJECTED' ...
Connection 3: status='REPLAY_REJECTED' ...
```

---

### MITM / tamper demo (copy-paste this one line)

```powershell
python main.py demo mitm
```

Look for:

```text
[RECEIVER] AUTH FAILURE! Tag verification failed.
Receiver outcome: status='AUTH_FAILURE'
```

---

## Part 3 — Run all automated tests (one terminal)

```powershell
cd C:\Users\ASUS\OneDrive\Desktop\WN\secure-wireless-lwc-cursor
.\venv\Scripts\Activate.ps1
python -m pytest tests -v
```

Expected last line:

```text
32 passed
```

---

## If `No module named 'Crypto'`

You used the wrong Python. Run **exactly**:

```powershell
cd C:\Users\ASUS\OneDrive\Desktop\WN\secure-wireless-lwc-cursor
.\venv\Scripts\Activate.ps1
```

or use only:

```powershell
C:\Users\ASUS\OneDrive\Desktop\WN\secure-wireless-lwc-cursor\venv\Scripts\python.exe main.py serve -p 9000 --key keys\psk.bin
```

---

*More context: `README.md`, `PROJECT_GOALS_STANDARDS_AND_TEST_RESULTS.md`.*
