# Project goals, how we meet them, standards alignment, and test results

This document answers: **what this project does**, **why**, **how it works end-to-end**, **whether it matches the intended standards / course plan**, and **what automated tests were run with what outcome**.

---

## 1. What this project does (in plain language)

We built a **small secure messaging prototype** for a **lab / course** setting:

- Two programs (or two threads) talk over **TCP** on a network interface (usually **localhost**). That stands in for “wireless” in the sense of **untrusted transport**: anyone who can reach the port could try to read or modify bytes.
- Messages are **not sent in plaintext**. Each payload is **encrypted and authenticated** using a **shared secret key (PSK)** and a **binary packet format** (`SecurePacket`: version, algorithm id, nonce, sequence number, timestamp, associated data, ciphertext, authentication tag).
- The **primary cipher** is **ASCON** in authenticated encryption mode (via the standard PyPI **`ascon`** library), aligned with the **lightweight cryptography** theme from NIST’s LWC program (standardization context: **NIST SP 800-232** in your course materials).
- We **compare** ASCON to **AES-128-GCM** (common baseline), **SPECK-128/128** in a **CTR + HMAC** construction, and **PRESENT-80** similarly—so we can **benchmark** time/memory/throughput and discuss trade-offs in a report.
- We include **replay protection** (sliding window on sequence numbers) and **demos** that illustrate **eavesdropping** (ciphertext only), **replay** (duplicate packet rejected), and **tampering** (integrity check fails).

**What it is not:** a certified product, a full key-management/PKI system, or firmware on a microcontroller. It is a **Python reference implementation** plus **measurements** and **demos** suitable for analysis and a written report.

---

## 2. Goal we are trying to achieve

**Stated goal (from your project / phased plan):**

1. Show **end-to-end protected communication** (confidentiality + integrity) using **lightweight-oriented** crypto, with **ASCON** as the featured algorithm.
2. **Measure** how **ASCON** stacks up against **AES**, **SPECK**, and **PRESENT** on the same machine for several payload sizes.
3. **Demonstrate** that common attacks against naive channels (**eavesdrop**, **replay**, **tamper/MITM-style bit flips**) are **handled** by encryption + tags + replay logic—at least in this controlled prototype.
4. Produce **artifacts** for grading: **code**, **CSV benchmarks**, **charts**, optional **logs**, and (outside this repo) a **written report** and **presentation**.

**How we achieve that:**

| Goal piece | Mechanism in this repo |
|------------|-------------------------|
| Confidentiality | AEAD / encrypt-then-MAC style outputs: ciphertext + tag (ASCON/AES native AEAD; SPECK/PRESENT use CTR + HMAC). |
| Integrity | Tag verification; decrypt returns failure on bad tag or wrong key. |
| Replay resistance | `ReplayGuard` + monotonic `seq_num` in the packet; duplicate seq rejected. |
| Comparability | Common `CryptoEngine` interface; same benchmark loop for all algorithms. |
| Evidence | `bench_runner` → CSV; `visualize` → 6 PNGs; attack **demo scripts**; **pytest** for regression. |

---

## 3. Did we match the “standards” we were supposed to meet?

Interpret this in **two** ways: **course / phased plan** vs **formal cryptographic standardization**.

### 3.1 Course phased plan (software deliverables)

| Phase | Planned exit / deliverable | Met in this codebase? |
|-------|----------------------------|------------------------|
| 1 | Environment, imports, ASCON smoke test, `CryptoEngine` | **Yes** — `verify_setup.py`, layout, ABC |
| 2 | Four engines + tests | **Yes** — `tests/test_crypto_engines.py` |
| 3 | Packet, replay guard, sender/receiver, E2E | **Yes** — `tests/test_network.py`, `tests/test_e2e.py` |
| 4 | Benchmark CSV (24 rows full run) | **Yes** — `bench_runner` (you must **run** full benchmark to generate file) |
| 5 | Three attack demos | **Yes** — `src/attacks/*.py` |
| 6 | Six charts from CSV | **Yes** — `visualize.py` (run after CSV exists) |
| 6 | Final Word report + slides | **Not in repo** — you author separately |

**Conclusion:** For **software and automation**, the phased plan is **implemented**. **Written** Phase-6 deliverables are **your** work product, not generated here.

### 3.2 Formal standards (NIST, ISO, FIPS)

- **ASCON:** We use a **published Python implementation** (`ascon` on PyPI), not a hand-rolled permutation. That is appropriate for a course lab. It does **not** by itself mean “FIPS validated” or “formally verified.”
- **AES-128-GCM:** Implemented via **PyCryptodome**, a widely used library. Again, suitable for coursework benchmarks—not a certification claim.
- **SPECK / PRESENT:** Implemented or composed **for comparison** (SPECK block + CTR + HMAC; PRESENT block + CTR + HMAC). These are **educational constructions**; they are **tested for consistency and basic security properties** in code, **not** submitted as standards-compliant product crypto.
- **Protocol:** Our **packet format** and **TCP framing** are **project-specific**, not a published IoT standard like DTLS or MQTT-over-TLS.

**Conclusion:** We **align with the *intent*** of the course doc (LWC + ASCON + comparisons + analysis). We do **not** claim **regulatory** or **industrial certification**—and that is normal for a student prototype.

---

## 4. Automated test cases and results

### 4.1 How tests were run

- **Command:** `python -m pytest tests -v --tb=no`
- **Environment (example run):** Windows, Python **3.12.3**, **pytest 9.0.2**, project root `secure-wireless-lwc-cursor`, virtualenv active.
- **Outcome:** **32 passed**, **0 failed**.

> **Note:** Duration varies by machine load (e.g. ~18–45 s). The line `32 passed` is what matters for regression.

### 4.2 Captured pytest log (representative successful run)

```
============================= test session starts =============================
platform win32 -- Python 3.12.3, pytest-9.0.2, pluggy-1.6.0 -- ...\venv\Scripts\python.exe
cachedir: .pytest_cache
rootdir: ...\secure-wireless-lwc-cursor
configfile: pytest.ini (WARNING: ignoring pytest config in pyproject.toml!)
collecting ... collected 32 items

tests/test_bench_runner.py::test_run_benchmarks_writes_csv_quick PASSED  [  3%]
tests/test_crypto_engines.py::test_speck_block_roundtrip PASSED          [  6%]
tests/test_crypto_engines.py::test_encrypt_decrypt_roundtrip[ASCON-AEAD128] PASSED [  9%]
tests/test_crypto_engines.py::test_encrypt_decrypt_roundtrip[AES-128-GCM] PASSED [ 12%]
tests/test_crypto_engines.py::test_encrypt_decrypt_roundtrip[SPECK-128/128-CTR-HMAC] PASSED [ 15%]
tests/test_crypto_engines.py::test_encrypt_decrypt_roundtrip[PRESENT-80-CTR-HMAC] PASSED [ 18%]
tests/test_crypto_engines.py::test_wrong_key_fails[ASCON-AEAD128] PASSED [ 21%]
tests/test_crypto_engines.py::test_wrong_key_fails[AES-128-GCM] PASSED   [ 25%]
tests/test_crypto_engines.py::test_wrong_key_fails[SPECK-128/128-CTR-HMAC] PASSED [ 28%]
tests/test_crypto_engines.py::test_wrong_key_fails[PRESENT-80-CTR-HMAC] PASSED [ 31%]
tests/test_crypto_engines.py::test_tampered_ciphertext_fails[ASCON-AEAD128] PASSED [ 34%]
tests/test_crypto_engines.py::test_tampered_ciphertext_fails[AES-128-GCM] PASSED [ 37%]
tests/test_crypto_engines.py::test_tampered_ciphertext_fails[SPECK-128/128-CTR-HMAC] PASSED [ 40%]
tests/test_crypto_engines.py::test_tampered_ciphertext_fails[PRESENT-80-CTR-HMAC] PASSED [ 43%]
tests/test_crypto_engines.py::test_tampered_ad_fails[ASCON-AEAD128] PASSED [ 46%]
tests/test_crypto_engines.py::test_tampered_ad_fails[AES-128-GCM] PASSED [ 50%]
tests/test_crypto_engines.py::test_tampered_ad_fails[SPECK-128/128-CTR-HMAC] PASSED [ 53%]
tests/test_crypto_engines.py::test_tampered_ad_fails[PRESENT-80-CTR-HMAC] PASSED [ 56%]
tests/test_e2e.py::test_e2e_encrypt_over_tcp[ASCON-AEAD128] PASSED       [ 59%]
tests/test_e2e.py::test_e2e_encrypt_over_tcp[AES-128-GCM] PASSED         [ 62%]
tests/test_e2e.py::test_e2e_encrypt_over_tcp[SPECK-128/128-CTR-HMAC] PASSED [ 65%]
tests/test_e2e.py::test_e2e_encrypt_over_tcp[PRESENT-80-CTR-HMAC] PASSED [ 68%]
tests/test_e2e.py::test_replay_same_packet_rejected PASSED               [ 71%]
tests/test_e2e.py::test_tampered_ciphertext_rejected PASSED              [ 75%]
tests/test_network.py::test_secure_packet_roundtrip PASSED               [ 78%]
tests/test_network.py::test_replay_guard_fresh_and_duplicate PASSED      [ 81%]
tests/test_network.py::test_replay_guard_rejects_seq_zero PASSED         [ 84%]
tests/test_receiver_limits.py::test_receiver_rejects_oversized_length_prefix PASSED [ 87%]
tests/test_utils.py::test_generate_psk_length PASSED                     [ 90%]
tests/test_utils.py::test_save_load_key_roundtrip PASSED                 [ 93%]
tests/test_utils.py::test_get_logger_emits PASSED                        [ 96%]
tests/test_visualize.py::test_generate_all_charts_writes_pngs PASSED     [100%]

============================= 32 passed in 18.43s =============================
```

*(The `pytest.ini (WARNING: ignoring pytest config in pyproject.toml!)` message means both files define pytest options; `pytest.ini` wins. Tests still run correctly.)*

### 4.3 What each test file is responsible for

| File | Role |
|------|------|
| `test_crypto_engines.py` | Cryptographic correctness and failure modes (wrong key, tamper) for all four engines; SPECK block invertibility. |
| `test_network.py` | Wire encoding of `SecurePacket`; replay window logic. |
| `test_e2e.py` | Real TCP path + threading; all engines; replay + tamper at protocol level. |
| `test_bench_runner.py` | Benchmark produces a valid CSV for a small run. |
| `test_visualize.py` | All six charts are generated. |
| `test_utils.py` | Key file helpers and logger. |
| `test_receiver_limits.py` | Receiver rejects absurd length-prefix before allocating huge buffers. |

### 4.4 What is *not* covered by pytest

- **Attack demo scripts** (`eavesdrop_demo`, `replay_demo`, `mitm_demo`) — run manually or via `python main.py demo …`.
- **Full 24-row benchmark** runtime/numbers — run `python main.py benchmark` when you need final data; the quick test only checks the **machinery**.
- **CLI `serve` / `send`** — not separately pytest-wrapped; behavior builds on the same sender/receiver classes that E2E tests exercise.

---

## 5. One-paragraph summary for your report

This project demonstrates **authenticated encrypted messaging** over **TCP** using **ASCON** as the primary algorithm, with **AES-128-GCM**, **SPECK**, and **PRESENT** as comparators, plus **replay protection** and **benchmark/visualization** tooling. It fulfills the **software** goals of the six-phase development plan; **formal standard compliance** is interpreted as **using reputable libraries and sound design patterns for a lab prototype**, not product certification. **Automated regression** consists of **32 pytest cases**, all **passing** on the recorded run above.

---

*To refresh test results on your PC, run from the project root:*

```bash
python -m pytest tests -v
```
