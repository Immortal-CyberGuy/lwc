# Secure Wireless Communication Using Lightweight Cryptography

This repository implements a complete software prototype for secure wireless-style communication using lightweight cryptography, then validates it through tests, benchmarking, attack simulations, and charted analysis.

## Goal
Build and validate an end-to-end secure channel where:
- payloads are encrypted/authenticated with ASCON (primary),
- replayed or tampered packets are rejected,
- behavior is compared against AES-128-GCM, SPECK, and PRESENT implementations,
- performance and security outcomes are reproducible via CSVs, logs, and charts.

## What This Repo Does
1. Encrypts/decrypts messages with a pluggable crypto engine interface.
2. Sends encrypted packets over TCP with a defined packet format.
3. Protects against replay using a sliding-window replay guard.
4. Runs benchmark suites and exports CSV metrics.
5. Demonstrates eavesdrop/replay/MITM attack scenarios and defenses.
6. Generates 6 report-ready charts and summary datasets.

## Architecture We Followed
High-level layers:
1. Crypto layer (`src/crypto/`)
- `CryptoEngine` abstraction + 4 concrete engines.
2. Protocol/network layer (`src/network/`)
- secure packet format
- sender/receiver transport
- replay guard
3. Evaluation layer (`src/benchmark/`, `src/attacks/`)
- benchmark runner + metrics
- attack simulations + logs
- visualization pipeline
4. Utility and orchestration (`src/utils/`, `main.py`)
- key/log helpers
- simple entrypoint commands

Packet model:
- `version | algo_id | nonce | seq_num | timestamp | ad_len | ad | ct_len | ciphertext | tag`

Security model:
- confidentiality + integrity via AEAD-style behavior,
- authenticity via tag verification,
- replay mitigation via sequence-number windowing.

## Process We Followed (Implementation Process, Not Code Details)
We implemented this in 6 phases:
1. Environment and skeleton setup.
2. Crypto engine implementation + correctness tests.
3. Protocol and transport implementation + end-to-end tests.
4. Benchmark pipeline and CSV export.
5. Attack simulations with verifiable outcomes.
6. Visualization/report artifacts and final validation.

Each phase ended with executable checks before moving on.

## Repository Structure
```text
src/
  crypto/
    base_engine.py
    ascon_engine.py
    aes_engine.py
    speck_engine.py
    present_engine.py
  network/
    packet.py
    replay_guard.py
    sender.py
    receiver.py
    engine_factory.py
    run_server.py
    run_client.py
  benchmark/
    metrics.py
    bench_runner.py
    visualize.py
  attacks/
    eavesdrop_demo.py
    replay_demo.py
    mitm_demo.py
  utils/
    key_manager.py
    logger.py
tests/
docs/
results/
main.py
verify_setup.py
```

## Setup
From repository root:

### Windows (PowerShell)
```powershell
python -m venv venv
.\venv\Scripts\python -m pip install -r requirements.txt
.\venv\Scripts\python verify_setup.py
```

### Linux/macOS
```bash
python -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
python verify_setup.py
```

Expected setup check output:
- `ALL IMPORTS OK. ASCON encrypt/decrypt VERIFIED.`

## How To Run (Main Flows)

## A) Run one-shot server/client manually
Use same `--key-hex` and `--engine` on both sides.

Terminal 1 (server):
```powershell
.\venv\Scripts\python -m src.network.run_server --host 127.0.0.1 --port 9000 --engine ascon --key-hex 00112233445566778899aabbccddeeff
```

Terminal 2 (client):
```powershell
.\venv\Scripts\python -m src.network.run_client --host 127.0.0.1 --port 9000 --engine ascon --key-hex 00112233445566778899aabbccddeeff --message "hello secure world"
```

What this proves:
- packet framing works,
- encryption/decryption works,
- receiver returns status and plaintext for valid message.

## B) Run attack demos
```powershell
.\venv\Scripts\python main.py attack_all
```
Outputs logs to:
- `results/attack_logs/eavesdrop_demo.log`
- `results/attack_logs/replay_demo.log`
- `results/attack_logs/mitm_demo.log`

## C) Run benchmarks
Quick/safe baseline:
```powershell
.\venv\Scripts\python main.py benchmark_quick
```

Three repeated quick runs:
```powershell
.\venv\Scripts\python main.py benchmark_repeat_quick
```

Full benchmark mode (heavier):
```powershell
.\venv\Scripts\python main.py benchmark_full
```

## D) Generate charts
```powershell
.\venv\Scripts\python main.py charts
```

## E) Run full test suite
```powershell
.\venv\Scripts\python -m pytest -q
```

## Test Suites and What They Signify

1. `tests/test_crypto_engines.py`
- Validates crypto correctness and failure behavior across all 4 engines:
  - roundtrip success,
  - wrong key rejection,
  - tampered ciphertext rejection,
  - tampered associated-data rejection.

2. `tests/test_e2e.py`
- Validates protocol and transport:
  - sender/receiver end-to-end success across engines,
  - packet serialize/deserialize fidelity,
  - replay guard logic and replay attack rejection path.

3. `tests/test_benchmark_runner.py`
- Validates benchmark output generation and metric sanity (non-negative values).

4. `tests/test_attacks.py`
- Validates security demonstrations:
  - eavesdrop has no plaintext leakage in raw packet bytes,
  - replay packets are rejected,
  - MITM tampering triggers auth failure.

5. `tests/test_visualize.py`
- Validates chart pipeline produces all required visual artifacts.

6. `tests/test_utils.py`
- Validates key save/load and logging utilities.

7. `tests/test_engine_factory.py`
- Validates engine selection utility used by CLI server/client runners.

## Latest Known Test Status
Current local run:
- `30 passed` (before adding engine factory test), then engine factory test added.
- Re-run after current additions:
```powershell
.\venv\Scripts\python -m pytest -q
```
Expected: full green suite (now includes `test_engine_factory.py`).

Per-suite latest captured results file:
- `results/test_results_latest.txt`

## Output Artifacts
Benchmark data:
- `results/benchmark_results.csv`
- `results/benchmark_results_quick.csv`
- `results/run1.csv`
- `results/run2.csv`
- `results/run3.csv`
- `results/benchmark_summary.csv`

Charts:
- `results/chart1_throughput.png`
- `results/chart2_enc_time.png`
- `results/chart3_memory.png`
- `results/chart4_enc_dec.png`
- `results/chart5_tradeoff.png`
- `results/chart6_attacks.png`

Attack logs:
- `results/attack_logs/eavesdrop_demo.log`
- `results/attack_logs/replay_demo.log`
- `results/attack_logs/mitm_demo.log`

Documentation:
- `docs/Final_Report.md`
- `docs/Presentation_Outline.md`
- `README_PROJECT_STATUS.md` (detailed built-vs-not-built audit)

## What Is Built vs Not Fully Built
Built:
- all 6 planned phases are implemented in software form,
- end-to-end protocol + testing + benchmarking + attack demos + charts.

Not fully finalized (if strict academic production packaging is required):
- final `.docx` report and `.pptx` slides are not generated from markdown yet,
- hardware deployment on ESP32/Raspberry Pi is not part of this repo runtime.

## Standards Alignment (Practical)
- Uses ASCON as primary lightweight algorithm path.
- Applies authenticated encryption model and replay defense in protocol design.
- Produces test-backed, reproducible results and security demonstration evidence.

For exact completion audit and constraints:
- see `README_PROJECT_STATUS.md`.
