# Secure Wireless Communication Using Lightweight Cryptography

## Abstract
This project implements an end-to-end secure communication prototype for constrained environments using ASCON-AEAD128 as the primary algorithm, with AES-128-GCM, SPECK-128/128-CTR-HMAC, and PRESENT-80-CTR-HMAC as comparison baselines. The system provides confidentiality, integrity, and replay protection over TCP sockets through authenticated encryption and sequence-based validation. Results include cryptographic correctness tests, protocol integration tests, benchmark measurements, and attack simulation outcomes.

## 1. Introduction
- Problem: Wireless communication channels are exposed to interception, replay, and tampering.
- Objective: Build and validate a secure, lightweight protocol suitable for IoT-class systems.
- Scope: Software prototype with cryptographic engine abstraction, protocol framing, benchmarking, and attack demonstrations.

## 2. System Design
- Crypto abstraction: `CryptoEngine` base interface.
- Implemented engines: ASCON, AES-GCM, SPECK-CTR-HMAC, PRESENT-CTR-HMAC.
- Protocol fields: version, algorithm ID, nonce, sequence number, timestamp, associated data, ciphertext, tag.
- Replay defense: sliding-window replay guard.

## 3. Implementation
- Phase 1: environment and structure.
- Phase 2: engine wrappers + crypto tests.
- Phase 3: sender/receiver + packet and replay guard.
- Phase 4: benchmark runner with CSV export.
- Phase 5: eavesdrop, replay, MITM attack demos with logs.
- Phase 6: visualization and analysis outputs.

## 4. Benchmark Results
Benchmark charts generated in `results/`:
- `chart1_throughput.png`
- `chart2_enc_time.png`
- `chart3_memory.png`
- `chart4_enc_dec.png`
- `chart5_tradeoff.png`

Summary table exported:
- `benchmark_summary.csv`

## 5. Security Analysis
Attack detection chart:
- `chart6_attacks.png`

Attack log artifacts:
- `results/attack_logs/eavesdrop_demo.log`
- `results/attack_logs/replay_demo.log`
- `results/attack_logs/mitm_demo.log`

## 6. Testing Evidence
- Unit and integration coverage:
  - `tests/test_crypto_engines.py`
  - `tests/test_e2e.py`
  - `tests/test_benchmark_runner.py`
  - `tests/test_attacks.py`
  - `tests/test_visualize.py`
- Current status: all tests passing in local run.

## 7. Discussion and Trade-offs
- ASCON is primary due to NIST LWC standard alignment.
- AES-GCM provides strong baseline and often high software performance.
- SPECK/PRESENT comparisons are useful for lightweight trends but use different constructions than native AEAD standardization in this prototype.
- Quick benchmark mode is intentionally constrained for fast and safe iteration; full benchmark mode is available when needed.

## 8. Conclusion
The prototype demonstrates secure message transport, replay rejection, and tamper detection, with reproducible benchmark and security analysis artifacts. The codebase is organized in phase-aligned modules and can be extended toward hardware-specific measurements.

## 9. Future Work
- Add full-size benchmark campaigns (`run1.csv`, `run2.csv`, `run3.csv`) with controlled runtime budgets.
- Add optional MQTT transport integration.
- Add key rotation and session bootstrapping (e.g., ECDH-based exchange).
- Extend attack simulations with malformed packet fuzzing and stale timestamp enforcement.
