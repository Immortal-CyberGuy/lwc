# Project Status Readme

## 1. What This Project Is
This project is an end-to-end **secure communication prototype** for constrained/IoT-style environments using **lightweight cryptography**.

Primary target:
- Use **ASCON-AEAD128** for secure message transport.

Comparative targets:
- Compare with **AES-128-GCM**, **SPECK-128/128-CTR-HMAC**, and **PRESENT-80-CTR-HMAC**.

Security targets:
- Confidentiality (encrypted payload)
- Integrity/authentication (tag verification)
- Replay protection (sequence-based sliding window)
- Demonstrable resistance to eavesdrop, replay, and tamper/MITM scenarios.

---

## 2. What We Were Supposed To Build (Original 6-Phase Scope)
1. Phase 1: Project setup and environment verification.
2. Phase 2: 4 crypto engines + correctness tests.
3. Phase 3: Packet protocol + sender/receiver + replay guard + end-to-end tests.
4. Phase 4: Benchmark suite + CSV datasets.
5. Phase 5: Attack simulations (eavesdrop, replay, MITM) with proof outputs.
6. Phase 6: Visualization + analysis + report/presentation artifacts.

---

## 3. What We Implemented (Exactly)

## Phase 1 (Implemented)
- Isolated project workspace: `secure-wireless-lwc-codex`
- Package structure under `src/` and `tests/`
- Dependency management in `requirements.txt`
- Setup verification script: `verify_setup.py`
- Base crypto interface: `src/crypto/base_engine.py`

## Phase 2 (Implemented)
- `src/crypto/ascon_engine.py`
- `src/crypto/aes_engine.py`
- `src/crypto/speck_engine.py`
- `src/crypto/present_engine.py`
- Engine test suite: `tests/test_crypto_engines.py`

## Phase 3 (Implemented)
- Packet format and serializer/deserializer: `src/network/packet.py`
- Replay guard: `src/network/replay_guard.py`
- Sender: `src/network/sender.py`
- Receiver: `src/network/receiver.py`
- End-to-end and protocol tests: `tests/test_e2e.py`

## Phase 4 (Implemented)
- Benchmark orchestrator: `src/benchmark/bench_runner.py`
- Metrics helpers: `src/benchmark/metrics.py`
- Benchmark test: `tests/test_benchmark_runner.py`
- Produced benchmark datasets:
  - `results/benchmark_results.csv`
  - `results/benchmark_results_quick.csv`
  - `results/run1.csv`
  - `results/run2.csv`
  - `results/run3.csv`

## Phase 5 (Implemented)
- Eavesdrop simulation: `src/attacks/eavesdrop_demo.py`
- Replay simulation: `src/attacks/replay_demo.py`
- MITM tamper simulation: `src/attacks/mitm_demo.py`
- Attack tests: `tests/test_attacks.py`
- Logs generated:
  - `results/attack_logs/eavesdrop_demo.log`
  - `results/attack_logs/replay_demo.log`
  - `results/attack_logs/mitm_demo.log`

## Phase 6 (Implemented)
- Visualization pipeline: `src/benchmark/visualize.py`
- Visualization tests: `tests/test_visualize.py`
- Generated charts:
  - `results/chart1_throughput.png`
  - `results/chart2_enc_time.png`
  - `results/chart3_memory.png`
  - `results/chart4_enc_dec.png`
  - `results/chart5_tradeoff.png`
  - `results/chart6_attacks.png`
- Summary CSV: `results/benchmark_summary.csv`
- Report/presentation drafts:
  - `docs/Final_Report.md`
  - `docs/Presentation_Outline.md`

## Extra implemented items
- Unified launcher: `main.py`
- Utilities:
  - `src/utils/key_manager.py`
  - `src/utils/logger.py`
- Utility tests: `tests/test_utils.py`

---

## 4. What The System Actually Does (Functional Flow)
1. Sender builds associated data (device ID + timestamp) and encrypts plaintext with selected engine.
2. Sender builds secure packet (`version, algo_id, nonce, seq, timestamp, ad, ciphertext, tag`) and transmits via TCP.
3. Receiver parses packet and checks:
   - packet validity
   - algorithm match
   - replay guard acceptance
   - authentication tag/decryption success
4. If checks pass, receiver outputs plaintext; otherwise rejects with reason (`REPLAY_REJECTED`, `AUTH_FAILURE`, etc.).

---

## 5. Standards / Quality Target Match

## Security architecture match
- AEAD usage for ASCON and AES paths: **matched**.
- Replay-protection sliding window: **matched**.
- Packetized protocol with associated data and sequence metadata: **matched**.
- Attack simulation evidence (eavesdrop/replay/tamper): **matched**.

## LWC standard alignment
- ASCON implementation uses the Python `ascon` package and follows AEAD usage pattern consistent with the targeted standard workflow: **matched at prototype level**.
- This is a software prototype (localhost TCP), not hardware conformance testing: **expected for current scope**.

## Evaluation/reporting match
- Benchmark tooling exists and runs: **matched**.
- Charts and summary generation exist and run: **matched**.
- Markdown report and presentation outline are available: **matched (draft form)**.

---

## 6. What Is Partial / Not Fully Completed Yet
These are the remaining gaps versus the strictest interpretation of the original big plan:

1. Benchmark coverage level:
- Current generated datasets are **quick-mode** profile (12 rows each: 4 algos x 3 payload sizes).
- The original full target suggested 6 payload sizes (24 rows per run).
- Code supports full runs, but current saved artifacts are quick-safe runs to keep runtime stable.

2. Delivery format:
- Final outputs are currently in Markdown (`.md`) for report/presentation structure.
- Not converted to final `.docx` / `.pptx` deliverables yet.

3. Hardware realism:
- Communication is validated on localhost/TCP simulation.
- No Raspberry Pi/ESP32 deployment or radio-level sniffing setup in this workspace.

---

## 7. Exact Test Cases Run and Latest Results
Latest evidence file:
- `results/test_results_latest.txt`

Fresh per-suite run results:

1. `tests/test_crypto_engines.py`
- Result: **16 passed in 1.62s**
- Covers: roundtrip, wrong-key failure, tampered-ciphertext failure, tampered-AD failure for all 4 engines.

2. `tests/test_e2e.py`
- Result: **7 passed in 2.48s**
- Covers: end-to-end messaging across all engines, packet roundtrip serialization, replay behavior.

3. `tests/test_benchmark_runner.py`
- Result: **1 passed in 1.62s**
- Covers: benchmark CSV generation and non-negative metrics.

4. `tests/test_attacks.py`
- Result: **3 passed in 1.07s**
- Covers: eavesdrop, replay, and MITM simulation pass conditions.

5. `tests/test_visualize.py`
- Result: **1 passed in 4.86s**
- Covers: generation of all expected charts and summary CSV.

6. `tests/test_utils.py`
- Result: **2 passed in 0.09s**
- Covers: key save/load roundtrip and logging write behavior.

Full suite snapshot:
- `pytest -q` => **30 passed**

---

## 8. Completion Assessment
- Core implementation objective (secure channel + crypto comparison + attack defenses): **completed**
- Test-backed implementation quality: **completed**
- Visualization and analysis pipeline: **completed**
- Academic/portfolio packaging as markdown artifacts: **completed**
- Strict full-benchmark artifact depth (24-row per run) and docx/pptx export: **partially completed**

Estimated completion against full original roadmap:
- **~90-95% complete** in implementation and validation.
- Remaining ~5-10% is mostly output-depth/polish (full benchmark profile and final office-format docs).
