# Secure Wireless Communication Using Lightweight Cryptography

This README is written for a student who wants to explain this project confidently in a Wireless Networks viva, even if they currently have zero background in ASCON, AES, or cryptography.

---

## 1) What This Project Is (One-line answer)
We built a complete secure communication prototype for wireless-style traffic, where messages are encrypted, authenticated, replay-protected, benchmarked against multiple algorithms, attacked in controlled demos, and presented with report-ready charts and a project dashboard.

---

## 2) Why This Matters in Wireless Networks
Wireless communication is inherently exposed because signals travel through open space. Anyone in range can capture traffic. That creates three practical risks:

1. Eavesdropping: attacker reads sensitive payloads.
2. Tampering (MITM): attacker changes data in transit.
3. Replay: attacker resends old valid packets to repeat actions.

A secure wireless design must give:

1. Confidentiality: attacker cannot read message content.
2. Integrity: attacker cannot alter data without detection.
3. Authenticity: receiver accepts only packets created by a key holder.
4. Freshness: old packets cannot be accepted as new.

This project implements all four.

---

## 3) Crypto Theory in Plain Language

### 3.1 Symmetric Key Basics
A symmetric key is a shared secret used by both sender and receiver.

1. Sender encrypts with the key.
2. Receiver decrypts with the same key.

If key remains secret and protocol is correct, captured traffic is useless to attackers.

### 3.2 AEAD (What we actually need in networks)
Modern secure messaging uses AEAD (Authenticated Encryption with Associated Data). AEAD gives encryption + integrity together.

1. Input: key, nonce, associated data (AD), plaintext.
2. Output: ciphertext + authentication tag.
3. Receiver verifies tag first; if verification fails, message is rejected.

### 3.3 What is Nonce and Why It Is Critical
A nonce is a per-message unique value under a given key.

1. Same key + reused nonce can break security.
2. Nonce must be unique per encryption call.

In this project, nonce is 16 bytes and tied to sequence behavior.

### 3.4 Why "Lightweight Crypto"
Wireless IoT and edge devices have limits:

1. Low CPU
2. Low RAM
3. Battery constraints
4. Small packet budgets

Lightweight crypto targets strong security with lower computational cost.

---

## 4) Why We Compare ASCON, AES, SPECK, PRESENT

1. ASCON-AEAD128: NIST lightweight standard family candidate finalized in SP 800-232 context; our primary algorithm.
2. AES-128-GCM: industry baseline everyone recognizes.
3. SPECK-based AEAD wrapper: lightweight software-friendly comparison.
4. PRESENT-based AEAD wrapper: ultra-light design comparison.

This comparison helps answer a WN question: "Which algorithm gives acceptable security at lower cost for constrained networked devices?"

---

## 5) What We Built Exactly (Deliverables)

### 5.1 Secure Protocol and Transport
We created packet-level secure messaging over TCP with this format:

`version | algo_id | nonce | seq_num | timestamp | ad_len | ad | ct_len | ciphertext | tag`

Implemented in:
- [packet.py](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/src/network/packet.py)
- [sender.py](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/src/network/sender.py)
- [receiver.py](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/src/network/receiver.py)

### 5.2 Replay Protection
We implemented a sliding-window replay guard:

1. Fresh sequence accepted.
2. Duplicate sequence rejected.
3. Too-old sequence rejected.

Implemented in:
- [replay_guard.py](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/src/network/replay_guard.py)

### 5.3 Crypto Engines
Common interface + four engines:

- [base_engine.py](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/src/crypto/base_engine.py)
- [ascon_engine.py](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/src/crypto/ascon_engine.py)
- [aes_engine.py](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/src/crypto/aes_engine.py)
- [speck_engine.py](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/src/crypto/speck_engine.py)
- [present_engine.py](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/src/crypto/present_engine.py)

### 5.4 Benchmark and Analysis Pipeline
We automated performance measurement and export:

1. encryption time
2. decryption time
3. throughput
4. memory usage
5. summary CSV
6. repeated runs

Implemented in:
- [bench_runner.py](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/src/benchmark/bench_runner.py)
- [metrics.py](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/src/benchmark/metrics.py)
- [visualize.py](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/src/benchmark/visualize.py)

### 5.5 Attack Demonstrations
We implemented three practical attack scenarios and generated proof logs:

1. Eavesdrop demo: plaintext should not appear in captured wire bytes.
2. Replay demo: first packet accepted, replay packets rejected.
3. MITM/tamper demo: modified ciphertext fails authentication.

Implemented in:
- [eavesdrop_demo.py](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/src/attacks/eavesdrop_demo.py)
- [replay_demo.py](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/src/attacks/replay_demo.py)
- [mitm_demo.py](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/src/attacks/mitm_demo.py)

### 5.6 Lightweight Key Strategy Upgrade (Important)
To address key-focused evaluation, we added a dedicated key strategy module:

1. Profile-based key policy (`minimal`, `balanced`, `hardened`).
2. HKDF-based context-separated key derivation.
3. Counter-based nonce construction helper.
4. Rekey threshold checks.
5. Key material health assessment.

Implemented in:
- [key_manager.py](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/src/utils/key_manager.py)
- Strategy notes: [KEY_MANAGEMENT_STRATEGY.md](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/docs/KEY_MANAGEMENT_STRATEGY.md)

---

## 6) What Is On The UI (Dashboard)
We added a practical project UI (not a fancy landing page) for operations, evidence, and viva flow.

Implemented in:
- [dashboard.py](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/src/ui/dashboard.py)
- UI flow notes: [UI_FLOW.md](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/docs/UI_FLOW.md)

Dashboard sections:

1. Workflow panel
   - Key setup -> validate -> benchmark -> attacks -> report.
2. Run controls
   - One-click verify, tests, quick/full benchmark, attack_all, charts.
3. Lightweight key strategy panel
   - Shows profile table and key policy.
4. Benchmark summary + raw benchmark table
   - Pulls from `results/benchmark_results.csv` and `benchmark_summary.csv`.
5. Attack evidence panel
   - Reads PASS/FAIL from attack logs.
6. Charts panel
   - Shows chart1 to chart6 images.
7. Submission pack check
   - Shows if key evidence files/docs are present.

This UI is designed for project demonstration and progress tracking, not marketing.

---

## 7) How To Run Everything

From project root:
`C:\Users\ASUS\OneDrive\Desktop\WN\lwc_sync_repo\secure-wireless-lwc-codex`

### 7.1 Setup
Windows PowerShell:
```powershell
python -m venv venv
.\venv\Scripts\python -m pip install -r requirements.txt
.\venv\Scripts\python verify_setup.py
```

### 7.2 Core Workflow
```powershell
.\venv\Scripts\python main.py benchmark_quick
.\venv\Scripts\python main.py attack_all
.\venv\Scripts\python main.py charts
.\venv\Scripts\python -m pytest -q
```

### 7.3 Launch Dashboard
```powershell
.\venv\Scripts\python main.py dashboard
```
Then open:
`http://127.0.0.1:8091`

Stop server with `Ctrl+C`.

---

## 8) Output Artifacts You Can Show

### Benchmark and summary
- [benchmark_results.csv](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/results/benchmark_results.csv)
- [benchmark_summary.csv](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/results/benchmark_summary.csv)
- [run1.csv](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/results/run1.csv)
- [run2.csv](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/results/run2.csv)
- [run3.csv](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/results/run3.csv)

### Charts
- [chart1_throughput.png](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/results/chart1_throughput.png)
- [chart2_enc_time.png](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/results/chart2_enc_time.png)
- [chart3_memory.png](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/results/chart3_memory.png)
- [chart4_enc_dec.png](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/results/chart4_enc_dec.png)
- [chart5_tradeoff.png](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/results/chart5_tradeoff.png)
- [chart6_attacks.png](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/results/chart6_attacks.png)

### Attack proof logs
- [eavesdrop_demo.log](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/results/attack_logs/eavesdrop_demo.log)
- [replay_demo.log](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/results/attack_logs/replay_demo.log)
- [mitm_demo.log](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/results/attack_logs/mitm_demo.log)

---

## 9) How To Explain Each Chart in Viva

1. Chart 1 (Throughput)
   - Shows which algorithm can carry more payload per second.
   - Good for "performance vs payload size" argument.
2. Chart 2 (Encryption time)
   - Shows latency cost by algorithm and payload.
3. Chart 3 (Memory)
   - Shows resource fit for constrained devices.
4. Chart 4 (Encrypt vs Decrypt)
   - Shows directional asymmetry; useful for sender-heavy vs receiver-heavy systems.
5. Chart 5 (Tradeoff)
   - Maps speed against claimed security level.
6. Chart 6 (Attack detection)
   - Shows whether defenses worked in eavesdrop/replay/tamper scenarios.

---

## 10) How To Answer "Did You Build ASCON or Just Import It?"
Correct technical answer:

1. We use a standards-conformant ASCON implementation library intentionally.
2. In production and academic security work, validated algorithm implementations are preferred over handwritten crypto internals.
3. Our contribution is the network-security system around it:
   - secure packet protocol,
   - nonce and sequence handling,
   - replay defense,
   - attack validation,
   - benchmark comparison across algorithms,
   - key strategy layer and project dashboard.

This is the right engineering approach for Wireless Networks system design.

---

## 11) How To Explain "Lightweight and Secure Key" Clearly
Use this concise narrative:

1. Keep minimum 128-bit security for symmetric keys.
2. Use cryptographic randomness (`os.urandom`) for root keys.
3. Derive context-specific engine keys via HKDF, so one root key is not reused directly in all contexts.
4. Enforce nonce uniqueness via deterministic fixed-field + counter.
5. Rotate keys after threshold message counts to reduce long-term exposure.

That is exactly why we added the new key strategy module.

---

## 12) Test Coverage Summary
Current suite includes:

1. Crypto correctness and tamper rejection.
2. End-to-end sender/receiver tests.
3. Replay behavior validation.
4. Attack demo verification.
5. Benchmark output sanity.
6. Chart generation checks.
7. Key strategy tests.
8. Dashboard rendering/state tests.

Run:
```powershell
.\venv\Scripts\python -m pytest -q
```

---

## 13) Project Limits (Be Honest in Presentation)
What is done:

1. End-to-end secure channel prototype.
2. Multi-algorithm comparison.
3. Attack simulation and evidence.
4. Data-to-chart reporting pipeline.
5. Key strategy framework.
6. Demo-ready dashboard.

What is not fully done:

1. Hardware deployment on real ESP32/RPi nodes in this repository runtime.
2. Final `.docx` and `.pptx` auto-generation from markdown.
3. Official ASCON KAT ingestion pipeline is not yet integrated into tests.

---

## 14) Quick Viva Script (2 minutes)
You can say:

1. "Our project solves secure wireless communication for constrained environments."
2. "We implemented AEAD-based secure transport with ASCON as primary and compared it with AES, SPECK, and PRESENT."
3. "We added replay protection using sequence-window logic and validated eavesdrop, replay, and MITM scenarios."
4. "We generated benchmark CSVs and six charts for performance and security analysis."
5. "We strengthened key strategy with profile-driven HKDF derivation, nonce uniqueness helpers, and rekey guidance."
6. "We built a project dashboard that runs the whole flow and shows evidence artifacts directly."

---

## 15) Standards and References
Key references used for design rationale:

1. NIST SP 800-232 (Ascon): https://csrc.nist.gov/pubs/sp/800/232/final
2. NIST SP 800-133 Rev.2 (key generation): https://csrc.nist.gov/pubs/sp/800/133/r2/final
3. NIST SP 800-38D (GCM IV uniqueness guidance): https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
4. RFC 5116 (AEAD interface and nonce requirements): https://www.rfc-editor.org/rfc/rfc5116
5. RFC 5869 (HKDF): https://www.rfc-editor.org/rfc/rfc5869

---

## 16) File Map (Fast Navigation)
Core implementation:
- [main.py](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/main.py)
- [src/crypto](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/src/crypto)
- [src/network](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/src/network)
- [src/benchmark](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/src/benchmark)
- [src/attacks](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/src/attacks)
- [src/utils/key_manager.py](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/src/utils/key_manager.py)
- [src/ui/dashboard.py](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/src/ui/dashboard.py)

Documentation:
- [KEY_MANAGEMENT_STRATEGY.md](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/docs/KEY_MANAGEMENT_STRATEGY.md)
- [UI_FLOW.md](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/docs/UI_FLOW.md)
- [Final_Report.md](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/docs/Final_Report.md)
- [Presentation_Outline.md](/c:/Users/ASUS/OneDrive/Desktop/WN/lwc_sync_repo/secure-wireless-lwc-codex/docs/Presentation_Outline.md)

---

If you want, next step I can generate a separate `VIVA_NOTES.md` with expected teacher questions and answer scripts line by line.
