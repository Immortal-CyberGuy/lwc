# Secure Wireless Communication Using Lightweight Cryptography

## Slide 1: Title
- Project title
- Course / team details
- Date

## Slide 2: Problem and Motivation
- Wireless channel risks
- Why lightweight cryptography matters for constrained systems

## Slide 3: Objectives
- End-to-end secure channel prototype
- Algorithm comparison (ASCON, AES, SPECK, PRESENT)
- Attack defense demonstrations

## Slide 4: Architecture
- Sender, receiver, crypto layer, replay guard
- Packet structure overview

## Slide 5: Cryptographic Engines
- Unified interface
- Primary and baseline algorithms
- Authentication behavior on tampering

## Slide 6: Protocol Flow
- Encrypt + packetize + send
- Parse + replay check + decrypt + verify

## Slide 7: Benchmark Method
- Metrics: encrypt/decrypt latency, throughput, memory
- Payload sizes and iteration model
- Quick vs full benchmark modes

## Slide 8: Performance Charts
- Throughput and encryption-time charts
- Memory and encrypt-vs-decrypt charts

## Slide 9: Security Trade-off and Detection
- Security vs performance scatter
- Attack detection chart

## Slide 10: Attack Demos
- Eavesdrop: ciphertext-only exposure
- Replay: duplicate rejection
- MITM tamper: auth failure

## Slide 11: Validation
- Test coverage summary
- Total passing tests and key checks

## Slide 12: Conclusion and Next Steps
- Key takeaways
- Limitations
- Future work roadmap
