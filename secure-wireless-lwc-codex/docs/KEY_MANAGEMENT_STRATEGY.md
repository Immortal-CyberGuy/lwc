# Lightweight Key Management Strategy (Codex Version)

## Why this matters
The project requirement is not only "use ASCON", but to run secure communication in a constrained setting with a key strategy that is both lightweight and defensible.

## Standards-based decisions
1. **128-bit floor for symmetric security**
   - We keep derived engine keys at 16 bytes (128 bits) for ASCON/AES/SPECK compatibility.
2. **CSPRNG root keys**
   - Root keys are generated with `os.urandom`, matching cryptographic randomness guidance.
3. **Nonce uniqueness per key**
   - We use a fixed-field + counter nonce pattern (`fixed_field(8) || sequence(8)`) as a deterministic uniqueness strategy.
4. **HKDF domain separation**
   - Root keys are not used directly in all contexts.
   - We derive engine keys with HKDF over context (`engine`, `profile`, `deployment`, `session`) to reduce key-reuse risk.
5. **Rekey thresholds**
   - Profiles include practical message-count rotation thresholds to limit long-term exposure.

## Profile summary
- `minimal`: smallest footprint (16-byte root key).
- `balanced`: recommended default for this project.
- `hardened`: 32-byte root key and faster rotation.

## Code entry points
- `src/utils/key_manager.py`
  - `recommended_profiles()`
  - `generate_root_key()`
  - `derive_engine_key()`
  - `derive_nonce_fixed_field()`
  - `build_counter_nonce()`
  - `assess_key_material()`
  - `should_rekey()`

## Primary references
- NIST SP 800-232 (Ascon family): https://csrc.nist.gov/pubs/sp/800/232/final
- NIST SP 800-133 Rev.2 (Key generation): https://csrc.nist.gov/pubs/sp/800/133/r2/final
- NIST SP 800-38D (GCM IV/nonce uniqueness guidance): https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
- RFC 5116 (AEAD interface and nonce requirements): https://www.rfc-editor.org/rfc/rfc5116
- RFC 5869 (HKDF): https://www.rfc-editor.org/rfc/rfc5869

