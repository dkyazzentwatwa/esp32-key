# Solo-Like Lab Plus Roadmap

Status: roadmap implementation tracker
Targets: Waveshare ESP32-S3-Touch-AMOLED-1.8 and ESP32-S3-Touch-LCD-1.47
Security posture: Lab Plus, not production or FIDO certified

## Summary

This roadmap moves the working ESP32-S3 display-board WebAuthn lab key toward a Solo-like developer authenticator while keeping the claims conservative. The goal is better CTAP2 correctness, browser compatibility, standard host-entered PIN support, resident credentials, credential management, and richer display diagnostics.

The PIN direction is standard CTAP `authenticatorClientPIN`: the browser or OS prompts for PIN entry, and the board display shows status only. Touch hardware may later host local admin/settings UI, but it must not become the browser PIN entry path.

## Milestones

### 1. CTAP2 Compatibility Baseline

- Prefer modern CTAP2 host probes over legacy U2F proof.
- Keep CTAP1/U2F fallback code available for lab probes, but advertise no CTAPHID MSG support in `fido-lab` so browsers prefer CTAP2.
- Stop over-advertising unimplemented CTAP2.1-preview behavior.
- Add direct CTAP2 registration plus assertion probe coverage.

Current implementation slice:

- `getInfo` advertises `FIDO_2_0` only.
- CTAPHID INIT advertises `CBOR | NMSG` to steer browsers away from legacy U2F.
- `tools/ctaphid_probe.py --ctap2-roundtrip` registers and signs through CTAP2 without CTAP1/U2F.
- Storage V2 records are versioned and checksummed.
- `tools/ctaphid_probe.py --resident-roundtrip` creates a discoverable credential and signs in without an allow list.

### 2. Storage V2

- Replace raw fixed records with versioned credential records.
- Add bounded fields for resident credentials: RP ID, RP name, user handle, user name, display name, flags, and per-credential counter.
- Remove silent overwrite behavior once management/delete flows exist.
- Add migration-safe wipe behavior before changing persistent formats.

Current status:

- Implemented for the lab credential store.
- Storage full now returns an error instead of overwriting slot 0.
- Old incompatible records are compacted away at boot.

### 3. Host PIN

- Implement CTAP `authenticatorClientPIN` with PIN protocol 2 as the primary target.
- Add PIN set, change, retries, lockout, and token-permission flow.
- Store PIN verifier/state locally without logging or displaying PIN material.
- Advertise `clientPin` only after the command flow is implemented and tested.

Current status:

- Implemented as a lab PIN protocol 2 path.
- `tools/ctaphid_probe.py --client-pin-smoke` sets a test PIN, obtains a PIN/UV token, and verifies UV-required makeCredential/getAssertion.
- Browser compatibility still needs Chrome/Firefox/Safari validation with real OS PIN prompts.

### 4. Discoverable Credentials

- Support `rk=true` makeCredential requests.
- Support getAssertion without an allow list.
- Add `authenticatorGetNextAssertion` for multiple credentials.
- Use board display screens for RP/account display and BOOT confirmation.

Current status:

- Implemented for resident credentials without user verification.
- Multiple credentials for the same RP are returned with `getNextAssertion`.

### 5. Credential Management

- Enumerate relying parties.
- Enumerate credentials for a relying party.
- Delete credentials with physical confirmation.
- Update user information where supported.
- Show credential count and storage-full states on the board display.

Current status:

- Minimal lab implementation exists for resident-credential metadata, RP enumeration, credential enumeration, delete, and user-info update.
- `tools/ctaphid_probe.py --cred-mgmt-smoke` covers create, enumerate, delete, and post-delete failure.
- Display admin reset shows credential count/storage-full state and can wipe all credentials plus the lab PIN through a two-hold BOOT confirmation.

### 6. Touch/Admin UX

- Bring up touch controllers as separate modules when they are needed for local diagnostics.
- Test false activations before using touch near sensitive flows.
- Use touch for local diagnostics/settings only.
- Keep BOOT as the required confirmation for create/sign/delete/reset.

Current status:

- BOOT-only display admin reset exists.
- Individual credential browsing/deletion is still future touch/admin UI work.

### 7. Compatibility Matrix

- Track Chrome/Chromium, Firefox, Safari/macOS, Linux, macOS, and Windows behavior.
- Record whether each path used CTAP2 or CTAP1/U2F.
- Keep proof levels separate: compile-ready, uploaded, enumerated, probe-proven, browser-proven.

### 8. Stateless Credentials (Key-Wrapping)

Move non-resident credentials toward the Solo-Hacker model so the device is a usable developer key, not capped at a handful of sites.

- Derive each non-resident P-256 key from a device master secret plus a per-credential nonce; store nothing for them.
- Encode the nonce and an rpIdHash-bound MAC inside the credential ID; re-derive the key at assertion.
- Keep resident/discoverable credentials in the existing store (the cap applies only to them).
- Rotate the master secret on reset/admin-wipe so a reset invalidates every outstanding stateless credential ID.

Current status:

- Implemented. Non-resident `makeCredential` returns a 33-byte wrapped credential ID `[version:1][nonce:16][MAC:16]` and writes nothing to NVS; `getAssertion` is stateless-first and re-derives the key.
- `src/MasterSecret.{h,cpp}` holds the master secret (NVS namespace `fido_ms`), domain-separated HKDF sub-keys, and a global signature counter; `CryptoProvider::deriveP256FromSeed` does the deterministic keygen.
- `getAssertion` now evaluates the full allowList (not just the first entry) for mixed resident/stateless multi-account RPs.
- `tools/ctaphid_probe.py --stateless-bulk N` registers N (>8) non-resident credentials with no `kKeyStoreFull`, signs one, and confirms tampered and cross-RP credential IDs are rejected with `0x2e`.
- Hardware-verified: 9 stateless registrations (distinct 33-byte IDs), stateless sign, tamper/cross-RP rejection, resident path unchanged, and silent `up=false` pre-flight on a stateless credential.
- Browser-proven on Chrome/WebAuthn.io as of 2026-05-31 for both non-discoverable security-key credentials and discoverable/resident credentials with ES256, security-key hints, and user verification discouraged for registration and authentication. Chrome may still prompt for the host PIN when a lab PIN is set.
- `.dummy` getAssertion remains silent no-credentials, while `.dummy` makeCredential now collects BOOT as a synthetic touch step, creates no credential, and returns `0x27` operation-denied. `tools/ctaphid_probe.py --dummy-makecred-probe` covers this host touch-collection path.
- Resident/discoverable assertions suppress identifying user strings when UV is false; `--login-verify` checks that UV-discouraged sign-in returns only the user handle in the user entity.

### 9. SD Lab Recorder

Current status:

- Implemented as an optional, redacted recorder on the onboard TF slot using 1-bit SD_MMC (`CLK=2`, `CMD=1`, `D0=3`), with no USB mass-storage surface and no credential export path.
- Writes `/fido-lab/sessions/session-NNN.jsonl` and `/fido-lab/proofs/session-NNN.md` when a FAT32 card is present; missing/failed SD is passive and must not block FIDO flows.
- Logs CTAP/HID command names, statuses, counts, flags, redacted RP labels, short RP hashes, proof notes, and boot/error breadcrumbs. It never logs private keys, master secrets, PINs, PIN tokens, clientDataHash values, signatures, raw credential IDs, usernames, or display names.
- The ready/admin screens show passive SD state and the last redacted event summary without interrupting browser prompts or synthetic `.dummy` handling.

### 10. Waveshare Touch-LCD-1.47 Profile

Current status:

- `fido-lab-147` and `debug-cdc-147` build profiles exist for the Waveshare ESP32-S3-Touch-LCD-1.47.
- The 1.47 board uses the generic `esp32:esp32:esp32s3` FQBN with 16 MB flash, OPI PSRAM, TinyUSB mode, and the existing 3 MB app partition.
- The 1.47 runtime sets TinyUSB VID/PID to the working Waveshare AMOLED lab identity for iOS/WebAuthn.me compatibility testing, without changing the FIDO HID report descriptor or adding USB interfaces.
- `src/BoardProfile.h` selects the compact 172 x 320 ST7789-compatible LCD UI and preserves BOOT/GPIO0 as the FIDO user-presence input.
- Touch is not used as an approval mechanism.

## Test Commands

Compile:

```sh
arduino-cli compile --profile fido-lab /Users/cypher/Documents/GitHub/esp32-key
arduino-cli compile --profile fido-lab-147 /Users/cypher/Documents/GitHub/esp32-key
```

Upload:

```sh
arduino-cli upload --profile fido-lab -p /dev/cu.usbmodemXXXX /Users/cypher/Documents/GitHub/esp32-key
arduino-cli upload --profile fido-lab-147 -p /dev/cu.usbmodemXXXX /Users/cypher/Documents/GitHub/esp32-key
```

Basic probe:

```sh
tools/ctaphid_probe.py
```

CTAP2-only register/sign probe:

```sh
tools/ctaphid_probe.py --ctap2-roundtrip
```

Discoverable credential probe:

```sh
tools/ctaphid_probe.py --resident-roundtrip
```

Stateless non-resident credential / cap-removal probe:

```sh
tools/ctaphid_probe.py --stateless-bulk 9
```

Credential-management smoke probe:

```sh
tools/ctaphid_probe.py --cred-mgmt-smoke
```

Host PIN smoke probe:

```sh
tools/ctaphid_probe.py --client-pin-smoke
```

Browser-login debug probes:

```sh
tools/ctaphid_probe.py --dummy-rp-probe
tools/ctaphid_probe.py --dummy-makecred-probe
tools/ctaphid_probe.py --login-verify
```

Legacy U2F probe:

```sh
tools/ctaphid_probe.py --u2f-register
```

## Boundaries

- This roadmap does not make the device production-safe.
- No secure element is assumed.
- Secure boot, flash encryption, NVS encryption, and debug lockdown are future research items unless explicitly implemented and verified.
- The device must not expose keyboard, mouse, mass-storage, or host-attack interfaces.
- Browser PIN is host-entered through CTAP; touch PIN is optional future local admin UI only.
