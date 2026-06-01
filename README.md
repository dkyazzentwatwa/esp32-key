# ESP32-S3 AMOLED FIDO Lab Key

Experimental Arduino CLI firmware for using the Waveshare ESP32-S3-Touch-AMOLED-1.8 as a USB FIDO/WebAuthn lab authenticator.

This project is a learning prototype. It has completed Chrome/WebAuthn.io registration and sign-in in local testing for both non-discoverable security-key credentials and discoverable/resident credentials, but it is not a certified FIDO authenticator and must not be used to protect important personal, business, financial, cloud, or developer accounts.

## Lab Safety Boundary

Use this firmware only with owned disposable test accounts, local relying parties, or public demo relying parties such as WebAuthn.io.

This board stores or derives credential secrets from ESP32-S3 flash-backed state. In the current lab profile, anyone with physical possession of the board and the right tooling may be able to extract or clone resident credential private keys, the stateless master secret, or other NVS-backed credential material. Reset is useful cleanup, but it is not a forensic erasure guarantee.

Browser success proves lab interoperability only. It does not prove FIDO certification, secure-element-backed storage, production attestation, physical-extraction resistance, or suitability for important accounts.

## Current Status

The firmware currently supports:

- Waveshare ESP32-S3-Touch-AMOLED-1.8 target board.
- Arduino CLI-only build and upload workflow.
- ESP32 Arduino core `3.3.8`.
- USB HID FIDO device enumeration as `ESP32-S3 AMOLED FIDO Lab Key`.
- 64-byte FIDO HID reports using the FIDO usage page.
- CTAPHID `INIT`, `PING`, `CBOR`, `MSG`, `CANCEL`, `WINK`, `ERROR`, and `KEEPALIVE`.
- CTAP2 `authenticatorGetInfo`, `authenticatorMakeCredential`, `authenticatorGetAssertion`, and guarded reset.
- CTAP2 discoverable/resident credentials and `authenticatorGetNextAssertion` for lab account flows.
- Minimal CTAP2 credential management for lab enumeration, delete, and user-info update flows.
- Standard host-entered CTAP `authenticatorClientPIN` using PIN protocol 2 for lab UV-required flows.
- Legacy CTAP1/U2F registration and authentication compatibility for direct lab probes, while the main `fido-lab` capability advertisement steers browsers toward CTAP2.
- ES256/P-256 key generation and signing through Arduino-accessible crypto.
- Stateless non-resident credentials using 33-byte wrapped credential IDs; resident/discoverable credentials still use the small fixed NVS lab store.
- Versioned, checksummed credential records with deterministic storage-full behavior.
- BOOT/GPIO0 user-presence confirmation for registration, signing, and reset.
- AMOLED admin reset screen with credential count, resident count, free-slot/full status, and two-step BOOT wipe confirmation.
- AMOLED status and diagnostic screens for host commands, rejections, user-presence prompts, and success states.
- Optional TF-card lab recorder for redacted JSONL event logs, proof notes, boot/error breadcrumbs, and AMOLED session history.
- Host-side probing with `tools/ctaphid_probe.py`.
- Solo-like Lab Plus roadmap tracked in `docs/roadmap/solo-like-lab-plus.md`.

## Hardware

Target board:

- Waveshare `ESP32-S3-Touch-AMOLED-1.8`
- ESP32-S3R8, 8 MB PSRAM, 16 MB flash
- 1.8 inch 368 x 448 SH8601 AMOLED
- Native ESP32-S3 USB over USB-C
- BOOT button on GPIO0
- Optional FAT32 TF card in the onboard slot for non-secret lab diagnostics

Use a USB-C data cable. Some charge-only cables will power the board but will not enumerate USB HID or serial.

## Safety Boundary Details

Use this firmware only with disposable lab accounts, local relying parties, or public demo relying parties such as WebAuthn.io.

Known boundaries:

- Not FIDO certified.
- Not production hardened.
- No secure element.
- Lab host PIN only; no biometric/user-verification hardware and no hardened PIN storage.
- No biometric verification.
- No hardened private-key storage.
- No protection against physical flash/NVS extraction in the current lab profile.
- No protection against malicious firmware replacement unless you add and correctly provision secure boot and flash encryption.
- Lab attestation only. Do not represent this as a trusted commercial authenticator.

Read [SECURITY.md](SECURITY.md) before using the device with any account.

## Build

Primary profile:

```sh
arduino-cli compile --profile fido-lab /Users/cypher/Documents/GitHub/esp32-key
```

Debug bring-up profile:

```sh
arduino-cli compile --profile debug-cdc /Users/cypher/Documents/GitHub/esp32-key
```

Use `fido-lab` for browser/WebAuthn testing. Use `debug-cdc` only for bring-up when serial logs are worth the USB-interface tradeoff.

## Flash

List attached boards:

```sh
arduino-cli board list
```

Upload to the detected ESP32-S3 serial port:

```sh
arduino-cli upload --profile fido-lab -p /dev/cu.usbmodemXXXX /Users/cypher/Documents/GitHub/esp32-key
```

If the board is in bootloader mode, it usually appears as `/dev/cu.usbmodem*`. After flashing and rebooting normally, it should enumerate as a FIDO HID device instead of only a serial download device.

## Host Probe

Install probe dependencies in your preferred Python environment:

```sh
python3 -m pip install hidapi cbor2 cryptography
```

Run the repeatable baseline after flashing:

```sh
tools/run_probe_baseline.sh
```

The baseline lists attached boards, compiles `fido-lab`, lists FIDO HID devices, runs the host probe ladder, and ends with a guarded CTAP2 reset. It mutates lab state by creating disposable credentials and setting the lab PIN during the PIN smoke probe, then asks you to hold BOOT for cleanup reset. Press BOOT whenever the AMOLED requests user presence or reset confirmation.

Baseline proof levels:

- Compile-ready: `arduino-cli compile --profile fido-lab` succeeded.
- Enumerated: the host probe opened the FIDO HID device after listing devices.
- Probe-proven: the CTAPHID, CTAP2, PIN, U2F, stateless, and browser-compat probes passed.
- Cleanup-reset requested: guarded reset completed after BOOT confirmation.

Browser-proven status is separate. Run a real browser/WebAuthn.io registration and sign-in manually when you need browser proof.

Targeted probe commands remain useful while debugging:

List FIDO HID devices:

```sh
python3 tools/ctaphid_probe.py --list
```

Run the basic CTAPHID and CTAP2 probe:

```sh
python3 tools/ctaphid_probe.py
```

Run direct CTAP2 registration:

```sh
python3 tools/ctaphid_probe.py --make-credential
```

Run direct CTAP2 registration plus sign-in:

```sh
python3 tools/ctaphid_probe.py --ctap2-roundtrip
```

Run discoverable credential registration plus sign-in:

```sh
python3 tools/ctaphid_probe.py --resident-roundtrip
```

Run credential-management smoke coverage:

```sh
python3 tools/ctaphid_probe.py --cred-mgmt-smoke
```

Run host PIN and UV-required CTAP2 smoke coverage:

```sh
python3 tools/ctaphid_probe.py --client-pin-smoke
```

Verify the reserved `.dummy` relying party is rejected silently (must return `0x2e` with no BOOT and no AMOLED change):

```sh
python3 tools/ctaphid_probe.py --dummy-rp-probe
```

Verify Chrome's reserved `.dummy` `makeCredential` touch-collection path (press BOOT when prompted; it must create no credential and return `0x27` operation-denied):

```sh
python3 tools/ctaphid_probe.py --dummy-makecred-probe
```

Verify silent login pre-flight handling (registers a credential, then checks that an `up=false` assertion answers without BOOT and clears the UP flag, while the real `up=true` assertion still needs BOOT):

```sh
python3 tools/ctaphid_probe.py --preflight-probe
```

Prove non-resident credentials are stateless (register more than the 8-slot store cap, sign one, and reject tampered / cross-RP credential IDs). Press BOOT once per registration:

```sh
python3 tools/ctaphid_probe.py --stateless-bulk 9
```

Run the Chrome-like login oracle for non-resident and resident paths (checks canonical CBOR, UP flags, resident-user privacy, and ES256 signatures):

```sh
python3 tools/ctaphid_probe.py --login-verify
```

Run a guarded lab credential wipe:

```sh
python3 tools/ctaphid_probe.py --reset
```

Use the on-device AMOLED admin reset:

1. Long-hold BOOT for about 2 seconds to open the admin reset screen.
2. Release BOOT.
3. Long-hold BOOT again for about 5 seconds to wipe credentials and the lab PIN.

Run direct legacy U2F registration against the lab handler:

```sh
python3 tools/ctaphid_probe.py --u2f-register
```

When the AMOLED prompts for user presence, press BOOT once. For reset, hold BOOT until the board confirms the wipe; on-device reset requires the two-hold admin flow above. A successful PIN smoke probe sets a lab PIN, requests a PIN/UV token, and verifies UV-required registration and sign-in. A successful U2F probe should return `U2F register status=0x9000` and `Verified OK`. Browsers should prefer CTAP2 because `fido-lab` advertises CBOR and no CTAPHID MSG support.

## Browser Test

Use a test relying party only. WebAuthn.io has worked for this lab flow.

Recommended WebAuthn.io registration settings:

- User verification: discouraged
- Attachment: cross-platform
- Discoverable credential: discouraged
- Attestation: none
- Public key algorithm: ES256
- Select USB security key when the browser prompts

Browser-proven Chrome/WebAuthn.io settings as of 2026-05-31:

- Non-discoverable path: registration and authentication user verification discouraged, discoverable credential discouraged, ES256, security-key hints for registration and authentication.
- Discoverable/resident path: registration and authentication user verification discouraged, discoverable credential required, ES256, security-key hints for registration and authentication.
- Chrome may still show a host PIN prompt even with UV discouraged if a lab PIN is set; the current lab PIN used during bring-up was `123456`.

Expected device flow:

1. Browser opens the USB security-key prompt.
2. AMOLED shows host activity such as `HID INIT`, `CBOR getInfo`, or `makeCredential`.
3. AMOLED shows a user-presence prompt.
4. Press BOOT once.
5. AMOLED shows success.
6. Browser completes registration or sign-in.

If the browser hangs, check the AMOLED diagnostic text first. It is designed to show whether the host sent a command, the firmware rejected the request, or the USB HID send path failed. When the device returns to the ready screen it also shows the last command, the last relying party, and the last CTAP2 status, and marks synthetic host probes so they can be told apart from real relying-party prompts.

Login is expected to prompt for BOOT for the real relying-party assertion. The browser first runs a silent pre-flight (`getAssertion` with `up=false`) to find which security key holds the credential; the firmware answers that immediately with no BOOT, then the real sign-in prompts for BOOT. Chrome/macOS may also send reserved `.dummy` relying-party requests: `.dummy` `getAssertion` remains silent no-credentials, while `.dummy` `makeCredential` is treated as a synthetic touch-collection step that asks for BOOT, creates no credential, and returns operation-denied.

With discoverable credentials and browser authentication user verification set to discouraged, sign-in should not ask for the PIN. The assertion may still include the user handle, but the firmware suppresses identifying user strings (`name`, `displayName`, `icon`) unless UV/PIN actually completed; Chrome can reject a signed assertion as a privacy error if those fields are exposed without UV.

For PIN-required browser tests, use the browser or OS PIN dialog. Do not enter PIN material on the AMOLED; the screen only shows status. The current host probe sets the lab PIN to `123456`; reset the device before treating browser PIN behavior as a fresh setup test.

## SD Lab Recorder

If a FAT32 TF card is present, the firmware mounts the onboard slot through 1-bit SD_MMC (`CLK=GPIO2`, `CMD=GPIO1`, `D0=GPIO3`) and creates:

- `/fido-lab/sessions/session-NNN.jsonl`: redacted per-boot event log.
- `/fido-lab/proofs/session-NNN.md`: compact lab proof notes for successful register/sign/reset/admin events.

The recorder is optional. If the card is missing, unreadable, or full, FIDO registration and sign-in continue normally and the AMOLED shows a passive SD status. The recorder never exposes USB mass storage and never writes credential private keys, the stateless master secret, PINs, PIN/UV tokens, browser client data hashes, signatures, raw credential IDs, usernames, or display names.

Default redaction stores full RP names only for common lab RPs such as `webauthn.io` and `.dummy`; other RP IDs are recorded as `redacted` plus a short SHA-256 hash. Removing the card exposes lab metadata, so treat logs as diagnostic artifacts rather than publishable security evidence.

## Project Layout

Important files:

- `esp32-key.ino`: Arduino sketch entrypoint.
- `sketch.yaml`: pinned Arduino CLI profiles, ESP32 core, FQBN, and libraries.
- `src/`: USB HID, CTAPHID, CTAP2/U2F, CBOR, crypto, NVS storage, BOOT presence, and AMOLED UX modules.
- `tools/ctaphid_probe.py`: host-side CTAPHID, CTAP2, and U2F probe script.
- `tools/run_probe_baseline.sh`: repeatable compile/list/probe/reset baseline for the lab key.
- `docs/bringup/arduino-cli-mvp.md`: bring-up notes and command reference.
- `docs/roadmap/solo-like-lab-plus.md`: roadmap toward host PIN, resident credentials, credential management, and touch/admin UX.
- `docs/specs/esp32-s3-fido2-webauthn-authenticator-spec.md`: original design specification.

## Development Rules

- Keep the project Arduino CLI-only.
- Do not add PlatformIO, ESP-IDF project scaffolding, or CMake conversion.
- Do not add keyboard, mouse, mass-storage, or covert HID behavior.
- Compile before flashing.
- Treat compile success, upload success, probe success, and browser success as separate proof levels.
- Keep security language blunt and conservative.

See [AGENTS.md](AGENTS.md) for future coding-agent instructions.
