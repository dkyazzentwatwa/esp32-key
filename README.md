# ESP32-S3 AMOLED FIDO Lab Key

Experimental Arduino CLI firmware that turns the Waveshare ESP32-S3-Touch-AMOLED-1.8 into a USB FIDO/WebAuthn lab authenticator.

This is a learning and testing project. It has completed Chrome/WebAuthn.io registration and sign-in in local testing for both non-discoverable and discoverable/resident credentials, but it is not a certified security key and must not be used to protect important accounts.

## Safety Boundary

Use this only with owned disposable accounts, local test apps, or public demo relying parties such as WebAuthn.io.

This board stores or derives credential secrets from ESP32-S3 flash/NVS state. In the current lab profile, a person with physical possession of the board and the right tooling may be able to extract or clone credential material. Reset is useful cleanup, not forensic erasure.

This project does not claim:

- FIDO certification.
- Production hardening.
- Secure-element-backed key storage.
- Production attestation.
- Resistance to physical extraction.
- Suitability for personal, business, financial, cloud, developer, password-manager, cryptocurrency, or government accounts.

Read [SECURITY.md](SECURITY.md) before using the device with any account.

## What It Does

- Enumerates as a USB FIDO HID device named `ESP32-S3 AMOLED FIDO Lab Key`.
- Handles CTAP2 registration, sign-in, discoverable/resident credentials, credential management, host-entered lab PIN flows, and guarded reset.
- Supports stateless non-resident credentials with 33-byte wrapped credential IDs.
- Keeps browser testing CTAP2-first while retaining direct legacy U2F probe coverage.
- Uses BOOT/GPIO0 as the physical user-presence button for registration, signing, and reset.
- Shows host activity, prompts, errors, and reset/admin state on the AMOLED display.
- Optionally writes redacted TF-card lab logs and proof notes without USB mass storage or credential export.
- Includes repeatable host probes for compile, enumeration, CTAP2, U2F, PIN, browser-compat behavior, and cleanup reset.

## Hardware

Target board:

- Waveshare `ESP32-S3-Touch-AMOLED-1.8`
- ESP32-S3R8 with 16 MB flash and 8 MB PSRAM
- 1.8 inch 368 x 448 AMOLED
- Native USB-C
- BOOT button on GPIO0
- Optional FAT32 TF card for redacted lab diagnostics

Use a USB-C data cable. Charge-only cables can power the board without exposing serial or FIDO HID.

## Quick Start

Install probe dependencies:

```sh
python3 -m pip install hidapi cbor2 cryptography
```

Compile the lab profile:

```sh
arduino-cli compile --profile fido-lab .
```

List attached boards:

```sh
arduino-cli board list
```

Upload to the detected ESP32-S3 serial port:

```sh
arduino-cli upload --profile fido-lab -p /dev/cu.usbmodemXXXX .
```

After flashing, run the repeatable baseline:

```sh
tools/run_probe_baseline.sh
```

The baseline compiles `fido-lab`, lists FIDO HID devices, runs the host probe ladder, creates disposable lab credentials, sets the lab PIN during the PIN smoke test, and ends with a guarded CTAP2 reset. Press BOOT whenever the AMOLED asks for user presence or reset confirmation.

Browser testing is separate. Use a real browser/WebAuthn.io flow when you need browser proof.

## Browser Demo

Use a test relying party only. WebAuthn.io has worked with:

- User verification: discouraged
- Attachment: cross-platform
- Attestation: none
- Public key algorithm: ES256
- Discoverable credential: discouraged for non-resident testing
- Discoverable credential: required for resident credential testing
- USB security key selected when the browser prompts

Expected flow:

1. Start registration or sign-in in the browser.
2. Select the USB security key.
3. Confirm the AMOLED shows the expected action.
4. Press BOOT once for user presence.
5. Confirm the browser completes the operation.

## Proof Levels

Keep these separate when reporting results:

- Compile-ready: Arduino CLI build succeeded.
- Uploaded: esptool wrote and verified flash.
- Enumerated: the host sees the FIDO HID device.
- Probe-proven: `tools/ctaphid_probe.py` or `tools/run_probe_baseline.sh` passed.
- Browser-proven: a real browser registration/sign-in succeeded.

Compile output alone is not browser or hardware proof.

## Project Layout

- `esp32-key.ino`: Arduino sketch entrypoint.
- `sketch.yaml`: board profile, FQBN, ESP32 core, and library source of truth.
- `src/`: USB HID, CTAPHID, CTAP2/U2F, CBOR, crypto, NVS storage, BOOT presence, AMOLED UX, and lab recorder modules.
- `tools/ctaphid_probe.py`: focused host probe tool.
- `tools/run_probe_baseline.sh`: repeatable compile/list/probe/reset baseline.
- `docs/bringup/arduino-cli-mvp.md`: full bring-up and probe reference.
- `docs/roadmap/solo-like-lab-plus.md`: feature roadmap and proof notes.
- `docs/specs/esp32-s3-fido2-webauthn-authenticator-spec.md`: design-level notes and hardening boundaries.

## Development Rules

- Keep this Arduino CLI-only.
- Do not add PlatformIO, ESP-IDF project scaffolding, CMake conversion, keyboard HID, mouse HID, mass storage, covert host-control behavior, credential export, phishing flows, or impersonation flows.
- Use `fido-lab` for realistic browser/WebAuthn testing.
- Use `debug-cdc` only for explicit bring-up work.
- Keep docs blunt about the lab-only risk boundary.

This is a bench key for learning how FIDO/WebAuthn works on tiny hardware. Treat it like a transparent prototype, not a production authenticator.
