# Agent Instructions

This repository is an Arduino CLI-only firmware project for the Waveshare ESP32-S3-Touch-AMOLED-1.8 FIDO/WebAuthn lab key.

Follow these instructions for all future coding-agent work in this repo.

## Project Contract

- Keep the project Arduino CLI-only.
- Do not add PlatformIO.
- Do not add ESP-IDF project scaffolding.
- Do not convert the project to CMake.
- Do not add generated multi-framework wrappers.
- Preserve `sketch.yaml` as the source of board/profile truth.
- Prefer existing `src/` module boundaries over broad rewrites.

Primary compile command:

```sh
arduino-cli compile --profile fido-lab /Users/cypher/Documents/GitHub/esp32-key
```

Primary upload command:

```sh
arduino-cli upload --profile fido-lab -p /dev/cu.usbmodemXXXX /Users/cypher/Documents/GitHub/esp32-key
```

## Profiles

Use `fido-lab` for realistic browser and WebAuthn testing.

Use `debug-cdc` only for bring-up work that explicitly needs serial diagnostics. Do not make browser success depend on debug serial output.

Do not casually change:

- Target FQBN: `esp32:esp32:waveshare_esp32_s3_touch_amoled_18`
- ESP32 Arduino core baseline: `3.3.8`
- Partition/profile choices in `sketch.yaml`
- USB HID report size
- FIDO usage page/report descriptor

## USB Safety

The device should expose only the interfaces needed for the FIDO lab authenticator.

Do not add:

- Keyboard interfaces.
- Mouse interfaces.
- Mass-storage interfaces.
- Gamepad interfaces.
- Covert host-control behavior.
- Credential export commands.
- Phishing or impersonation flows.

If a USB change is required, document why it is needed and prove it does not turn the device into a general HID attack tool.

## Security Language

Keep security claims conservative.

Always describe this project as:

- Experimental.
- Lab/prototype only.
- Not FIDO certified.
- Not production hardened.
- Not suitable for important accounts.

Do not imply:

- Secure-element-backed protection.
- Certified authenticator behavior.
- Production attestation.
- Resistance to physical extraction.
- Safe storage for high-value credentials.

## Hardware Workflow

Before flashing:

1. Run `arduino-cli board list`.
2. Compile with the intended profile.
3. Confirm the detected `/dev/cu.usbmodem*` port.
4. Upload with the intended profile.
5. Re-detect the device after reset.

After flashing, distinguish proof levels:

- Compile-ready: build succeeded.
- Uploaded: esptool wrote and verified flash.
- Enumerated: host sees the FIDO HID device.
- Probe-proven: `tools/ctaphid_probe.py` succeeds.
- Browser-proven: WebAuthn registration/sign-in succeeds in a browser.

Do not claim browser or hardware success from compile output alone.

## Test Commands

List FIDO devices:

```sh
tools/ctaphid_probe.py --list
```

Run basic probe:

```sh
tools/ctaphid_probe.py
```

Run CTAP2 makeCredential probe:

```sh
tools/ctaphid_probe.py --make-credential
```

Run CTAP2 register/sign roundtrip probe:

```sh
tools/ctaphid_probe.py --ctap2-roundtrip
```

Run CTAP2 resident/discoverable roundtrip probe:

```sh
tools/ctaphid_probe.py --resident-roundtrip
```

Run CTAP2 credential-management smoke probe:

```sh
tools/ctaphid_probe.py --cred-mgmt-smoke
```

Run CTAP2 host PIN smoke probe:

```sh
tools/ctaphid_probe.py --client-pin-smoke
```

Run guarded reset probe:

```sh
tools/ctaphid_probe.py --reset
```

Run legacy U2F register probe:

```sh
tools/ctaphid_probe.py --u2f-register
```

When a probe or browser test waits for user presence, press BOOT once.

## Editing Rules

- Protect user changes. Do not revert unrelated work.
- Avoid destructive commands such as `git reset --hard` or `git checkout --` unless the user explicitly asks.
- Keep edits focused on the requested behavior.
- Use existing module names and patterns unless there is a concrete reason to change them.
- Keep docs synchronized with actual firmware behavior.
- Keep browser troubleshooting notes grounded in observed diagnostics.

## Documentation Rules

If firmware behavior changes, update the docs that users and agents depend on:

- `README.md` for operator workflow.
- `SECURITY.md` for security boundary changes.
- `docs/bringup/arduino-cli-mvp.md` for bring-up details.
- `docs/roadmap/solo-like-lab-plus.md` for Solo-like roadmap progress.
- `docs/specs/esp32-s3-fido2-webauthn-authenticator-spec.md` for design-level changes.

Do not turn docs into marketing copy. This is a lab key, and the risk boundary should stay visible.
