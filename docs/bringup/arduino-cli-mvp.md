# Arduino CLI MVP Bring-up

This repo is intentionally Arduino CLI only. Do not add PlatformIO or an ESP-IDF project wrapper.

## Local Tooling

- Arduino CLI: `1.4.1`
- ESP32 Arduino core: `esp32:esp32 3.3.8`
- Target FQBN: `esp32:esp32:waveshare_esp32_s3_touch_amoled_18`
- Primary profile: `fido-lab`

## Compile

```sh
arduino-cli compile --profile fido-lab /Users/cypher/Documents/GitHub/esp32-key
```

Debug bring-up profile:

```sh
arduino-cli compile --profile debug-cdc /Users/cypher/Documents/GitHub/esp32-key
```

## Upload

Attach the Waveshare ESP32-S3-Touch-AMOLED-1.8 and re-check the port:

```sh
arduino-cli board list
arduino-cli upload --profile fido-lab -p /dev/cu.usbmodemXXXX /Users/cypher/Documents/GitHub/esp32-key
```

No upload proof exists until a real `/dev/cu.usbmodem*` board is detected.

## Host Probe

After flashing, install optional host dependencies:

```sh
python3 -m pip install hidapi cbor2 cryptography
```

Then run:

```sh
python3 tools/ctaphid_probe.py --list
python3 tools/ctaphid_probe.py
python3 tools/ctaphid_probe.py --ctap2-roundtrip
python3 tools/ctaphid_probe.py --resident-roundtrip
python3 tools/ctaphid_probe.py --cred-mgmt-smoke
python3 tools/ctaphid_probe.py --client-pin-smoke
python3 tools/ctaphid_probe.py --dummy-rp-probe
python3 tools/ctaphid_probe.py --dummy-makecred-probe
python3 tools/ctaphid_probe.py --preflight-probe
python3 tools/ctaphid_probe.py --stateless-bulk 9
python3 tools/ctaphid_probe.py --login-verify
python3 tools/ctaphid_probe.py --reset
```

The basic probe sends CTAPHID INIT, PING, and CTAP2 getInfo. The CTAP2 roundtrip probe performs makeCredential followed by getAssertion and asks for BOOT on both sensitive operations. The resident roundtrip probe creates a discoverable credential and signs in without an allow list. The credential-management smoke probe creates a resident credential, enumerates RPs and credentials, deletes the credential with BOOT confirmation, and verifies that the deleted RP no longer signs. The client PIN smoke probe sets a lab PIN, obtains a PIN/UV token, and verifies UV-required registration and sign-in. The dummy RP probe verifies that reserved `.dummy` getAssertion is answered silently with `0x2e` no-credentials and never asks for BOOT. The dummy makeCredential probe verifies Chrome's synthetic touch path: it asks for BOOT, creates no credential, and returns `0x27` operation-denied. The pre-flight probe registers a credential, then verifies that a `getAssertion` with `options.up=false` returns immediately with the UP authData flag cleared and **without** a BOOT press, and that the following real `up=true` assertion still requires BOOT and sets UP=1. The login oracle verifies canonical CBOR, UP flags, resident-user privacy under UV discouraged, and ES256 signatures for non-resident and resident paths. Chrome/WebAuthn.io browser testing passed on 2026-05-31 for both non-discoverable and discoverable/resident security-key flows after these probes and fixes.

## Current MVP Boundary

The firmware compiles and includes:

- FIDO HID descriptor with 64-byte IN/OUT reports.
- CTAPHID INIT, PING, CBOR, CANCEL, WINK, ERROR, and KEEPALIVE support.
- CTAP2 getInfo, makeCredential, getAssertion, and guarded reset handlers.
- CTAP2 discoverable credentials and getNextAssertion for lab account flows.
- Stateless key-wrapping for non-resident credentials: the P-256 key is derived from a device master secret plus a per-credential nonce, the nonce and an rpIdHash-bound MAC are carried inside a 33-byte credential ID, and nothing is stored in NVS. This removes the 8-slot cap for non-resident creds. Resident credentials still use the credential store. A reset rotates the master secret and invalidates every outstanding stateless credential ID.
- CTAP2 `getAssertion` honors the `options.up=false` silent pre-flight: it answers without BOOT and clears the UP authData flag, so the browser's credential-discovery step no longer hangs on a touch. Synthetic `.dummy` getAssertion requests are answered silently with no-credentials, while synthetic `.dummy` makeCredential asks for BOOT, creates no credential, and returns operation-denied for Chrome's touch-collection path.
- Discoverable-credential assertions with UV discouraged return the user handle but suppress identifying account strings unless host PIN/UV completed, matching Chrome's resident-credential privacy expectations.
- Minimal CTAP2 credential management for lab enumerate/delete/update flows.
- CTAP `authenticatorClientPIN` PIN protocol 2 for host-entered lab PIN and UV-required flows.
- Legacy CTAP1/U2F compatibility for direct lab probes; the `fido-lab` CTAPHID capability advertisement is CTAP2/CBOR-first.
- Stateless non-resident credential IDs; only resident/discoverable credentials use NVS credential slots.
- Versioned, checksummed NVS credential storage.
- ES256/P-256 key generation and signing through Arduino-accessible mbedTLS.
- BOOT/GPIO0 user-presence confirmation.
- AMOLED admin reset screen with credential count, storage-full status, and two-step BOOT wipe confirmation.
- AMOLED status and diagnostic screens for host commands, rejections, prompts, and success states.

Browser flows that require user verification or PIN should use the host/browser PIN dialog. The AMOLED is status-only for PIN flows.

## AMOLED Admin Reset

The local admin reset is intentionally blunt: it wipes credentials and the lab PIN. It does not yet browse/delete individual credentials.

1. Long-hold BOOT for about 2 seconds to open the admin reset screen.
2. Release BOOT.
3. Long-hold BOOT again for about 5 seconds to confirm the wipe.
