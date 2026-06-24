# CLAUDE.md

Experimental **Arduino CLI** firmware that turns Waveshare **ESP32-S3 display boards** into USB **FIDO/WebAuthn lab keys**. It is a learning prototype: not FIDO certified, not production hardened, and for use only with disposable test accounts and lab relying parties (e.g. WebAuthn.io). Keep security language blunt and conservative — see [SECURITY.md](SECURITY.md).

## Architecture

Data flows host → USB → transport → protocol → crypto/storage, with the board display reflecting state:

```
esp32-key.ino → src/App (Esp32KeyApp, orchestrates subsystems)
  USB        src/UsbFidoHid    HID enumeration, 64-byte reports, FIDO usage page
  Transport  src/CtapHid       CTAPHID framing: INIT/PING/CBOR/MSG/CANCEL/WINK/KEEPALIVE
  Protocol   src/Ctap2         makeCredential / getAssertion / getNextAssertion /
                               credential mgmt / guarded reset / legacy CTAP1/U2F
             src/CborCodec     CBOR encode/decode used by Ctap2
  Crypto     src/CryptoProvider  ES256 / P-256 keygen + signing
  Storage    src/CredentialStore NVS, versioned + checksummed records, fixed cap
  Presence   src/UserPresence  BOOT / GPIO0 confirmation
  UX         src/AmoledUx + src/BoardProfile + src/Diagnostics  status / diagnostic screens
```

`src/Ctap2.cpp` is by far the largest module and holds most protocol logic. Configuration truth lives in [sketch.yaml](sketch.yaml) (FQBN, ESP32 core `3.3.8`, `fido-lab` / `debug-cdc` / `fido-lab-147` / `debug-cdc-147` profiles), [src/BoardProfile.h](src/BoardProfile.h) (board display pins/geometry), and [src/BuildConfig.h](src/BuildConfig.h) (device name, pins, limits).

## Key invariants

- **Arduino CLI only** — no PlatformIO, ESP-IDF scaffolding, or CMake conversion.
- USB exposes **only** the FIDO HID interface — never keyboard, mouse, mass-storage, or covert host-control behavior.
- 64-byte HID reports (`kHidReportSize`) on the FIDO usage page; **ES256 / P-256 only**.
- Resident credential cap is `kMaxCredentials = 8`; non-resident credentials are stateless 33-byte wrapped IDs.
- **BOOT / GPIO0** (`kBootButtonPin = 0`) is the user-presence button for register/sign/reset.
- Lab CTAP `authenticatorClientPIN` exists for host-entered PIN protocol 2 testing. Built-in UV is still false; use WebAuthn UV `discouraged` unless intentionally testing browser/OS PIN prompts.
- For resident/discoverable sign-in with UV discouraged, assertions must not include identifying user strings (`name`, `displayName`, `icon`); return only the user handle unless host PIN/UV completed.
- Optional SD lab recorder uses 1-bit SD_MMC (`CLK=2`, `CMD=1`, `D0=3`) for redacted diagnostics only. Never log secrets, raw credential IDs, PIN material, clientDataHash values, signatures, usernames, display names, or add USB mass storage.
- `fido-lab-147` targets the Waveshare ESP32-S3-Touch-LCD-1.47 through the generic `esp32:esp32:esp32s3` FQBN, ST7789-compatible 172x320 LCD UI, and BOOT/GPIO0 confirmation. Touch is not a FIDO approval mechanism.

## Commands

```sh
# Compile (primary profile for browser/WebAuthn testing)
arduino-cli compile --profile fido-lab /Users/cypher/Documents/GitHub/esp32-key

# Compile the 1.47 inch Touch-LCD profile
arduino-cli compile --profile fido-lab-147 /Users/cypher/Documents/GitHub/esp32-key

# Flash (find the port with `arduino-cli board list`)
arduino-cli upload --profile fido-lab -p /dev/cu.usbmodemXXXX /Users/cypher/Documents/GitHub/esp32-key

# Flash the 1.47 inch Touch-LCD profile
arduino-cli upload --profile fido-lab-147 -p /dev/cu.usbmodemXXXX /Users/cypher/Documents/GitHub/esp32-key
```

Use `debug-cdc` / `debug-cdc-147` only for bring-up that needs serial logs. Full flash/probe/browser steps are in [README.md](README.md); host tests run through [tools/ctaphid_probe.py](tools/ctaphid_probe.py) (e.g. `--list`, `--ctap2-roundtrip`, `--resident-roundtrip`). Press BOOT once when a probe or browser waits for user presence.

## Proof levels

Compile ≠ upload ≠ enumerate ≠ probe ≠ browser. **Never claim hardware or browser success from compile output alone** — verify at the level you actually reached.

Current browser proof: on 2026-05-31 Chrome/WebAuthn.io completed registration and sign-in for both non-discoverable security-key credentials and discoverable/resident credentials using ES256, security-key hints, and UV discouraged for registration/authentication. Chrome may still prompt for the host PIN when the lab PIN is set.

## Before changing USB, crypto, or storage

Read [SECURITY.md](SECURITY.md) first — those paths define the device's safety boundary. When firmware behavior changes, keep the relevant docs in sync ([README.md](README.md), [SECURITY.md](SECURITY.md), [docs/bringup/arduino-cli-mvp.md](docs/bringup/arduino-cli-mvp.md), [docs/roadmap/solo-like-lab-plus.md](docs/roadmap/solo-like-lab-plus.md), [docs/specs/esp32-s3-fido2-webauthn-authenticator-spec.md](docs/specs/esp32-s3-fido2-webauthn-authenticator-spec.md)).

## Coding-agent rules

The full project contract, USB-safety rules, security-language rules, hardware workflow, and editing/documentation rules live in AGENTS.md and are imported here:

@AGENTS.md
