# ESP32-S3 FIDO2/WebAuthn Authenticator Spec

Status: research/specification only
Target boards: Waveshare ESP32-S3-Touch-AMOLED-1.8 and Waveshare ESP32-S3-Touch-LCD-1.47
Primary implementation direction: Arduino CLI sketch using the ESP32 Arduino core native USB/HID stack
Security boundary: experimental learning prototype, not a certified or production security key

## 1. Executive Summary

This project is an experimental ESP32-S3-based FIDO2/WebAuthn hardware authenticator. The practical goal is to make a low-cost USB security-key learning prototype, similar in concept to a "poor man's YubiKey," that can enumerate as a FIDO USB HID authenticator and complete basic WebAuthn registration and login flows against test relying parties.

The firmware must be Arduino CLI only. The repository should be a normal Arduino sketch with a `sketch.yaml` project file and pinned Arduino CLI build profiles. Do not create an ESP-IDF application, PlatformIO project, CMake-based firmware tree, or generated multi-framework scaffold. Low-level ESP32-S3 facts from Espressif ESP-IDF documentation remain useful because the Arduino ESP32 core is built on ESP-IDF and the same silicon, but the project contract is Arduino CLI compile/upload/profile workflow.

The primary target board remains the Waveshare ESP32-S3-Touch-AMOLED-1.8, with a first-class Waveshare ESP32-S3-Touch-LCD-1.47 profile for the smaller display board. Both are ESP32-S3 display boards with native USB, BOOT/GPIO0 available as the physical user-presence input, onboard flash, and a screen suitable for visible consent and diagnostics. The 1.8 board uses a 368 x 448 SH8601 AMOLED panel; the 1.47 board uses a compact 172 x 320 ST7789-compatible LCD panel. The authenticator protocol must work over USB HID without depending on display type.

This is not a certified FIDO authenticator. It is not a production-ready security key, not a safe place for high-value real accounts, and not a replacement for a YubiKey, SoloKey, Titan key, passkey manager, smart card, or platform authenticator. The value of the project is education: learning CTAP HID framing, CTAP2 CBOR commands, WebAuthn credential creation, assertion signing, embedded key storage, and ESP32-S3 hardening tradeoffs.

The project must not include credential theft, covert keyboard injection, phishing workflows, authentication bypass, host attack tooling, or anything designed to impersonate another user. It should expose only a FIDO HID authenticator interface, not a keyboard interface, and all demonstrations should use owned local test accounts or public WebAuthn demo relying parties.

## 2. Goals

- Enumerate over USB as a FIDO-compatible HID authenticator using Arduino CLI, the ESP32 Arduino core, and its native USB/HID support.
- Implement a basic CTAP HID transport layer with channel initialization, request/response framing, continuation packets, cancellation, errors, and keepalive status.
- Implement a minimal CTAP2 command set for browser-driven WebAuthn registration and sign-in.
- Create credentials for local or public test WebAuthn relying parties.
- Produce authentication assertions for those test relying parties using the stored credential private key.
- Require physical user presence via a button press before creating credentials, signing assertions, or resetting stored credentials.
- Use the board display and optional LED only for transparent status, consent, errors, and lab diagnostics.
- Provide a safe local test workflow that keeps prototype credentials away from important accounts.
- Keep architecture modular enough that later hardening, storage improvements, and conformance testing can happen without rewriting the whole stack.

## 3. Non-Goals

- Credential theft.
- Covert keyboard injection or Rubber Ducky-style HID behavior.
- Phishing tools or fake relying-party flows.
- Bypassing authentication on any service or device.
- Production-grade protection for real personal, business, financial, cloud, or developer accounts.
- FIDO certification or claims of conformance.
- Enterprise attestation.
- Biometrics.
- PIN, user verification, or passkey account-selection UX in the first version.
- NFC or BLE transports in the first version.
- CTAP1/U2F backward compatibility in the first version.
- Advanced passkey sync, cloud backup, or multi-device credential features.
- Secure-element-backed private-key storage in the MVP.
- ESP-IDF project files, PlatformIO configuration, or non-Arduino build systems in the first implementation.

## 4. Background: WebAuthn, CTAP2, and USB HID

WebAuthn is the browser-facing W3C API for public-key credentials. CTAP is the client-to-authenticator protocol defined by the FIDO Alliance. In a typical roaming-authenticator flow, the browser and operating system act as the client/platform, the website is the relying party, and the USB key is the authenticator. CTAP2 messages are encoded with canonical CBOR, and CTAP2 authenticators are FIDO2/WebAuthn authenticators according to the CTAP specification.

During registration, the relying party asks the browser to create a public-key credential. The browser sends a CTAP2 `authenticatorMakeCredential` request to the authenticator. The authenticator validates supported options, asks for user presence, creates a new asymmetric key pair scoped to the relying party ID, stores the credential source, and returns attested credential data containing the public key and credential ID.

During authentication, the relying party asks the browser for an assertion. The browser sends CTAP2 `authenticatorGetAssertion` with the relying party ID, client data hash, and an allow list for non-resident credentials. The authenticator locates the matching credential, asks for user presence, increments or updates signature counter state, signs authenticator data plus the client data hash, and returns the signature.

For USB transport, this prototype should implement the FIDO CTAP HID framing described by the CTAP specification. USB HID packets carry CTAPHID initialization packets and continuation packets. `CTAPHID_INIT` allocates a channel ID. `CTAPHID_CBOR` carries CTAP2 command bytes and CBOR payloads. `CTAPHID_ERROR` reports malformed transport state. `CTAPHID_KEEPALIVE` is sent while the authenticator is processing or waiting for user presence.

User presence and user verification are different. User presence means the user intentionally touched or pressed the authenticator. User verification means the authenticator verified a local factor such as PIN, biometric, or equivalent. This MVP supports user presence only and must report that truthfully in `authenticatorGetInfo` and authenticator data flags.

## 5. Hardware Requirements

Recommended MVP hardware:

- Waveshare ESP32-S3-Touch-AMOLED-1.8 development board, or Waveshare ESP32-S3-Touch-LCD-1.47 with the `fido-lab-147` profile.
- USB-C data cable connected to the board's ESP32-S3 native USB interface.
- BOOT button as the required physical user-presence input.
- Board display as a visible consent/status surface.
- Optional external LED if an enclosure hides the screen or button.
- Optional enclosure that leaves BOOT accessible and does not encourage accidental activation.
- Optional secure element for a future version only, not MVP.

Board-specific facts to carry into firmware design:

- MCU: ESP32-S3R8, dual-core Xtensa LX7 up to 240 MHz.
- Memory: 8 MB PSRAM, 16 MB NOR flash.
- Display:
  - Touch-AMOLED-1.8: 1.8 inch AMOLED, 368 x 448, QSPI SH8601 panel.
  - Touch-LCD-1.47: 1.47 inch LCD, 172 x 320, SPI ST7789-compatible panel.
- Touch: FT3168 or FT6146 depending on batch/SKU for the AMOLED board; I2C touch controller on the 1.47 board. Do not use touch as the MVP approval input without board-specific false-activation testing.
- Buttons: BOOT is readable as GPIO0 when the application is running; pressed state is low. PWR is mediated through the board's power-management/IO-expander path and long holds can power off the board.
- USB: USB-C is the ESP32-S3 USB interface for flashing and logs. Espressif documents ESP32-S3 USB D+ and D- on GPIO20 and GPIO19.
- Storage: onboard 16 MB flash is enough for firmware plus a small credential database; TF card must not store private keys in the MVP.
- Peripherals: RTC, IMU, microphone, speaker, battery connector, and TF slot are useful for future demos but are not required for CTAP2.

GPIO and board-integration considerations:

- Do not repurpose GPIO19/GPIO20; they are the native USB data lines.
- BOOT/GPIO0 can be used for user presence after boot, but firmware must avoid getting stuck in download mode after crashes or resets.
- Avoid relying on PWR for required user presence because long press behavior can power off the board.
- Keep display refresh incremental and board-aware. Earlier work on this board family showed full-screen redraws can produce visible flicker; the 1.47 LCD profile also needs compact text and tighter spacing.
- Treat touch as optional confirmation only after testing false-positive behavior; a physical button is clearer for a security ceremony.
- If using battery power while connected to USB as a self-powered device, account for VBUS monitoring requirements.

## 6. Firmware Architecture

The firmware should be modular from the first prototype:

```text
USB host/browser
    |
    | USB HID reports
    v
+--------------------------+
| USB HID transport layer  |  TinyUSB descriptors, endpoints, 64-byte reports
+--------------------------+
| CTAPHID framing layer    |  channels, INIT, PING, CBOR, CANCEL, errors
+--------------------------+
| CTAP2 dispatcher         |  getInfo, makeCredential, getAssertion, reset
+--------------------------+
| CBOR codec               |  canonical CBOR parse/encode for CTAP2 maps
+--------------------------+
| WebAuthn data model      |  rpIdHash, user handle, credential ID, flags
+--------------------------+
| Crypto module            |  SHA-256, P-256 keygen, ES256 signatures, RNG
+--------------------------+
| Credential storage       |  NVS records, counters, lifecycle, wipe
+--------------------------+
| User presence and UX     |  BOOT press, timeout, display status, LED state
+--------------------------+
| Lifecycle/debug          |  reset, diagnostics, guarded logs, safe builds
+--------------------------+
```

Module responsibilities:

- Arduino build/profile layer: pin the ESP32 Arduino core and required libraries in `sketch.yaml`; provide Arduino CLI compile/upload commands for every profile.
- USB HID transport layer: use the ESP32 Arduino core native USB/HID APIs, or a narrowly vendored Arduino-compatible TinyUSB/custom-HID shim if the stock API cannot expose the FIDO HID descriptor and IN/OUT reports. Avoid composite keyboard behavior.
- CTAPHID packet/framing layer: parse initialization and continuation packets, enforce sequence numbers, enforce message length, handle channel busy state, and emit CTAPHID error codes.
- CTAP2 command dispatcher: dispatch CTAP2 command byte and CBOR payload to supported command handlers; reject unsupported commands with correct CTAP status.
- CBOR encoder/decoder: implement or adopt a small deterministic CBOR library with map/array/string/integer bounds checks.
- WebAuthn data model: construct authenticator data, attested credential data, COSE keys, signatures, and status flags.
- Crypto module: wrap Arduino-accessible mbedTLS/ESP32 core APIs for SHA-256, ECDSA P-256, key generation, DRBG, zeroization, and error mapping.
- Credential storage module: store and load credential records, counters, wrapping metadata, schema version, and reset state.
- User presence module: debounce BOOT, manage timeout/cancel, and publish state to CTAP keepalive and board UI.
- Device lifecycle/reset module: handle first boot, device UUID/AAGUID placeholder, reset ceremony, and factory wipe.
- Logging/debug module: keep secret-free logs; compile out verbose USB/crypto/credential logging in hardened builds.

Arduino CLI is the required stack. The first implementation should use an `.ino` entrypoint plus C++ modules under the sketch folder, with `arduino-cli compile --profile <name>` as the normal build command. The ESP32 Arduino USB API supports ESP32-S2/ESP32-S3 native USB device functionality, and the implementation must validate whether the stock `USBHID`/vendor HID path can expose the FIDO HID usage page, two endpoints, and 64-byte reports. If not, the acceptable fallback is a small Arduino-compatible custom HID layer or vendored TinyUSB adaptation inside the Arduino sketch/libraries path, still built only through Arduino CLI.

Because the Waveshare board's USB-C port is also used for flashing/logs, CDC serial logging can conflict with realistic FIDO HID testing. CDC may be acceptable in an early `debug-cdc` profile, but the MVP compatibility profile should be HID-only. Do not expose a USB keyboard, mouse, gamepad, mass-storage, or serial interface in the FIDO test profile unless a specific test requires it.

Recommended repo shape for implementation:

```text
esp32-key/
  esp32-key.ino
  sketch.yaml
  src/
    UsbFidoHid.*
    CtapHid.*
    Ctap2.*
    CborCodec.*
    WebAuthnModel.*
    CryptoProvider.*
    CredentialStore.*
    UserPresence.*
    AmoledUx.*
    Diagnostics.*
  libraries/            # only if a Waveshare/offline Arduino library must be vendored
  docs/
```

Expected command shape:

```sh
arduino-cli core update-index
arduino-cli compile --profile fido-lab /Users/cypher/Documents/GitHub/esp32-key
arduino-cli upload --profile fido-lab -p /dev/cu.usbmodemXXXX /Users/cypher/Documents/GitHub/esp32-key
arduino-cli compile --profile fido-lab-147 /Users/cypher/Documents/GitHub/esp32-key
arduino-cli upload --profile fido-lab-147 -p /dev/cu.usbmodemXXXX /Users/cypher/Documents/GitHub/esp32-key
```

## 7. MVP Protocol Scope

Smallest realistic MVP:

- USB HID device descriptor suitable for FIDO transport.
- 64-byte HID reports.
- One HID IN endpoint and one HID OUT endpoint for FIDO traffic.
- CTAPHID channel initialization and message reassembly.
- CTAP2 CBOR command handling for `authenticatorGetInfo`, `authenticatorMakeCredential`, `authenticatorGetAssertion`, and guarded `authenticatorReset`.
- ES256 credential creation and assertion signatures.
- Non-resident credentials using allow-list lookup.
- Button-based user presence.
- Safe reset/wipe flow.

Required or likely required CTAPHID support:

| Command | MVP decision | Notes |
| --- | --- | --- |
| `CTAPHID_INIT` | Required | Browser/platform discovery and channel allocation. Return nonce, channel ID, protocol version, device version, and capabilities. |
| `CTAPHID_PING` | Required | Echo payload for transport tests and simple host diagnostics. |
| `CTAPHID_CBOR` | Required | Carries CTAP2 commands and CBOR payloads. Set capability flag for CBOR. |
| `CTAPHID_CANCEL` | Required | Cancel active operation, especially while waiting for user presence. |
| `CTAPHID_ERROR` | Required response | Report invalid command, bad sequence, bad length, timeout, channel busy, and other transport failures. |
| `CTAPHID_KEEPALIVE` | Required in practice | Send while processing and while waiting for BOOT press. Use user-presence-needed status where appropriate. |
| `CTAPHID_WINK` | Optional | Nice for display/LED identification later. Defer unless browser testing needs it. |
| `CTAPHID_LOCK` | Deferred | Not needed for single-user lab MVP. |
| `CTAPHID_MSG` | Deferred | CTAP1/U2F/APDU compatibility is out of scope. |

Required or likely required CTAP2 support:

| CTAP2 command | MVP decision | Notes |
| --- | --- | --- |
| `authenticatorGetInfo` | Required | Advertise versions, extensions/options, transports, algorithms, max message size, and user-presence-only limits. |
| `authenticatorMakeCredential` | Required | Parse clientDataHash, RP, user, pubKeyCredParams, excludeList, options, and extensions enough to reject unsupported features cleanly. |
| `authenticatorGetAssertion` | Required | Support non-resident allow-list lookup, discoverable credentials, user presence, authenticator data, ES256 signature, and resident-user privacy when UV is false. |
| `authenticatorReset` | Required but guarded | Require strong physical confirmation and clear display warning; erase credentials, lab PIN state, and rotate the stateless master secret. |
| `authenticatorClientPIN` | Lab implemented | Host-entered PIN protocol 2 for UV-required lab flows; no device-side PIN entry and no hardened PIN storage. |
| Credential management | Lab implemented | Minimal resident-credential enumeration, delete, and user-info update coverage for lab management. |
| Selection, bio enrollment, large blobs | Deferred | Not needed for MVP. |

Defer these features:

- Browser validation of host PIN and UV-required flows across Chrome, Firefox, and Safari.
- Hardened PIN storage, local biometrics, and production user-verification claims.
- Large blobs and blob-key storage.
- `hmac-secret`.
- Enterprise attestation.
- Bio enrollment.
- NFC and BLE transports.
- CTAP1/U2F backwards compatibility.
- Multi-account account-selection UI.

Important MVP behavior rules:

- If an option is unsupported, reject it clearly rather than pretending support.
- If `uv` is required by a relying party, return an appropriate unsupported/user-verification error.
- If no matching credential is found in the allow list, return no-credential rather than leaking record details.
- If user presence times out or is canceled, return a user-action timeout/cancel path, not a generic crash.
- Do not sign until user presence is confirmed for that operation.

## 8. Cryptography Design

Preferred MVP algorithm: ES256, which is ECDSA over the NIST P-256 curve with SHA-256. ES256 is the safest compatibility target because it is widely expected by WebAuthn relying parties and appears throughout WebAuthn examples and COSE algorithm usage.

Required crypto operations:

- SHA-256 over relying party IDs to produce `rpIdHash`.
- SHA-256 over browser-provided `clientDataJSON`, already passed to CTAP2 as `clientDataHash`.
- P-256 key generation for each credential.
- ECDSA P-256 signature over `authenticatorData || clientDataHash`.
- COSE_Key encoding of the P-256 public key with x and y coordinates.
- Secure random generation for credential IDs, private keys, device nonce values, and optional attestation key material.
- Constant-time or library-managed private-key operations where available.

ESP32-S3 feasibility:

- The ESP32 Arduino core includes Arduino-accessible ESP32 and mbedTLS functionality because it is built on Espressif's lower-level SDK stack. The implementation must confirm the exact Arduino-core version exposes the needed mbedTLS headers/configuration for elliptic-curve cryptography, ECDSA, SHA-256, and DRBG.
- P-256 ECDSA is realistic on ESP32-S3 for low-frequency WebAuthn operations. Registration and login latency should be acceptable for lab use.
- Hardware acceleration may improve SHA, MPI, or ECC depending on Arduino ESP32 core version and its bundled SDK configuration. Do not depend on acceleration for correctness.
- RNG requires care. Espressif documents true random output only when an entropy source is active, such as Wi-Fi/Bluetooth RF, bootloader entropy, or temporarily enabled internal entropy. For a FIDO authenticator, key generation must seed a DRBG from true hardware entropy, not from pseudo-random output after boot.

Recommended MVP crypto module:

- Use Arduino-accessible mbedTLS for ECDSA P-256, SHA-256, and DRBG.
- During startup or before credential key generation, enable a documented entropy source and seed CTR-DRBG or HMAC-DRBG.
- Use `esp_fill_random()` only when true-entropy prerequisites are met, then feed a DRBG for keygen and credential IDs.
- Generate one unique P-256 credential key pair per relying-party user credential.
- Encode signatures in the format expected by CTAP/WebAuthn for the selected command response.
- Zeroize private-key buffers, DRBG seed material, and temporary big-number state after use.

Attestation recommendation:

- MVP should use test-only self attestation or no meaningful attestation, depending on browser compatibility during testing.
- Do not claim hardware-backed attestation.
- Use a lab AAGUID, clearly documented as experimental.
- Do not ship or publish reusable attestation private keys.
- If a packed self-attestation format is used, make the spec clear that it is for local compatibility testing only.

Library comparison:

| Option | Use | Pros | Cons |
| --- | --- | --- | --- |
| Arduino ESP32 core + mbedTLS | Recommended MVP | Arduino CLI compatible, built on Espressif's SDK stack, can expose mbedTLS and native USB on ESP32-S3. | Need to verify custom FIDO HID descriptor support and exact bundled mbedTLS config. |
| Arduino-compatible TinyUSB/custom HID shim | Conditional fallback | Can provide lower-level descriptor/report control while staying Arduino CLI only. | More maintenance risk; must avoid turning into an ESP-IDF project. |
| ESP32 low-level crypto/peripheral APIs through Arduino core | Supporting role | Useful for RNG, SHA acceleration, secure boot, flash/NVS encryption where exposed. | Availability varies by core version; not a complete WebAuthn abstraction by itself. |
| OpenSK crypto design | Reference only | Mature open-source authenticator architecture ideas. | Rust/Nordic-oriented; do not copy blindly. |
| SoloKeys firmware | Reference only | Real FIDO2/U2F firmware design lessons. | Different MCU/security model; not a drop-in ESP32-S3 solution. |
| External secure element | Future | Better private-key isolation if chosen carefully. | Adds cost, drivers, key model, and supply-chain complexity. |

Key crypto risks:

- Poor entropy creates predictable credential private keys.
- Reusing one private key across relying parties destroys WebAuthn privacy.
- Bad COSE encoding breaks browser compatibility.
- Incorrect signature input breaks authentication.
- Logging private keys, credential IDs with private metadata, or raw client data can leak lab credentials.
- Flash readout can expose private keys unless storage hardening is enabled.

## 9. Credential Storage Design

Recommended MVP storage model: local non-resident credentials in ESP32-S3 flash/NVS, referenced by random credential IDs.

Credential record format:

| Field | Type | Purpose |
| --- | --- | --- |
| `schema_version` | uint16 | Allows future migration. |
| `credential_id` | 32 random bytes minimum | Public opaque handle returned to relying party and used for lookup. |
| `rp_id` | UTF-8 string | Relying party ID, such as `example.com`. |
| `rp_id_hash` | 32 bytes | SHA-256 of RP ID; stored to avoid recomputing and for exact matching. |
| `user_handle` | byte string | User handle from makeCredential. |
| `user_name` | optional string | Display-only hint for board UI; do not rely on it for security. Do not return it in assertions unless UV/PIN completed. |
| `display_name` | optional string | Display-only hint for consent screens. Do not return it in assertions unless UV/PIN completed. |
| `private_key` | P-256 scalar or wrapped blob | Credential private key. |
| `public_key` | P-256 x/y or COSE_Key | Optional cached public key for diagnostics/reconstruction. |
| `sign_count` | uint32 or uint64 | Signature counter. |
| `created_at` | optional RTC timestamp | Lab diagnostics only; RTC may not be trustworthy. |
| `flags` | bitfield | Backup eligibility/state false, resident false, UV false. |

Credential ID strategy:

- MVP: generate a random 32-byte credential ID and store it as a reference into local NVS.
- Do not encode private key material into the credential ID for MVP.
- Do not put RP/user names into credential IDs.
- Use allow-list credential IDs in `getAssertion` to find the local record.

Storage limits:

- Reserve a dedicated NVS namespace such as `fido_creds`.
- Cap records to a small fixed number at first, such as 16 or 32 credentials, to simplify wear and UI.
- Keep each record bounded. Reject oversized user fields from CTAP2 requests.
- Track storage-full errors explicitly and show a clear display error.

NVS and flash layout:

- MVP lab build may use plain NVS to simplify bring-up, but must label private keys as extractable from flash.
- Hardened lab build should enable flash encryption and NVS encryption.
- NVS encryption requires an NVS key partition; Espressif's underlying storage model stores NVS encryption keys in a partition protected by flash encryption. In Arduino CLI, this needs explicit verification against the selected ESP32 Arduino core, partition scheme, and upload workflow.
- A future more-secure model can store an encrypted credential database in a dedicated encrypted data partition and use a device-unique wrapping key protected by ESP32-S3 eFuses or a secure element.
- TF card must not store private keys. It may hold redacted lab logs, proof notes, and boot/error breadcrumbs only if those artifacts are secret-free and expose no PINs, PIN/UV tokens, client data hashes, signatures, raw credential IDs, usernames, display names, master secrets, or credential export data.

Wipe/reset behavior:

- `authenticatorReset` must require physical confirmation, not just a USB command.
- Reset ceremony: display full-screen warning, require BOOT hold for a fixed duration, optionally require a second press after a countdown.
- Wipe all credential records, counters, schema metadata, and cached UI names.
- After wipe, reboot or reinitialize USB state cleanly.
- Provide a lab-only serial/build option to erase credentials during development, but compile it out of hardened builds.

More secure later model:

- Enable secure boot and flash encryption before loading real test credentials.
- Enable NVS encryption or use a dedicated encrypted partition.
- Consider a secure element for credential private keys or key wrapping.
- Disable debug interfaces and secret-bearing logs.
- Add authenticated firmware updates.
- Add credential database integrity checks and anti-rollback metadata.

## 10. User Presence and UX

The authenticator must be understandable while remaining small. The board display should make consent visible. The BOOT button should be the required user-presence action.

User-presence behavior:

- On `makeCredential`, display RP ID, action `REGISTER`, and a countdown.
- On `getAssertion`, display RP ID, action `LOGIN`, and a countdown.
- Require a short BOOT press after the prompt appears.
- Debounce BOOT and ignore presses that began before the prompt.
- Timeout after a bounded period such as 15-30 seconds.
- If `CTAPHID_CANCEL` arrives while waiting, stop waiting and show canceled status.
- Never accept touch-only confirmation for MVP unless hardware testing proves it is reliable and intentional.

LED/display states:

| State | Display | Optional LED |
| --- | --- | --- |
| Idle | Device name, lock icon, credential count, USB state | Dim blue/white pulse |
| USB connected | Small USB/FIDO status | Solid blue |
| Registration pending | `REGISTER`, RP ID, `Press BOOT` | Yellow blink |
| Login pending | `LOGIN`, RP ID, `Press BOOT` | Green blink |
| Processing | Spinner or progress strip | Fast white pulse |
| Success | `Approved` for under 1 second | Green flash |
| Cancel/timeout | `Canceled` or `Timed out` | Amber flash |
| Error | Short error code and safe label | Red flash |
| Reset pending | Full-screen warning and countdown | Red blink |

Example flows:

Registration request:

1. Browser sends `authenticatorMakeCredential`.
2. Firmware validates parameters and unsupported options.
3. Display shows `REGISTER` and RP ID.
4. Firmware sends keepalive status while waiting.
5. User presses BOOT.
6. Firmware creates key pair, stores credential, returns attestation object.
7. Display briefly shows success, then idle.

Login request:

1. Browser sends `authenticatorGetAssertion`.
2. Firmware finds matching allow-list credential.
3. Display shows `LOGIN` and RP ID.
4. User presses BOOT.
5. Firmware signs authenticator data plus client data hash.
6. Firmware returns assertion.

Reset request:

1. Browser/tool sends `authenticatorReset`.
2. Display shows destructive warning.
3. User must hold BOOT for a long duration, such as 5 seconds, within a countdown.
4. Firmware wipes credentials and counters.
5. Device reboots or reinitializes USB state.

Error state:

- Show short labels only: `Unsupported option`, `No credential`, `Storage full`, `Canceled`, `Bad request`, `Crypto error`.
- Do not show private keys, raw hashes, full credential IDs, or client data.

## 11. Security Model

This prototype protects only against a narrow threat: a passive remote relying party should receive a public key at registration and a signature at login, not the private key, assuming the firmware is honest, key generation is sound, storage is not physically extracted, and the host/browser follows WebAuthn semantics.

Assets:

- Credential private keys.
- Credential records and relying-party mappings.
- Signature counter state.
- Device identity/AAGUID metadata.
- Firmware integrity.
- User intent signal from BOOT.

Trust assumptions:

- The browser and operating system correctly enforce WebAuthn origin and RP ID rules.
- The user only tests with accounts they own.
- The firmware running on the board is the intended firmware.
- The board has not been physically modified or probed.
- Entropy is correctly configured before key generation.

Attacker capabilities to consider:

- Malicious USB host sending malformed CTAP HID or CTAP2 CBOR.
- Physical attacker reading or modifying flash.
- Physical attacker probing debug interfaces.
- Malicious firmware flashed before hardening.
- Power loss during credential write.
- User confusion caused by poor UI.
- Relying parties requiring production-grade PIN/UV, unsupported extensions, or stricter conformance than this lab slice provides.

What ESP32-S3 can help with:

- Native USB device mode for HID transport.
- Hardware RNG when entropy prerequisites are met.
- Flash encryption for off-chip flash confidentiality.
- Secure Boot v2 for firmware authenticity after configured.
- eFuses to restrict debug and bootloader behavior.
- NVS encryption when flash encryption and key partition are configured.

What it cannot provide by itself:

- Certified FIDO security properties.
- Tamper-resistant private-key storage equivalent to secure elements.
- Protection from a compromised host that lies in its UI.
- Protection if the user approves the wrong RP because the UI is unclear.
- Strong phishing resistance if browser/platform origin checks are bypassed outside WebAuthn.
- Protection from firmware installed before secure boot is enabled.
- Protection from all side-channel, fault-injection, decapping, or invasive attacks.

Differences from real certified security keys:

- No FIDO certification.
- No audited secure firmware lifecycle.
- No secure element in MVP.
- No mature anti-tamper design.
- No enterprise attestation trust chain.
- Lab-only host PIN path, with no hardened PIN storage or built-in UV.
- No proven CTAP conformance.
- No production key-injection or manufacturing controls.

Blunt boundary: this device is for learning and local protocol exploration. Do not register it as a second factor for important email, bank, cloud, code-hosting, password-manager, identity-provider, or business accounts.

## 12. ESP32-S3 Hardening Plan

MVP lab hardening:

- Keep Wi-Fi/BLE disabled unless needed for entropy seeding tests; this is a USB authenticator, not a networked authenticator.
- Use dedicated Arduino CLI profiles in `sketch.yaml`: at minimum `debug-cdc`, `fido-lab`, `debug-cdc-147`, `fido-lab-147`, and later hardened/release variants if needed.
- Avoid CDC serial in realistic HID tests; USB CDC logging changes descriptors and may interfere with host behavior.
- Remove secret-bearing logs before using persistent test credentials.
- Bounds-check all HID, CTAPHID, CBOR, RP, user, and credential-ID inputs.
- Use watchdog-safe user-presence waits.
- Zeroize private-key temporary buffers.
- Implement credential wipe before experimenting with storage format changes.
- Document that flash is extractable until flash/NVS encryption is enabled.

Later hardening:

- Enable Secure Boot v2 so only signed firmware boots.
- Enable flash encryption only after the Arduino CLI build/upload/recovery path is documented for this board. Espressif stores flash encryption keys in protected eFuses and recommends using secure boot with flash encryption.
- Enable NVS encryption with an NVS key partition protected by flash encryption.
- Burn/restrict eFuses to disable or restrict JTAG/USB-JTAG and unsafe download behavior when moving beyond lab bring-up.
- Use release build profile with debug logs disabled, assertions reviewed, and no test reset bypass.
- Add signed OTA or signed USB update flow, or intentionally require full physical reflash with documented wipe.
- Add firmware versioning and anti-rollback if updates become a real feature.
- Add deterministic build notes and dependency pinning.
- Consider a secure element for private-key generation and signing.

Arduino CLI build profiles:

| Profile | Purpose | Security posture |
| --- | --- | --- |
| `debug-cdc` | Early USB and CTAP debugging | CDC logs allowed, no real credentials; compiled with `arduino-cli compile --profile debug-cdc`. |
| `fido-lab` | Browser registration/login tests | HID-only, secret-free logs, plain or encrypted NVS depending on phase; primary MVP profile. |
| `debug-cdc-147` | Touch-LCD-1.47 early USB and CTAP debugging | CDC logs allowed, no real credentials; compiled with `arduino-cli compile --profile debug-cdc-147`. |
| `fido-lab-147` | Touch-LCD-1.47 browser registration/login tests | HID-only, secret-free logs, compact ST7789-compatible UI, BOOT/GPIO0 user presence. |
| `hardened-lab` | Serious local testing | Secure boot, flash encryption, NVS encryption, debug restricted where Arduino tooling supports it. |
| `release` | Not recommended for public claims | Would require audit, conformance, manufacturing controls, and certification work. |

## 13. Compatibility Plan

Likely test targets:

- Chrome/Chromium on macOS, Linux, and Windows.
- Firefox on macOS, Linux, and Windows.
- Safari on macOS, if available and practical.
- WebAuthn.io or equivalent demo relying parties.
- A local relying-party test server using a known WebAuthn library.
- USB enumeration tools: macOS System Information and `ioreg`, Linux `lsusb`/`hid-recorder`, Windows Device Manager/USBTreeView.
- CTAP test tooling such as `python-fido2` scripts for low-level commands.

Browser/platform compatibility risk table:

| Risk | Impact | Mitigation |
| --- | --- | --- |
| HID descriptor does not match FIDO expectations | Browser never discovers device | Compare against CTAP HID descriptor requirements and known TinyUSB examples; test enumeration before CTAP2. |
| Generic ESP32-S3 USB identity differs from the working Waveshare board profile | iOS or a demo relying party prompt fails before CTAP traffic reaches the authenticator | For the `fido-lab-147` profile, pin TinyUSB VID/PID to the working Waveshare AMOLED lab identity while preserving FIDO-only HID reports and interfaces. |
| Composite CDC + HID confuses tests | Browser ignores device or logs change timing | Use HID-only profile for compatibility testing. |
| Arduino USB API lacks enough custom HID control | FIDO HID descriptor/report shape may be blocked | First prototype task must prove custom usage page, usage, reports, and endpoints under Arduino CLI; use a small Arduino-compatible custom HID shim if required. |
| Missing/incorrect `authenticatorGetInfo` fields | Browser rejects authenticator | Start with minimal truthful values and add only tested options. |
| Relying party requires UV/PIN/resident credentials | Registration/login fails | Test with user-presence-only relying parties first; reject unsupported options accurately. |
| Attestation format not accepted | Registration fails | Prefer none/self/test attestation and test several demo RPs. |
| CBOR canonical encoding errors | Commands fail inconsistently | Unit-test encoded maps against known-good decoders. |
| Signature encoding mismatch | Assertion verification fails | Verify signatures with local server and `python-fido2`. |
| Counter behavior rejected | Relying party flags cloned key | Use monotonic per-credential or global counter and document limitations. |
| macOS/Windows/Linux differ in HID timing | Works on one platform only | Test all three early, especially cancel/keepalive/user-presence waits. |
| Safari behavior differs | Partial WebAuthn support path | Treat Safari as compatibility target after Chrome/Firefox pass. |

## 14. Testing Strategy

Unit tests:

- CBOR positive parse/encode tests for all MVP request and response maps.
- CBOR negative tests for oversized maps, duplicate keys, wrong integer ranges, indefinite lengths if unsupported, invalid UTF-8, and malformed byte strings.
- CTAPHID framing tests for initialization packets, continuation packets, sequence mismatch, timeout, channel busy, invalid length, and cancel.
- Crypto known-answer tests for SHA-256, P-256 public-key encoding, and ECDSA signature verification.
- Credential storage tests for create, lookup, counter update, delete, storage full, power-loss simulation, and schema mismatch.
- User-presence state-machine tests for press-before-prompt, debounce, timeout, cancel, and reset hold.

Integration tests:

- USB enumeration as a FIDO HID interface.
- `CTAPHID_INIT` and `CTAPHID_PING` host scripts.
- `authenticatorGetInfo` parsed by `python-fido2`.
- Browser registration on a demo relying party.
- Browser login on the same relying party.
- Local relying-party server verifies assertion signature and counter behavior.
- Reset/wipe removes credentials and blocks old assertions.

Fuzzing and robustness:

- Fuzz CBOR payloads at CTAP2 command boundary.
- Fuzz CTAPHID continuation sequences and lengths.
- Fuzz unsupported options and extensions.
- Test rapid connect/disconnect.
- Test cancel during user-presence wait.
- Test repeated malformed packets without rebooting.

Definition of done for MVP:

- Device enumerates as FIDO HID on at least one desktop OS.
- `CTAPHID_INIT`, `PING`, `CBOR`, `CANCEL`, `ERROR`, and keepalive behavior work under host-script tests.
- `authenticatorGetInfo` returns truthful MVP capabilities.
- Device can register an ES256 non-resident credential with at least one test relying party.
- Device can sign in with that credential after BOOT confirmation.
- Chrome/WebAuthn.io registration and sign-in pass for both non-discoverable credentials and discoverable/resident credentials with ES256, security-key hints, and UV discouraged for registration/authentication.
- Reset requires physical confirmation and wipes credentials.
- Unsupported extension and production-grade UV requests fail cleanly; lab PIN and resident flows are probe-covered.
- No secret-bearing logs are present in the `fido-lab` profile.
- Documentation clearly says compile-ready, flashed, and field-proven states are separate proof levels.

## 15. Development Plan

### Phase 1: Research validation and source map

Deliverables:

- Confirm CTAP/WebAuthn requirements from primary specs.
- Confirm board USB/display/button/storage facts from Waveshare, Arduino ESP32, Arduino CLI, and Espressif silicon/security docs.
- Decide exact Arduino CLI version, ESP32 Arduino core version, FQBN, partition scheme, and required Waveshare/Arduino libraries.

Acceptance criteria:

- Source map is current.
- MVP feature list is frozen.
- Unsupported features are listed with planned CTAP errors.

Main risks:

- CTAP2 option handling is more compatibility-sensitive than expected.
- Board USB debug mode conflicts with HID testing.

### Phase 2: USB HID enumeration prototype

Deliverables:

- Arduino CLI sketch with `sketch.yaml` profiles that exposes one FIDO HID interface.
- Proof that the ESP32 Arduino core USBHID path, or a vendored Arduino-compatible custom HID shim, can expose FIDO usage/report descriptors.
- FIDO usage page/usage and report descriptors.
- Host enumeration notes for macOS/Linux/Windows.

Acceptance criteria:

- Host sees a HID device with expected FIDO usage.
- No keyboard/mouse interface is exposed.
- HID-only profile works without CDC.

Main risks:

- Descriptor mismatch.
- USB-Serial-JTAG/OTG PHY conflict during debugging.

### Phase 3: CTAPHID framing

Deliverables:

- CTAPHID parser/serializer.
- Channel state table.
- INIT, PING, ERROR, CANCEL, and keepalive plumbing.

Acceptance criteria:

- Host script can initialize a channel and ping arbitrary payloads.
- Malformed sequence/length/channel cases return correct errors.

Main risks:

- Race conditions between channels.
- Incorrect timeout behavior under browser retries.

### Phase 4: CTAP2 getInfo

Deliverables:

- CTAP2 command dispatch shell.
- `authenticatorGetInfo` response.
- Minimal device metadata and lab AAGUID.

Acceptance criteria:

- `python-fido2` or equivalent can parse `getInfo`.
- Reported options match actual behavior.

Main risks:

- Advertising too many features causes browser requests the firmware cannot satisfy.

### Phase 5: CBOR command parsing

Deliverables:

- Bounded CBOR decoder/encoder integration.
- Request structs for makeCredential and getAssertion.
- Strict unsupported-option handling.

Acceptance criteria:

- Known-good CBOR fixtures parse.
- Malformed CBOR returns deterministic CTAP errors.

Main risks:

- Memory fragmentation or oversized allocations.
- Non-canonical CBOR edge cases.

### Phase 6: makeCredential with test keys

Deliverables:

- ES256 key generation.
- Attested credential data builder.
- Self/none test attestation response.

Acceptance criteria:

- Local decoder validates returned credential public key.
- Demo relying party reaches successful registration or a clearly diagnosed attestation limitation.

Main risks:

- RNG setup wrong after boot.
- COSE_Key or attestation object encoding mismatch.

### Phase 7: getAssertion signing flow

Deliverables:

- Credential lookup by allow-list credential ID.
- Authenticator data builder.
- ES256 signature generation.
- Counter update.

Acceptance criteria:

- Local relying-party server verifies signature.
- Browser login succeeds with a registered test credential.

Main risks:

- Signature format mismatch.
- Counter persistence bugs.

### Phase 8: Credential storage

Deliverables:

- NVS credential schema.
- Storage-full behavior.
- Reset/wipe.

Acceptance criteria:

- Credentials survive reboot.
- Wipe removes all credential records.
- Power-loss simulation does not corrupt unrelated records.

Main risks:

- Private keys extractable in lab mode.
- NVS wear or schema migration mistakes.

### Phase 9: Button-based user presence

Deliverables:

- BOOT debounce and prompt state machine.
- Timeout/cancel handling.
- Board display prompt screens, with compact layout for the 1.47 LCD profile.

Acceptance criteria:

- Pre-presses do not approve operations.
- Cancel during wait returns cleanly.
- Display never shows secrets.

Main risks:

- BOOT behavior interferes with boot/download mode.
- Touch/PWR accidental behavior if used too early.

### Phase 10: Browser compatibility testing

Deliverables:

- Chrome, Firefox, Safari where practical.
- macOS/Linux/Windows notes.
- Compatibility table with failures.

Acceptance criteria:

- Registration/login passes on at least one browser/OS.
- As of 2026-05-31, Chrome/WebAuthn.io passes for both non-discoverable and discoverable/resident flows.
- Failures on other targets are classified.

Main risks:

- Platform requires PIN/UV for chosen test flow.
- Attestation or getInfo values trigger unexpected platform policy.

### Phase 11: Security hardening pass

Deliverables:

- Secret-free logs.
- Hardened-lab sdkconfig.
- Secure boot/flash encryption/NVS encryption procedure.
- Debug restriction notes.

Acceptance criteria:

- Hardened lab device boots signed firmware.
- Credentials stored after hardening are not trivially readable from raw flash.

Main risks:

- Irreversible eFuse mistakes.
- Flash encryption complicates development and recovery.

### Phase 12: Documentation and demo

Deliverables:

- README with proof levels and safety warning.
- Demo script using owned test RP.
- Known limitations.

Acceptance criteria:

- A new developer can reproduce the demo.
- Docs do not imply production security.

Main risks:

- Overclaiming the security value of a working demo.

## 16. Bill of Materials

Estimated inexpensive MVP parts:

| Item | Purpose | Notes |
| --- | --- | --- |
| Waveshare ESP32-S3-Touch-AMOLED-1.8 | Primary board | Preferred target; includes display, touch, buttons, flash, PSRAM, USB-C. |
| Waveshare ESP32-S3-Touch-LCD-1.47 | Secondary board profile | Compact display target using `fido-lab-147`; keep BOOT accessible for user presence. |
| USB-C data cable | Host connection | Must support data, not charge-only. |
| Small enclosure | Physical handling | Should leave BOOT accessible and show display. |
| Optional external tactile button | User presence | Useful if BOOT is inconvenient in an enclosure. |
| Optional RGB LED | Status | Useful if display is off or hidden. |
| Optional TF card | Non-secret logs only | 1-bit SD_MMC on Waveshare AMOLED 1.8 (`CLK=GPIO2`, `CMD=GPIO1`, `D0=GPIO3`); do not store private keys or credential export data. |
| Optional secure element | Future hardening | Not required for MVP; adds driver and key-model work. |
| Optional NFC module | Future transport | Out of scope for first version. |

## 17. Open Questions

- Which exact Arduino CLI, ESP32 Arduino core, FQBN, and partition scheme should be pinned for the first firmware implementation?
- Can the stock Arduino ESP32 `USBHID`/vendor HID path express the exact FIDO HID descriptor, or is a small Arduino-compatible shim required?
- Which small CBOR library should be used, or should a tiny bounded CTAP-specific codec be written?
- Which attestation response is accepted by the chosen test relying parties with the least misleading security claim?
- Should the signature counter be global or per credential for MVP?
- How many credentials fit comfortably in encrypted NVS with bounded record sizes?
- Does the board's touch controller produce any false activations that make it unsuitable for security prompts?
- Can the PWR button be safely used for secondary confirmation without conflicting with power-off behavior?
- What exact keepalive cadence keeps Chrome/Firefox/Safari happy while waiting for BOOT?
- Which eFuse settings are acceptable for a lab board that may need recovery and reflashing?
- Is a secure element worth adding before any public demo, or should the project remain explicitly software-key-only?

## 18. Source Map

| Source title | URL | Used for | Reliability | Notes |
| --- | --- | --- | --- | --- |
| FIDO Alliance Client to Authenticator Protocol v2.2 Proposed Standard | https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html | CTAP2, CTAPHID commands, USB/NFC/BLE transports, CBOR framing, keepalive/cancel/error behavior | Primary | Use HTML as canonical reading source where PDF formatting differs. |
| W3C Web Authentication Level 3 | https://www.w3.org/TR/webauthn-3/ | WebAuthn roles, credential source model, registration/authentication ceremonies, public-key credential fields, ES256 examples | Primary | Published W3C spec; browser behavior can still vary. |
| Arduino CLI sketch project file | https://docs.arduino.cc/arduino-cli/sketch-project-file/ | `sketch.yaml`, reproducible build profiles, pinned boards/platforms/libraries | Primary | This is the build-system contract for the repo. |
| Arduino ESP32 USB API | https://docs.espressif.com/projects/arduino-esp32/en/latest/api/usb.html | ESP32-S2/S3 native USB device support through Arduino ESP32 core | Primary vendor | Implementation must verify custom FIDO HID support under the selected core version. |
| ESP-IDF USB Device Stack for ESP32-S3 | https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-reference/peripherals/usb_device.html | Underlying ESP32-S3 USB/TinyUSB silicon behavior, HID support, USB D+/D- GPIOs, CDC conflict considerations | Primary vendor | Reference only; do not create an ESP-IDF project. |
| ESP-IDF Random Number Generation for ESP32-S3 | https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-reference/system/random.html | Hardware RNG behavior, entropy-source prerequisites, `esp_random`, `esp_fill_random`, DRBG guidance | Primary vendor | Critical for key generation safety. |
| ESP-IDF mbedTLS guide | https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-reference/protocols/mbedtls.html | Underlying ECDSA/ECC/SHA-256 support, mbedTLS configuration, hardware acceleration categories | Primary vendor | Confirm Arduino ESP32 core exposes the needed pieces. |
| ESP-IDF Secure Boot v2 for ESP32-S3 | https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/security/secure-boot-v2.html | Secure boot plan, eFuse digest/revocation concepts, signed firmware lifecycle | Primary vendor | eFuse steps are irreversible; use only after lab validation. |
| ESP-IDF Flash Encryption for ESP32-S3 | https://docs.espressif.com/projects/esp-idf/en/release-v5.5/esp32s3/security/flash-encryption.html | Flash encryption, protected eFuse keys, limitations, JTAG/debug implications | Primary vendor | Coordinate with secure boot and recovery plan. |
| ESP-IDF NVS Flash/NVS Encryption | https://docs.espressif.com/projects/esp-idf/en/release-v4.4/esp32s3/api-reference/storage/nvs_flash.html | NVS encryption model, NVS key partition, flash encryption prerequisite | Primary vendor | Use version-matched docs during implementation. |
| Waveshare ESP32-S3-Touch-AMOLED-1.8 wiki | https://www.waveshare.com/wiki/ESP32-S3-Touch-AMOLED-1.8 | Board features, Arduino setup, ESP32 Arduino core >=3.0.6, BOOT/PWR behavior, display/touch libraries, flashing/debug notes | Primary vendor | Use to verify board-specific pins, libraries, and peripherals. |
| Waveshare ESP32-S3-Touch-AMOLED-1.8 product page | https://www.waveshare.com/product/arduino/displays/esp32-s3-touch-amoled-1.8.htm | Hardware summary: ESP32-S3R8, display, PSRAM, flash, peripherals, USB-C | Primary vendor | Product pages can lag revisions; verify physical board. |
| Waveshare ESP32-S3-Touch-LCD-1.47 wiki | https://www.waveshare.com/wiki/ESP32-S3-Touch-LCD-1.47 | Board features, Arduino setup, display/touch pins, BOOT behavior, flashing/debug notes | Primary vendor | Use to verify 1.47 board-specific pins, libraries, and peripherals. |
| Waveshare ESP32-S3-Touch-LCD-1.47 Arduino setup | https://docs.waveshare.com/ESP32-S3-Touch-LCD-1.47/Development-Environment-Setup-Arduino | Arduino development flow for the 1.47 board | Primary vendor | Keep aligned with the Arduino CLI profile instead of adding PlatformIO or ESP-IDF scaffolding. |
| Google OpenSK | https://github.com/google/OpenSK | Reference authenticator architecture and testing ideas | Reputable reference | Reference only; not a drop-in ESP32-S3 codebase. |
| SoloKeys Solo firmware | https://github.com/solokeys/solo | Reference FIDO2/U2F firmware architecture | Reputable reference | Reference only; different MCU and security model. |
| TinyUSB project | https://github.com/hathach/tinyusb | USB HID implementation reference and examples | Reputable open source | Reference only unless an Arduino-compatible shim is needed. |
| Yubico python-fido2 | https://github.com/Yubico/python-fido2 | Host-side CTAP/WebAuthn test tooling | Reputable open source | Useful for local scripts and assertion verification. |

## Recommended MVP and Top Risks

Recommended MVP:

- Build an Arduino CLI-only HID FIDO authenticator sketch for the supported Waveshare ESP32-S3 display-board profiles.
- Implement CTAPHID INIT/PING/CBOR/CANCEL/ERROR/KEEPALIVE.
- Implement CTAP2 getInfo, makeCredential, getAssertion, and physically guarded reset.
- Use ES256/P-256, SHA-256, and non-resident credentials stored in local NVS behind random credential IDs.
- Require BOOT button user presence and use the board display for clear, minimal consent prompts.
- Test only against owned local accounts and demo relying parties.

Top 5 technical risks:

1. RNG/key-generation mistakes could create predictable credential private keys.
2. CTAPHID/CBOR/getInfo details are strict enough that browsers may silently reject small incompatibilities.
3. Arduino ESP32's stock USBHID APIs may not expose enough custom HID descriptor control for FIDO without a small Arduino-compatible shim.
4. Local flash/NVS storage without secure boot, flash encryption, and NVS encryption is physically extractable.
5. The prototype can easily be overtrusted once browser login works; documentation and UX must keep the lab-only boundary visible.
