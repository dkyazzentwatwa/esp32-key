# Security Policy

This repository is an experimental learning project for an ESP32-S3 AMOLED FIDO/WebAuthn lab key. It is not a production security key.

Do not use this firmware to protect high-value accounts. Do not use it as your only authenticator. Do not use it for personal email, banking, business infrastructure, cloud consoles, source-code hosting, password managers, cryptocurrency, government services, or other important accounts.

## Security Status

Current security posture:

- Lab prototype only.
- Not FIDO certified.
- Not independently audited.
- No secure element.
- Host-entered CTAP PIN exists for lab testing, but there is no biometric verifier, secure element, or hardened PIN storage.
- No biometric verification.
- No hardened private-key storage.
- No production attestation.
- No guarantee of resistance to physical extraction, fault injection, firmware replacement, or malicious hosts.

Successful WebAuthn.io or host-probe flows prove functional interoperability for a test scenario only. They do not prove production security.

## Threat Model

This project currently assumes:

- The user controls the ESP32-S3 board.
- The user controls the host computer used for testing.
- Test accounts are disposable.
- Physical attackers are out of scope for protection.
- Firmware tampering is out of scope unless additional secure boot and flash encryption work is implemented and validated.
- Browser and operating-system USB stacks are trusted enough for lab testing.

This project does not currently defend against:

- Physical flash extraction.
- NVS credential record extraction.
- Debug, JTAG, UART, or bootloader abuse.
- Malicious reflashing.
- Supply-chain changes to local Arduino libraries or board packages.
- A compromised host computer.
- A malicious relying party.
- Side-channel attacks against ESP32-S3 crypto operations.
- Wear-leveling, rollback, or cloning attacks against flash-backed credential state.

## Private Keys And Credential Storage

Credential private keys are stored locally on the ESP32-S3 in flash-backed storage. The MVP does not use a secure element.

Consequences:

- Anyone with physical access and the right tooling may be able to extract or clone credential material.
- Flash/NVS contents should be treated as sensitive.
- Reset/wipe is a lab convenience, not a forensic erasure guarantee.
- Reflashing or debugging can change the trust state of the device.

Non-resident credentials use stateless key-wrapping: their private keys are not stored, but are re-derived from a single device master secret held in NVS (namespace `fido_ms`). That master secret is the crown jewel — anyone who extracts it can re-derive every non-resident credential key ever issued by the device, for every relying party. Without flash encryption the master secret is readable from NVS, so the same physical-extraction caveats as stored resident keys apply. Resetting the device rotates the master secret, which invalidates all outstanding stateless credential IDs.

Resident/discoverable credentials store RP and user display metadata for lab account-selection and credential-management flows. That metadata is not hardened against physical extraction. During UV-discouraged assertions, the firmware returns only the user handle and suppresses identifying strings such as `name` and `displayName`; it does not claim broader privacy protection outside this lab behavior.

Future hardening work would need to evaluate ESP32 secure boot, flash encryption, eFuse provisioning, debug disablement, NVS encryption, anti-rollback, and secure-element options. Those features are not claimed by this repository today.

## Attestation

Any attestation material in this project is for lab interoperability only.

Do not claim that this device has a trusted commercial attestation chain. Do not claim that relying parties can use this firmware to establish manufacturer-backed authenticator provenance.

## USB And Host Safety

The intended USB interface is FIDO HID only.

Do not add:

- Keyboard injection.
- Mouse injection.
- Gamepad behavior.
- Mass-storage payloads.
- Covert serial command channels for production profiles.
- Credential export commands.
- Host attack tooling.

The `debug-cdc` profile may be useful during bring-up, but browser compatibility testing should use the realistic FIDO lab profile and should not depend on serial logging.

## Safe Testing Rules

Allowed testing:

- Owned disposable accounts.
- WebAuthn.io or equivalent public demo relying parties.
- Local relying-party test apps.
- Direct host probes against the locally attached board.
- Browser enumeration and registration checks.

Not allowed:

- Phishing.
- Impersonation.
- Credential theft.
- Bypassing authentication on accounts or systems you do not own.
- Testing against another person's account.
- Presenting the device as a production security key.
- Publishing extracted private keys, real credentials, or account-specific authentication artifacts.

## Reporting Security Issues

For this local lab project, report issues with:

- A short description of the bug or security concern.
- The exact firmware commit or file state if available.
- Board model and Arduino core version.
- Reproduction steps using test accounts only.
- Host operating system and browser if the issue involves WebAuthn.
- Probe output with secrets removed.

Do not include:

- Real account credentials.
- Private keys.
- Valid authentication assertions for important accounts.
- Sensitive browser profile data.
- Dumps of flash/NVS from a device used with real accounts.

There is no bug bounty, certification program, warranty, or production support promise for this repository.

## Operator Checklist

Before each test:

- Confirm you are using a disposable account or local relying party.
- Confirm the browser prompt is for an action you started.
- Confirm the AMOLED prompt matches the expected action.
- Press BOOT only for requests you intentionally initiated.
- Wipe credentials before handing the board to another person.

After each test:

- Treat the board as containing secret material.
- Do not publish dumps, logs, or screenshots that expose account-specific data.
- Reflash only when you understand which profile is being uploaded.
