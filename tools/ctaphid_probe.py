#!/usr/bin/env python3
"""Small CTAPHID bring-up probe for the ESP32-S3 AMOLED FIDO lab key.

Requires the cython `hidapi` package, which imports as `hid`:

    python3 -m pip install hidapi cbor2 cryptography

This script only talks to a locally attached FIDO HID authenticator that exposes
the FIDO usage page. It sends CTAPHID_INIT, CTAPHID_PING, and CTAP2 getInfo.
"""

from __future__ import annotations

import argparse
import os
import secrets
import struct
import subprocess
import sys
import tempfile
import time
from typing import Iterable

try:
    import hid  # type: ignore
except ImportError:
    print("Missing hid package. Install with: python3 -m pip install hid", file=sys.stderr)
    raise SystemExit(2)


REPORT_SIZE = 64
FIDO_USAGE_PAGE = 0xF1D0
FIDO_USAGE = 0x01
BROADCAST_CID = 0xFFFFFFFF

CTAPHID_PING = 0x01
CTAPHID_MSG = 0x03
CTAPHID_INIT = 0x06
CTAPHID_CBOR = 0x10
CTAPHID_KEEPALIVE = 0x3B

CTAP2_MAKE_CREDENTIAL = 0x01
CTAP2_GET_ASSERTION = 0x02
CTAP2_GET_INFO = 0x04
CTAP2_CLIENT_PIN = 0x06
CTAP2_RESET = 0x07
CTAP2_GET_NEXT_ASSERTION = 0x08
CTAP2_CREDENTIAL_MANAGEMENT = 0x0A

PIN_PROTOCOL = 2
CP_GET_RETRIES = 0x01
CP_GET_KEY_AGREEMENT = 0x02
CP_SET_PIN = 0x03
CP_GET_TOKEN_LEGACY = 0x05
CP_GET_TOKEN_WITH_PERMISSIONS = 0x09
PIN_PERMISSION_MAKE_CREDENTIAL = 0x01
PIN_PERMISSION_GET_ASSERTION = 0x02

CM_GET_CREDS_METADATA = 0x01
CM_ENUM_RPS_BEGIN = 0x02
CM_ENUM_RPS_NEXT = 0x03
CM_ENUM_CREDS_BEGIN = 0x04
CM_ENUM_CREDS_NEXT = 0x05
CM_DELETE_CREDENTIAL = 0x06
CM_UPDATE_USER = 0x07

U2F_REGISTER = 0x01
U2F_VERSION = 0x03


def find_devices() -> list[dict]:
    return [
        d
        for d in hid.enumerate()
        if d.get("usage_page") == FIDO_USAGE_PAGE and d.get("usage") == FIDO_USAGE
    ]


def open_device(path: bytes | str | None):
    devices = find_devices()
    if path is None:
        if not devices:
            raise RuntimeError("No FIDO HID device found")
        path = devices[0]["path"]
    dev = hid.device()
    dev.open_path(path)
    dev.set_nonblocking(False)
    return dev


def write_report(dev, packet: bytes) -> None:
    if len(packet) != REPORT_SIZE:
        raise ValueError(f"expected {REPORT_SIZE} bytes, got {len(packet)}")
    # hidapi writes include report ID as the first byte. The firmware uses no
    # report ID, so prefix zero.
    written = dev.write(b"\x00" + packet)
    if written not in (REPORT_SIZE, REPORT_SIZE + 1):
        raise RuntimeError(f"short HID write: {written}")


def read_report(dev, timeout_ms: int = 3000) -> bytes:
    data = bytes(dev.read(REPORT_SIZE, timeout_ms=timeout_ms))
    if len(data) != REPORT_SIZE:
        raise RuntimeError(f"short HID read: {len(data)}")
    return data


def make_init_packet(cid: int, cmd: int, payload: bytes) -> bytes:
    if len(payload) > 57:
        raise ValueError("single-packet helper only accepts <=57-byte payloads")
    return (
        struct.pack(">IBH", cid, cmd | 0x80, len(payload))
        + payload
        + bytes(REPORT_SIZE - 7 - len(payload))
    )


def write_message(dev, cid: int, cmd: int, payload: bytes) -> None:
    if len(payload) > 7609:
        raise ValueError("payload is too large for CTAPHID")
    first_len = min(len(payload), 57)
    write_report(
        dev,
        struct.pack(">IBH", cid, cmd | 0x80, len(payload))
        + payload[:first_len]
        + bytes(REPORT_SIZE - 7 - first_len),
    )
    sent = first_len
    seq = 0
    while sent < len(payload):
        chunk = min(len(payload) - sent, 59)
        write_report(
            dev,
            struct.pack(">IB", cid, seq)
            + payload[sent : sent + chunk]
            + bytes(REPORT_SIZE - 5 - chunk),
        )
        sent += chunk
        seq += 1


def read_message(dev, timeout_ms: int = 3000) -> tuple[int, int, bytes]:
    first = read_report(dev, timeout_ms=timeout_ms)
    out_cid, out_cmd, total = struct.unpack(">IBH", first[:7])
    if not out_cmd & 0x80:
        raise RuntimeError("expected initialization response packet")
    body = bytearray(first[7 : 7 + min(total, 57)])
    seq = 0
    while len(body) < total:
        packet = read_report(dev, timeout_ms=timeout_ms)
        cont_cid = struct.unpack(">I", packet[:4])[0]
        if cont_cid != out_cid or packet[4] != seq:
            raise RuntimeError("bad continuation packet")
        body.extend(packet[5 : 5 + min(total - len(body), 59)])
        seq += 1
    return out_cid, out_cmd & 0x7F, bytes(body)


def send_single(dev, cid: int, cmd: int, payload: bytes, timeout_ms: int = 3000) -> tuple[int, int, bytes]:
    if len(payload) <= 57:
        write_report(dev, make_init_packet(cid, cmd, payload))
    else:
        write_message(dev, cid, cmd, payload)
    return read_message(dev, timeout_ms=timeout_ms)


def send_cbor_wait(dev, cid: int, payload: bytes, timeout_ms: int = 35000) -> tuple[int, bytes]:
    write_message(dev, cid, CTAPHID_CBOR, payload)
    while True:
        _, cmd, body = read_message(dev, timeout_ms=timeout_ms)
        if cmd == CTAPHID_KEEPALIVE:
            print(f"KEEPALIVE status=0x{body[0]:02x}; press BOOT now")
            continue
        return cmd, body


def send_msg_wait(dev, cid: int, payload: bytes, timeout_ms: int = 35000) -> tuple[int, bytes]:
    write_message(dev, cid, CTAPHID_MSG, payload)
    while True:
        _, cmd, body = read_message(dev, timeout_ms=timeout_ms)
        if cmd == CTAPHID_KEEPALIVE:
            print(f"KEEPALIVE status=0x{body[0]:02x}; press BOOT now")
            continue
        return cmd, body


def u2f_extended_apdu(ins: int, data: bytes = b"", le: bytes = b"\x00\x00") -> bytes:
    if len(data) > 65535:
        raise ValueError("U2F APDU data too large")
    return bytes([0x00, ins, 0x00, 0x00, 0x00]) + len(data).to_bytes(2, "big") + data + le


def der_object_len(data: bytes, offset: int = 0) -> int:
    if offset >= len(data) or data[offset] != 0x30:
        raise ValueError("expected DER sequence")
    first = data[offset + 1]
    if first < 0x80:
        return 2 + first
    count = first & 0x7F
    if count == 0 or count > 3:
        raise ValueError("unsupported DER length")
    length = int.from_bytes(data[offset + 2 : offset + 2 + count], "big")
    return 2 + count + length


def openssl_verify_u2f_register(body: bytes, challenge: bytes, app: bytes) -> bool:
    key_handle_len = body[66]
    key_handle = body[67 : 67 + key_handle_len]
    public_key = body[1:66]
    cert_offset = 67 + key_handle_len
    cert_len = der_object_len(body, cert_offset)
    cert = body[cert_offset : cert_offset + cert_len]
    signature = body[cert_offset + cert_len : -2]
    signed = b"\x00" + app + challenge + key_handle + public_key
    with tempfile.TemporaryDirectory() as tmp:
        cert_path = os.path.join(tmp, "att.der")
        pub_path = os.path.join(tmp, "att.pub")
        sig_path = os.path.join(tmp, "sig.der")
        signed_path = os.path.join(tmp, "signed.bin")
        open(cert_path, "wb").write(cert)
        open(sig_path, "wb").write(signature)
        open(signed_path, "wb").write(signed)
        pub = subprocess.check_output(["openssl", "x509", "-inform", "DER", "-in", cert_path, "-pubkey", "-noout"])
        open(pub_path, "wb").write(pub)
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", pub_path, "-signature", sig_path, signed_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        print(result.stdout.strip() or result.stderr.strip())
        return result.returncode == 0


def parse_attested_credential_id(auth_data: bytes) -> bytes:
    if len(auth_data) < 37:
        raise ValueError("authData too short")
    flags = auth_data[32]
    if not flags & 0x40:
        raise ValueError("authData does not include attested credential data")
    offset = 37 + 16
    if len(auth_data) < offset + 2:
        raise ValueError("authData missing credential ID length")
    credential_id_len = int.from_bytes(auth_data[offset : offset + 2], "big")
    offset += 2
    if credential_id_len <= 0 or len(auth_data) < offset + credential_id_len:
        raise ValueError("authData credential ID length is invalid")
    return auth_data[offset : offset + credential_id_len]


def make_ctap2_registration_request(
    cbor2,
    username: str = "dave",
    resident: bool = False,
    rp_id: str = "webauthn.io",
    uv: bool = False,
    pin_uv_auth_param: bytes | None = None,
) -> bytes:
    request = {
        1: secrets.token_bytes(32),
        2: {"id": rp_id, "name": rp_id},
        3: {"id": username.encode(), "name": username, "displayName": username},
        4: [{"type": "public-key", "alg": -7}],
        7: {"rk": resident, "uv": uv},
    }
    if pin_uv_auth_param is not None:
        request[8] = pin_uv_auth_param
        request[9] = PIN_PROTOCOL
    return bytes([CTAP2_MAKE_CREDENTIAL]) + cbor2.dumps(request)


def make_ctap2_assertion_request(
    cbor2,
    credential_id: bytes | None = None,
    rp_id: str = "webauthn.io",
    uv: bool = False,
    pin_uv_auth_param: bytes | None = None,
    up: bool | None = None,
) -> bytes:
    options = {"uv": uv}
    if up is not None:
        # Browsers set up=false for the silent pre-flight that discovers which
        # authenticator holds a credential; the key must answer without a touch.
        options["up"] = up
    request = {
        1: rp_id,
        2: secrets.token_bytes(32),
        5: options,
    }
    if credential_id is not None:
        request[3] = [{"type": "public-key", "id": credential_id}]
    if pin_uv_auth_param is not None:
        request[6] = pin_uv_auth_param
        request[7] = PIN_PROTOCOL
    return bytes([CTAP2_GET_ASSERTION]) + cbor2.dumps(request)


def make_uv_registration_request(cbor2, token: bytes, username: str, resident: bool, rp_id: str) -> bytes:
    client_hash = secrets.token_bytes(32)
    request = {
        1: client_hash,
        2: {"id": rp_id, "name": rp_id},
        3: {"id": username.encode(), "name": username, "displayName": username},
        4: [{"type": "public-key", "alg": -7}],
        7: {"rk": resident, "uv": True},
        8: hmac_sha256(token, client_hash),
        9: PIN_PROTOCOL,
    }
    return bytes([CTAP2_MAKE_CREDENTIAL]) + cbor2.dumps(request)


def make_uv_assertion_request(cbor2, token: bytes, credential_id: bytes, rp_id: str) -> bytes:
    client_hash = secrets.token_bytes(32)
    request = {
        1: rp_id,
        2: client_hash,
        3: [{"type": "public-key", "id": credential_id}],
        5: {"uv": True},
        6: hmac_sha256(token, client_hash),
        7: PIN_PROTOCOL,
    }
    return bytes([CTAP2_GET_ASSERTION]) + cbor2.dumps(request)


def print_assertion_summary(cbor2, body: bytes) -> int:
    print(f"getAssertion status=0x{body[0]:02x} cbor_len={len(body) - 1}")
    if body[0] != 0:
        return 0
    assertion = cbor2.loads(body[1:])
    credential = assertion.get(1, {})
    credential_count = assertion.get(5, 1)
    print(
        {
            "credentialIdLen": len(credential.get("id", b"")),
            "authDataLen": len(assertion.get(2, b"")),
            "signatureLen": len(assertion.get(3, b"")),
            "user": assertion.get(4, {}),
            "numberOfCredentials": credential_count,
        }
    )
    return int(credential_count or 0)


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    import hmac
    import hashlib

    return hmac.new(key, message, hashlib.sha256).digest()


def sha256(data: bytes) -> bytes:
    import hashlib

    return hashlib.sha256(data).digest()


def parse_cose_p256(key_agreement: dict) -> tuple[int, int]:
    x = int.from_bytes(key_agreement[-2], "big")
    y = int.from_bytes(key_agreement[-3], "big")
    return x, y


def derive_pin_shared_secret(authenticator_key_agreement: dict) -> tuple[object, bytes, bytes]:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    private_key = ec.generate_private_key(ec.SECP256R1())
    x, y = parse_cose_p256(authenticator_key_agreement)
    public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    shared = private_key.exchange(ec.ECDH(), public_numbers.public_key())
    salt = b"\x00" * 32
    hmac_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"CTAP2 HMAC key").derive(shared)
    aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"CTAP2 AES key").derive(shared)
    return private_key, hmac_key, aes_key


def cose_public_key(private_key) -> dict:
    numbers = private_key.public_key().public_numbers()
    return {
        1: 2,
        3: -25,
        -1: 1,
        -2: numbers.x.to_bytes(32, "big"),
        -3: numbers.y.to_bytes(32, "big"),
    }


def aes_cbc_encrypt(aes_key: bytes, plain: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    if len(plain) % 16 != 0:
        raise ValueError("PIN plaintext must be AES-block aligned")
    iv = secrets.token_bytes(16)
    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    return iv + encryptor.update(plain) + encryptor.finalize()


def aes_cbc_decrypt(aes_key: bytes, cipher_text: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    iv = cipher_text[:16]
    data = cipher_text[16:]
    decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def make_client_pin_request(cbor2, subcommand: int, params: dict | None = None) -> bytes:
    request = {1: PIN_PROTOCOL, 2: subcommand}
    if params:
        request.update(params)
    return bytes([CTAP2_CLIENT_PIN]) + cbor2.dumps(request)


def client_pin(dev, cid: int, cbor2, subcommand: int, params: dict | None = None) -> dict:
    _, cmd, body = send_single(dev, cid, CTAPHID_CBOR, make_client_pin_request(cbor2, subcommand, params))
    if cmd != CTAPHID_CBOR or not body:
        raise RuntimeError("clientPin failed")
    print(f"clientPin sub=0x{subcommand:02x} status=0x{body[0]:02x} cbor_len={len(body) - 1}")
    if body[0] != 0:
        return {"status": body[0]}
    decoded = cbor2.loads(body[1:]) if len(body) > 1 else {}
    print(decoded)
    return decoded


def get_pin_shared_secret(dev, cid: int, cbor2) -> tuple[dict, bytes, bytes]:
    key_response = client_pin(dev, cid, cbor2, CP_GET_KEY_AGREEMENT)
    private_key, hmac_key, aes_key = derive_pin_shared_secret(key_response[1])
    return cose_public_key(private_key), hmac_key, aes_key


def set_pin(dev, cid: int, cbor2, pin: str) -> None:
    platform_key, hmac_key, aes_key = get_pin_shared_secret(dev, cid, cbor2)
    pin_bytes = pin.encode("utf-8")
    if len(pin_bytes) < 4 or len(pin_bytes) > 63:
        raise ValueError("test PIN must be 4-63 UTF-8 bytes")
    new_pin_plain = pin_bytes + bytes(64 - len(pin_bytes))
    new_pin_enc = aes_cbc_encrypt(aes_key, new_pin_plain)
    pin_auth = hmac_sha256(hmac_key, new_pin_enc)
    result = client_pin(dev, cid, cbor2, CP_SET_PIN, {3: platform_key, 4: pin_auth, 5: new_pin_enc})
    if result.get("status", 0) != 0:
        raise RuntimeError("set PIN failed")


def get_pin_token(dev, cid: int, cbor2, pin: str, permissions: int, rp_id: str) -> bytes:
    platform_key, _hmac_key, aes_key = get_pin_shared_secret(dev, cid, cbor2)
    pin_hash_enc = aes_cbc_encrypt(aes_key, sha256(pin.encode("utf-8"))[:16])
    result = client_pin(
        dev,
        cid,
        cbor2,
        CP_GET_TOKEN_WITH_PERMISSIONS,
        {3: platform_key, 6: pin_hash_enc, 9: permissions, 10: rp_id},
    )
    if result.get("status", 0) != 0 or 2 not in result:
        raise RuntimeError("get PIN token failed")
    return aes_cbc_decrypt(aes_key, result[2])


def make_credential_management_request(cbor2, subcommand: int, params: dict | None = None) -> bytes:
    request = {1: subcommand}
    if params is not None:
        request[2] = params
    return bytes([CTAP2_CREDENTIAL_MANAGEMENT]) + cbor2.dumps(request)


def send_credential_management(dev, cid: int, cbor2, subcommand: int, params: dict | None = None) -> dict:
    cmd, body = send_cbor_wait(dev, cid, make_credential_management_request(cbor2, subcommand, params))
    if cmd != CTAPHID_CBOR or not body:
        raise RuntimeError("credentialManagement failed")
    print(f"credMgmt sub=0x{subcommand:02x} status=0x{body[0]:02x} cbor_len={len(body) - 1}")
    if body[0] != 0:
        return {"status": body[0]}
    decoded = cbor2.loads(body[1:]) if len(body) > 1 else {}
    print(decoded)
    return decoded


def run_reset(dev, cid: int) -> None:
    print("Sending authenticatorReset; hold BOOT until the board confirms wipe.")
    cmd, body = send_cbor_wait(dev, cid, bytes([CTAP2_RESET]))
    if cmd != CTAPHID_CBOR or not body:
        raise RuntimeError("reset failed")
    print(f"reset status=0x{body[0]:02x}")
    if body[0] != 0:
        raise RuntimeError("reset did not complete")


def run_credential_management_smoke(dev, cid: int, cbor2) -> None:
    rp_id = "credmgmt-" + secrets.token_hex(4) + ".local"
    username = "cm-" + secrets.token_hex(3)
    print(f"Creating resident credential for {rp_id}; press BOOT when the board prompts.")
    cmd, body = send_cbor_wait(
        dev,
        cid,
        make_ctap2_registration_request(cbor2, username=username, resident=True, rp_id=rp_id),
    )
    if cmd != CTAPHID_CBOR or not body or body[0] != 0:
        raise RuntimeError(f"resident setup failed: cmd={cmd} body={body.hex() if body else ''}")
    metadata = send_credential_management(dev, cid, cbor2, CM_GET_CREDS_METADATA)
    if metadata.get(1, 0) < 1:
        raise RuntimeError("credential metadata did not report resident credentials")

    first_rp = send_credential_management(dev, cid, cbor2, CM_ENUM_RPS_BEGIN)
    rp_entries = [first_rp]
    total_rps = int(first_rp.get(5, 1))
    for _ in range(1, total_rps):
        rp_entries.append(send_credential_management(dev, cid, cbor2, CM_ENUM_RPS_NEXT))
    target_rp = next((entry for entry in rp_entries if entry.get(3, {}).get("id") == rp_id), None)
    if target_rp is None:
        raise RuntimeError("created RP was not enumerated")
    rp_id_hash = target_rp[4]

    first_cred = send_credential_management(dev, cid, cbor2, CM_ENUM_CREDS_BEGIN, {1: rp_id_hash})
    credential_entries = [first_cred]
    total_credentials = int(first_cred.get(9, 1))
    for _ in range(1, total_credentials):
        credential_entries.append(send_credential_management(dev, cid, cbor2, CM_ENUM_CREDS_NEXT))
    target_credential = credential_entries[0][7]
    print("Deleting first enumerated credential; press BOOT when the board prompts.")
    send_credential_management(dev, cid, cbor2, CM_DELETE_CREDENTIAL, {2: target_credential})

    print("Checking deleted RP no longer has resident credentials.")
    cmd, body = send_cbor_wait(dev, cid, make_ctap2_assertion_request(cbor2, None, rp_id=rp_id))
    if cmd != CTAPHID_CBOR or not body:
        raise RuntimeError("post-delete getAssertion failed")
    print(f"postDelete getAssertion status=0x{body[0]:02x}")
    if body[0] == 0:
        raise RuntimeError("deleted credential still signs")


def run_client_pin_smoke(dev, cid: int, cbor2) -> None:
    rp_id = "pin-" + secrets.token_hex(4) + ".local"
    username = "pin-" + secrets.token_hex(3)
    pin = "123456"
    print("Checking PIN retries.")
    client_pin(dev, cid, cbor2, CP_GET_RETRIES)
    print(f"Setting host-entered test PIN for {rp_id}.")
    set_pin(dev, cid, cbor2, pin)
    print("Requesting pinUvAuthToken for makeCredential.")
    token = get_pin_token(dev, cid, cbor2, pin, PIN_PERMISSION_MAKE_CREDENTIAL, rp_id)
    print("Sending UV-required makeCredential; press BOOT when the board prompts.")
    cmd, body = send_cbor_wait(
        dev,
        cid,
        make_uv_registration_request(cbor2, token, username=username, resident=True, rp_id=rp_id),
    )
    if cmd != CTAPHID_CBOR or not body or body[0] != 0:
        raise RuntimeError(f"UV makeCredential failed: cmd={cmd} body={body.hex() if body else ''}")
    decoded = cbor2.loads(body[1:])
    auth_data = decoded.get(2, b"")
    if not auth_data or (auth_data[32] & 0x04) == 0:
        raise RuntimeError("makeCredential did not set the UV authData flag")
    credential_id = parse_attested_credential_id(auth_data)
    print({"uvMakeCredential": True, "credentialIdLen": len(credential_id)})

    print("Requesting pinUvAuthToken for getAssertion.")
    token = get_pin_token(dev, cid, cbor2, pin, PIN_PERMISSION_GET_ASSERTION, rp_id)
    print("Sending UV-required getAssertion; press BOOT when the board prompts.")
    cmd, body = send_cbor_wait(dev, cid, make_uv_assertion_request(cbor2, token, credential_id, rp_id))
    if cmd != CTAPHID_CBOR or not body or body[0] != 0:
        raise RuntimeError(f"UV getAssertion failed: cmd={cmd} body={body.hex() if body else ''}")
    assertion = cbor2.loads(body[1:])
    auth_data = assertion.get(2, b"")
    if not auth_data or (auth_data[32] & 0x04) == 0:
        raise RuntimeError("getAssertion did not set the UV authData flag")
    print({"uvGetAssertion": True, "signatureLen": len(assertion.get(3, b""))})


def run_dummy_rp_probe(dev, cid: int, cbor2) -> None:
    print("Sending synthetic .dummy getAssertion; device must reject without BOOT.")
    cmd, body = send_cbor_wait(dev, cid, make_ctap2_assertion_request(cbor2, None, rp_id=".dummy"))
    if cmd != CTAPHID_CBOR or not body:
        raise RuntimeError("dummy RP getAssertion probe failed")
    print(f"dummy getAssertion status=0x{body[0]:02x}")
    if body[0] != 0x2E:
        raise RuntimeError("dummy RP getAssertion was not rejected as no-credentials")


def run_dummy_makecred_probe(dev, cid: int, cbor2) -> None:
    print("Sending synthetic .dummy makeCredential; PRESS BOOT when prompted.")
    started = time.monotonic()
    write_message(dev, cid, CTAPHID_CBOR, make_ctap2_registration_request(cbor2, rp_id=".dummy"))
    _, cmd, body = read_message(dev, timeout_ms=3000)
    if cmd != CTAPHID_KEEPALIVE:
        raise RuntimeError("dummy RP makeCredential returned before user-presence keepalive")
    print(f"KEEPALIVE status=0x{body[0]:02x}; press BOOT now")
    while True:
        _, cmd, body = read_message(dev, timeout_ms=35000)
        if cmd == CTAPHID_KEEPALIVE:
            print(f"KEEPALIVE status=0x{body[0]:02x}; press BOOT now")
            continue
        break
    if cmd != CTAPHID_CBOR or not body:
        raise RuntimeError("dummy RP makeCredential probe failed")
    print(f"dummy makeCredential status=0x{body[0]:02x}")
    if body[0] != 0x27:
        raise RuntimeError("dummy RP makeCredential did not return operation-denied after touch")
    if time.monotonic() - started > 25:
        raise RuntimeError("dummy RP makeCredential timed out instead of collecting BOOT")


def run_preflight_probe(dev, cid: int, cbor2) -> None:
    """Regression test for silent pre-flight handling.

    A browser sends getAssertion with options.up=false to learn whether this
    authenticator holds a credential, and the key must answer immediately with
    the UP flag cleared and no touch. This catches the regression where the
    firmware ignored the up option and blocked every login on a BOOT press.
    """
    rp_id = "preflight-" + secrets.token_hex(4) + ".local"
    print(f"Registering a non-resident credential for {rp_id}; press BOOT when prompted.")
    cmd, body = send_cbor_wait(
        dev,
        cid,
        make_ctap2_registration_request(cbor2, username="preflight", resident=False, rp_id=rp_id),
    )
    if cmd != CTAPHID_CBOR or not body or body[0] != 0:
        raise RuntimeError(f"pre-flight setup makeCredential failed: cmd={cmd} body={body.hex() if body else ''}")
    credential_id = parse_attested_credential_id(cbor2.loads(body[1:]).get(2, b""))

    print("Sending silent pre-flight getAssertion (up=false); device must answer WITHOUT BOOT.")
    _, cmd, body = send_single(
        dev,
        cid,
        CTAPHID_CBOR,
        make_ctap2_assertion_request(cbor2, credential_id, rp_id=rp_id, up=False),
        timeout_ms=4000,
    )
    if cmd == CTAPHID_KEEPALIVE:
        raise RuntimeError("device sent KEEPALIVE for up=false pre-flight; it is still gating on BOOT")
    if cmd != CTAPHID_CBOR or not body:
        raise RuntimeError("pre-flight getAssertion returned no CBOR body")
    print(f"preflight getAssertion status=0x{body[0]:02x}")
    if body[0] != 0:
        raise RuntimeError(f"pre-flight up=false should succeed for a known credential, got 0x{body[0]:02x}")
    auth_data = cbor2.loads(body[1:]).get(2, b"")
    if not auth_data or len(auth_data) < 37:
        raise RuntimeError("pre-flight assertion missing authData")
    if auth_data[32] & 0x01:
        raise RuntimeError("pre-flight up=false must clear the UP flag in authData")
    print({"preflightUpFlag": 0, "authDataLen": len(auth_data), "note": "answered without BOOT"})

    print("Confirming the real up=true assertion still requires BOOT and sets UP=1; press BOOT.")
    cmd, body = send_cbor_wait(dev, cid, make_ctap2_assertion_request(cbor2, credential_id, rp_id=rp_id))
    if cmd != CTAPHID_CBOR or not body or body[0] != 0:
        raise RuntimeError(f"real getAssertion failed: status=0x{body[0] if body else 0:02x}")
    auth_data = cbor2.loads(body[1:]).get(2, b"")
    if not auth_data or (auth_data[32] & 0x01) == 0:
        raise RuntimeError("real up=true assertion must set the UP flag")
    print({"realUpFlag": 1, "note": "UP set after BOOT as expected"})


def run_stateless_bulk(dev, cid: int, cbor2, count: int) -> None:
    """Prove non-resident credentials are stateless: register far more than the
    8-slot store cap, confirm none fail with kKeyStoreFull, then sign with one
    and confirm tampered / cross-RP credential IDs are rejected."""
    rp_id = "webauthn.io"
    print(f"Registering {count} non-resident (stateless) credentials for {rp_id}; press BOOT for each.")
    cred_ids = []
    for i in range(count):
        cmd, body = send_cbor_wait(
            dev, cid, make_ctap2_registration_request(cbor2, username=f"bulk{i}", resident=False, rp_id=rp_id)
        )
        if cmd != CTAPHID_CBOR or not body:
            raise RuntimeError(f"registration {i} returned no body")
        if body[0] != 0:
            raise RuntimeError(f"registration {i} failed status=0x{body[0]:02x} (cap not removed?)")
        cred_id = parse_attested_credential_id(cbor2.loads(body[1:]).get(2, b""))
        cred_ids.append(bytes(cred_id))
        print(f"  [{i + 1}/{count}] ok, credentialIdLen={len(cred_id)}")
    if any(len(c) != 33 for c in cred_ids):
        raise RuntimeError("expected 33-byte stateless credential IDs")
    if len(set(cred_ids)) != count:
        raise RuntimeError("duplicate credential IDs minted (nonce collision)")
    print(f"All {count} stateless registrations succeeded with distinct 33-byte IDs (no 8-slot cap).")

    print("Signing with the last stateless credential; press BOOT.")
    cmd, body = send_cbor_wait(dev, cid, make_ctap2_assertion_request(cbor2, cred_ids[-1], rp_id=rp_id))
    if cmd != CTAPHID_CBOR or not body or body[0] != 0:
        raise RuntimeError(f"stateless assertion failed status=0x{body[0] if body else 0:02x}")
    print({"signedLastStateless": True, "signatureLen": len(cbor2.loads(body[1:]).get(3, b""))})

    tampered = bytearray(cred_ids[-1])
    tampered[-1] ^= 0xFF
    _, cmd, body = send_single(
        dev, cid, CTAPHID_CBOR, make_ctap2_assertion_request(cbor2, bytes(tampered), rp_id=rp_id, up=False), timeout_ms=4000
    )
    print(f"Tampered credential ID -> status=0x{body[0]:02x} (expect 0x2e, no BOOT)")
    if body[0] != 0x2E:
        raise RuntimeError("tampered stateless ID was not rejected")

    _, cmd, body = send_single(
        dev, cid, CTAPHID_CBOR, make_ctap2_assertion_request(cbor2, cred_ids[-1], rp_id="evil.example", up=False), timeout_ms=4000
    )
    print(f"Cross-RP reuse -> status=0x{body[0]:02x} (expect 0x2e, no BOOT)")
    if body[0] != 0x2E:
        raise RuntimeError("cross-RP reuse was not rejected")
    print("Stateless bulk + tamper + cross-RP checks passed.")


def run_stateless_verify(dev, cid: int, cbor2) -> None:
    """Register a non-resident (stateless) credential, then assert and
    CRYPTOGRAPHICALLY verify the signature against the public key from
    registration. This catches a key-derivation mismatch that a status-only
    check (--ctap2-roundtrip) would miss but a browser would reject."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature

    rp_id = "webauthn.io"
    print(f"Registering non-resident credential for {rp_id}; press BOOT.")
    cmd, body = send_cbor_wait(dev, cid, make_ctap2_registration_request(cbor2, username="verify", resident=False, rp_id=rp_id))
    if cmd != CTAPHID_CBOR or not body or body[0] != 0:
        raise RuntimeError(f"register failed status=0x{body[0] if body else 0:02x}")
    reg_auth = cbor2.loads(body[1:]).get(2, b"")
    cred_id = parse_attested_credential_id(reg_auth)
    cred_len = int.from_bytes(reg_auth[53:55], "big")
    cose = cbor2.loads(reg_auth[55 + cred_len:])
    pub_x = int.from_bytes(cose[-2], "big")
    pub_y = int.from_bytes(cose[-3], "big")
    pub = ec.EllipticCurvePublicNumbers(pub_x, pub_y, ec.SECP256R1()).public_key()
    print({"credentialIdLen": len(cred_id), "regAuthDataLen": len(reg_auth)})

    client_hash = secrets.token_bytes(32)
    request = {1: rp_id, 2: client_hash, 3: [{"type": "public-key", "id": cred_id}], 5: {"uv": False}}
    print("Asserting (up=true); press BOOT.")
    cmd, body = send_cbor_wait(dev, cid, bytes([CTAP2_GET_ASSERTION]) + cbor2.dumps(request))
    if cmd != CTAPHID_CBOR or not body or body[0] != 0:
        raise RuntimeError(f"assert failed status=0x{body[0] if body else 0:02x}")
    assertion = cbor2.loads(body[1:])
    a_auth = assertion.get(2, b"")
    sig = assertion.get(3, b"")
    print({
        "assertAuthDataLen": len(a_auth),
        "flagsByte": hex(a_auth[32]) if a_auth else None,
        "signatureLen": len(sig),
        "returnedCredentialMatches": bytes(assertion.get(1, {}).get("id", b"")) == bytes(cred_id),
        "userKeyPresent": 4 in assertion,
    })
    print("assertion authData hex:", a_auth.hex())
    print("signature DER hex:    ", sig.hex())
    try:
        pub.verify(sig, a_auth + client_hash, ec.ECDSA(hashes.SHA256()))
        print("SIGNATURE VALID -- verifies against the registration public key.")
    except InvalidSignature:
        print("SIGNATURE INVALID -- assertion key does not match registration key (derivation mismatch).")
        raise RuntimeError("stateless assertion signature does not verify")


def _es256_verify(pub_x: int, pub_y: int, message: bytes, der_sig: bytes):
    """Verify an ES256 (P-256/SHA-256) DER signature.

    Returns True/False if verification ran, or None when the ``cryptography``
    package is unavailable so the caller can print a pip hint and skip only the
    crypto step.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        return None
    try:
        pub = ec.EllipticCurvePublicNumbers(pub_x, pub_y, ec.SECP256R1()).public_key()
        pub.verify(der_sig, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    except Exception:
        # Invalid point (e.g. the (0,0) availability probe), malformed DER,
        # or any other crypto error: treat as a failed verification, never raise.
        return False


def _login_verify_path(dev, cid: int, cbor2, rp_id: str, label: str, resident: bool) -> bool:
    """Reproduce Chrome's login ceremony for one path and rigorously validate
    the assertion the way Chrome would. Returns True on PASS, False on FAIL and
    prints the first failing check."""

    def fail(msg: str) -> bool:
        print(f"{label}: FAIL {msg}")
        return False

    rp_id_hash = sha256(rp_id.encode("utf-8"))

    # 1. makeCredential; parse attestation; extract COSE pubkey (x,y) + credId.
    print(f"[{label}] makeCredential(rk={resident}) for {rp_id}; press BOOT.")
    cmd, body = send_cbor_wait(
        dev, cid, make_ctap2_registration_request(cbor2, username=f"login-{label}", resident=resident, rp_id=rp_id)
    )
    if cmd != CTAPHID_CBOR or not body:
        return fail("makeCredential returned no CBOR body")
    if body[0] != 0:
        return fail(f"makeCredential status=0x{body[0]:02x}")
    reg_auth = cbor2.loads(body[1:]).get(2, b"")
    try:
        cred_id = parse_attested_credential_id(reg_auth)
    except ValueError as exc:
        return fail(f"attestation authData parse: {exc}")
    cred_len = int.from_bytes(reg_auth[53:55], "big")
    try:
        cose = cbor2.loads(reg_auth[55 + cred_len:])
        pub_x = int.from_bytes(cose[-2], "big")
        pub_y = int.from_bytes(cose[-3], "big")
    except Exception as exc:
        return fail(f"attested COSE key parse: {exc}")
    print(f"  credentialId={len(cred_id)} bytes "
          f"(expect {'32 resident' if resident else '33 stateless'}), pubkey extracted")

    allow = bytes(cred_id)

    # 2. Silent pre-flight: up=false must succeed without BOOT and UP clear.
    print("  pre-flight getAssertion (up=false); device must answer WITHOUT BOOT.")
    _, cmd, body = send_single(
        dev, cid, CTAPHID_CBOR,
        make_ctap2_assertion_request(cbor2, allow, rp_id=rp_id, up=False), timeout_ms=4000,
    )
    if cmd == CTAPHID_KEEPALIVE:
        return fail("device sent KEEPALIVE for up=false pre-flight (still gating on BOOT)")
    if cmd != CTAPHID_CBOR or not body:
        return fail("pre-flight returned no CBOR body")
    if body[0] != 0:
        return fail(f"pre-flight up=false should succeed, got 0x{body[0]:02x}")
    pf_auth = cbor2.loads(body[1:]).get(2, b"")
    if not pf_auth or len(pf_auth) < 37:
        return fail("pre-flight assertion missing authData")
    if pf_auth[32] & 0x01:
        return fail(f"pre-flight UP bit set (flags 0x{pf_auth[32]:02x}); up=false must clear UP")
    print(f"  pre-flight OK (flags 0x{pf_auth[32]:02x}, UP clear, no BOOT)")

    # 3. Real getAssertion: up=true; validate like Chrome.
    client_data_hash = secrets.token_bytes(32)
    request = {1: rp_id, 2: client_data_hash, 3: [{"type": "public-key", "id": allow}], 5: {"uv": False, "up": True}}
    print("  real getAssertion (up=true); PRESS BOOT now.")
    cmd, body = send_cbor_wait(dev, cid, bytes([CTAP2_GET_ASSERTION]) + cbor2.dumps(request))
    if cmd != CTAPHID_CBOR or not body:
        return fail("real getAssertion returned no CBOR body")
    if body[0] != 0:
        return fail(f"real getAssertion status=0x{body[0]:02x}")
    raw_response = bytes(body[1:])

    # 3a. STRICT canonical-CBOR check: re-encode must byte-match raw response.
    try:
        assertion = cbor2.loads(raw_response)
    except Exception as exc:
        return fail(f"response is not valid CBOR: {exc}")
    if not isinstance(assertion, dict):
        return fail("top-level response is not a CBOR map")
    try:
        recanon = cbor2.dumps(assertion, canonical=True)
    except Exception as exc:
        return fail(f"could not re-encode response canonically: {exc}")
    if recanon != raw_response:
        print(f"    raw      : {raw_response.hex()}")
        print(f"    canonical: {recanon.hex()}")
        return fail("canonical-CBOR mismatch at top-level map "
                    "(non-canonical key order / non-minimal lengths -> Chrome rejects)")
    print("  canonical-CBOR OK (response is canonical)")

    # 3b. authData structural checks.
    auth_raw = assertion.get(2, b"")
    if not auth_raw:
        return fail("assertion missing authData (key 2)")
    if auth_raw[:32] != rp_id_hash:
        return fail("rpIdHash != sha256(rpId)")
    flags = auth_raw[32]
    if not (flags & 0x01):
        return fail(f"UP bit clear after up=true (flags 0x{flags:02x})")
    if flags & 0x40:
        return fail(f"AT bit set in assertion authData (flags 0x{flags:02x})")
    if len(auth_raw) != 37:
        return fail(f"authData length {len(auth_raw)} != 37 (unexpected attested data / extensions)")
    print(f"  authData OK (flags 0x{flags:02x}, len 37, rpIdHash matches)")

    # 3c. Cryptographically verify the ECDSA signature.
    sig = assertion.get(3, b"")
    if not sig:
        return fail("assertion missing signature (key 3)")
    verdict = _es256_verify(pub_x, pub_y, auth_raw + client_data_hash, sig)
    if verdict is None:
        print("  signature: SKIPPED (pip install cryptography to verify)")
    elif verdict is False:
        return fail("ECDSA signature does NOT verify over authData||clientDataHash")
    else:
        print("  signature VERIFIES over authData||clientDataHash OK")

    # 3d. Check resident-user privacy under UV=false. Chrome rejects assertions
    # that expose identifying user strings without user verification.
    user_entity = assertion.get(4)
    if user_entity is None:
        if resident:
            return fail("resident assertion missing user entity (key 4)")
    else:
        if not isinstance(user_entity, dict):
            return fail("user entity (key 4) is not a CBOR map")
        user_key_names = ", ".join(str(k) for k in sorted(user_entity.keys(), key=str))
        if "id" not in user_entity:
            return fail("user entity missing id")
        if not (flags & 0x04):
            leaked = [k for k in ("name", "displayName", "icon") if k in user_entity]
            if leaked:
                return fail(f"user entity leaks identifying fields without UV: {leaked}")
            print(f"  user entity privacy OK (UV=false, keys=[{user_key_names}])")
        else:
            print(f"  user entity OK (UV=true, keys=[{user_key_names}])")

    print(f"  key1 (credential descriptor) present: {1 in assertion}; "
          f"key4 (user) present: {4 in assertion}")

    print(f"{label}: PASS")
    return True


def run_login_verify(dev, cid: int, cbor2, rp_id: str) -> bool:
    """Chrome-like login oracle for both non-resident and resident paths.

    Catches the structural / signature defects that make Chrome HANG on login
    even though the device returns CTAP2_OK and a lenient probe is satisfied."""
    if _es256_verify(0, 0, b"", b"") is None:
        print("NOTE: cryptography not installed; signature step will be SKIPPED "
              "(pip install cryptography to enable).")
    nonres = _login_verify_path(dev, cid, cbor2, rp_id, "NON-RESIDENT", resident=False)
    res = _login_verify_path(dev, cid, cbor2, rp_id, "RESIDENT", resident=True)
    print("---- login-verify summary ----")
    print(f"NON-RESIDENT: {'PASS' if nonres else 'FAIL'}")
    print(f"RESIDENT: {'PASS' if res else 'FAIL'}")
    return nonres and res


def describe_devices(devices: Iterable[dict]) -> None:
    for index, dev in enumerate(devices):
        product = dev.get("product_string") or ""
        manufacturer = dev.get("manufacturer_string") or ""
        path = dev.get("path")
        print(f"[{index}] {manufacturer} {product} path={path!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true", help="list FIDO HID devices and exit")
    parser.add_argument("--make-credential", action="store_true", help="send a lab makeCredential request")
    parser.add_argument("--ctap2-roundtrip", action="store_true", help="register and sign with CTAP2 only")
    parser.add_argument("--resident-roundtrip", action="store_true", help="register and sign a discoverable CTAP2 credential")
    parser.add_argument("--cred-mgmt-smoke", action="store_true", help="create, enumerate, and delete a resident credential")
    parser.add_argument("--client-pin-smoke", action="store_true", help="set a test PIN and run UV-required CTAP2")
    parser.add_argument("--dummy-rp-probe", action="store_true", help="verify .dummy RP is rejected without user presence")
    parser.add_argument("--dummy-makecred-probe", action="store_true",
                        help="verify .dummy makeCredential collects BOOT then returns operation denied")
    parser.add_argument("--preflight-probe", action="store_true", help="verify up=false silent pre-flight answers without BOOT and clears the UP flag")
    parser.add_argument("--stateless-bulk", nargs="?", type=int, const=10, default=None, metavar="N",
                        help="register N (default 10) non-resident creds to prove the 8-slot cap is gone, then sign/tamper/cross-RP checks")
    parser.add_argument("--stateless-verify", action="store_true",
                        help="register a non-resident cred then cryptographically verify the assertion signature against the registration public key")
    parser.add_argument("--login-verify", action="store_true",
                        help="Chrome-like login oracle: validate canonical CBOR, authData flags, resident-user privacy, and assertion signatures for non-resident/resident paths")
    parser.add_argument("--rp-id", default="webauthn.io", help="relying party id to use for --login-verify (default webauthn.io)")
    parser.add_argument("--reset", action="store_true", help="guarded CTAP2 reset; hold BOOT to wipe lab credentials")
    parser.add_argument("--u2f-register", action="store_true", help="send a legacy CTAP1/U2F register request")
    parser.add_argument("--path", help="hidapi path to open; defaults to the first FIDO HID device")
    args = parser.parse_args()

    devices = find_devices()
    if args.list:
        describe_devices(devices)
        return 0

    dev = open_device(args.path.encode() if args.path else None)
    nonce = secrets.token_bytes(8)
    _, cmd, init_body = send_single(dev, BROADCAST_CID, CTAPHID_INIT, nonce)
    if cmd != CTAPHID_INIT or init_body[:8] != nonce:
        raise RuntimeError("CTAPHID_INIT failed")
    cid = struct.unpack(">I", init_body[8:12])[0]
    print(f"INIT ok: cid=0x{cid:08x} version={init_body[12]} caps=0x{init_body[16]:02x}")

    ping_payload = os.urandom(16)
    _, cmd, ping_body = send_single(dev, cid, CTAPHID_PING, ping_payload)
    if cmd != CTAPHID_PING or ping_body != ping_payload:
        raise RuntimeError("CTAPHID_PING failed")
    print("PING ok")

    _, cmd, cbor_body = send_single(dev, cid, CTAPHID_CBOR, bytes([CTAP2_GET_INFO]))
    if cmd != CTAPHID_CBOR or not cbor_body:
        raise RuntimeError("CTAP2 getInfo failed")
    print(f"getInfo status=0x{cbor_body[0]:02x} cbor={cbor_body[1:].hex()}")
    try:
        import cbor2  # type: ignore

        print(cbor2.loads(cbor_body[1:]))
    except Exception:
        print("Install cbor2 to pretty-print getInfo: python3 -m pip install cbor2")

    if args.reset:
        run_reset(dev, cid)

    if (
        args.make_credential
        or args.ctap2_roundtrip
        or args.resident_roundtrip
        or args.cred_mgmt_smoke
        or args.client_pin_smoke
        or args.dummy_rp_probe
        or args.dummy_makecred_probe
        or args.preflight_probe
        or args.stateless_bulk is not None
        or args.stateless_verify
        or args.login_verify
    ):
        try:
            import cbor2  # type: ignore
        except ImportError:
            print("Missing cbor2 package. Install with: python3 -m pip install cbor2", file=sys.stderr)
            return 2

    if args.cred_mgmt_smoke:
        run_credential_management_smoke(dev, cid, cbor2)

    if args.client_pin_smoke:
        run_client_pin_smoke(dev, cid, cbor2)

    if args.dummy_rp_probe:
        run_dummy_rp_probe(dev, cid, cbor2)

    if args.dummy_makecred_probe:
        run_dummy_makecred_probe(dev, cid, cbor2)

    if args.preflight_probe:
        run_preflight_probe(dev, cid, cbor2)

    if args.stateless_bulk is not None:
        run_stateless_bulk(dev, cid, cbor2, args.stateless_bulk)

    if args.stateless_verify:
        run_stateless_verify(dev, cid, cbor2)

    if args.login_verify:
        if not run_login_verify(dev, cid, cbor2, args.rp_id):
            return 1

    if args.make_credential or args.ctap2_roundtrip or args.resident_roundtrip:
        print("Sending makeCredential; press BOOT when the board prompts.")
        cmd, body = send_cbor_wait(dev, cid, make_ctap2_registration_request(cbor2, resident=args.resident_roundtrip))
        if cmd != CTAPHID_CBOR or not body:
            raise RuntimeError("CTAP2 makeCredential failed")
        print(f"makeCredential status=0x{body[0]:02x} cbor_len={len(body) - 1}")
        if body[0] == 0:
            decoded = cbor2.loads(body[1:])
            auth_data = decoded.get(2, b"")
            credential_id = parse_attested_credential_id(auth_data)
            print(
                {
                    "fmt": decoded.get(1),
                    "authDataLen": len(auth_data),
                    "credentialIdLen": len(credential_id),
                    "attStmt": decoded.get(3),
                }
            )
            if args.ctap2_roundtrip or args.resident_roundtrip:
                print("Sending getAssertion; press BOOT when the board prompts.")
                cmd, body = send_cbor_wait(
                    dev,
                    cid,
                    make_ctap2_assertion_request(cbor2, None if args.resident_roundtrip else credential_id),
                )
                if cmd != CTAPHID_CBOR or not body:
                    raise RuntimeError("CTAP2 getAssertion failed")
                credential_count = print_assertion_summary(cbor2, body)
                if args.resident_roundtrip and credential_count > 1:
                    for index in range(2, credential_count + 1):
                        print(f"Sending getNextAssertion #{index}.")
                        _, cmd, next_body = send_single(dev, cid, CTAPHID_CBOR, bytes([CTAP2_GET_NEXT_ASSERTION]))
                        if cmd != CTAPHID_CBOR or not next_body:
                            raise RuntimeError("CTAP2 getNextAssertion failed")
                        print_assertion_summary(cbor2, next_body)

    if args.u2f_register:
        _, cmd, version_body = send_single(dev, cid, CTAPHID_MSG, u2f_extended_apdu(U2F_VERSION))
        print(f"U2F version cmd=0x{cmd:02x} body={version_body!r}")
        challenge = secrets.token_bytes(32)
        app = secrets.token_bytes(32)
        print("Sending U2F register; press BOOT when the board prompts.")
        cmd, body = send_msg_wait(dev, cid, u2f_extended_apdu(U2F_REGISTER, challenge + app))
        if cmd != CTAPHID_MSG or len(body) < 2:
            raise RuntimeError("U2F register failed")
        status = int.from_bytes(body[-2:], "big")
        print(f"U2F register status=0x{status:04x} body_len={len(body)}")
        if status == 0x9000:
            key_handle_len = body[66]
            verified = openssl_verify_u2f_register(body, challenge, app)
            print(
                {
                    "reserved": body[0],
                    "pubkey_len": 65,
                    "keyHandleLen": key_handle_len,
                    "certAndSigLen": len(body) - 2 - 67 - key_handle_len,
                    "attestationVerified": verified,
                }
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
