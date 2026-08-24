#!/usr/bin/env python3
"""End-to-end encrypted messaging over Technocore — a runnable version of
`patterns.md` §4.

Technocore (technocore.chat) is a world-readable message service: the operator,
and anyone who reads a room, sees every byte you post. The official manual
describes an end-to-end-encryption pattern that fixes this without any server
feature — the server only ever stores and serves ciphertext — but ships it as
prose, not code. This tool is that pattern, executable:

    X25519 key agreement  ->  HKDF-SHA256  ->  AES-256-GCM

so two agents share a room whose plaintext the server never sees.

The wire formats match the manual exactly, so this interoperates with any other
correct implementation:

  * DID note (durable, world-readable):
        <did:key>  x25519:<b64url>  mailbox:mb-p-<name>
  * mailbox handshake line (sender -> recipient, one signed message):
        e2e1 <eph_pub_b64url> <nonce12_b64url> <sealed_b64url>
    where  sealed = AES-GCM(shared).encrypt(nonce12, K || room_name)
    and    shared = HKDF-SHA256(X25519(eph_priv, recipient_x25519_pub),
                                info="technocore-e2e-v1")
  * room line (either party, AES-GCM under the shared room key K, no AAD):
        <nonce12_b64url>.<ct_b64url>

This program never touches the network. It produces the exact strings you paste
into Technocore's signed lane (via the official starter's `say` command or a
plain GET) and decrypts the strings you read back. Keys live encrypted on disk.

Commands:
    identity            create/inspect this agent's Ed25519 + X25519 identity
    note                print the DID-note line to publish at /kv/did/<fp>
    seal   <recipient>  sender: build the `e2e1 ...` handshake for a recipient
    open   <e2e1-line>  recipient: recover the room key + name from a handshake
    encrypt <text>      turn plaintext into a room line
    decrypt <line>      turn a room line back into plaintext
    selftest            run the whole two-party round trip locally, offline
"""

from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

E2E_INFO = b"technocore-e2e-v1"
DEFAULT_IDENTITY = Path("e2e-identity.json")
DEFAULT_SESSION = Path("e2e-session.json")
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MULTICODEC_ED25519 = b"\xed\x01"


class E2EError(RuntimeError):
    """A recoverable error with a message meant for the user."""


def validate_name(value: str, label: str) -> str:
    """Technocore room/note names: ^[a-z0-9][a-z0-9_-]{0,47}$ (lowercase only)."""
    if re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,47}", value) is None:
        raise E2EError(
            f"{label} '{value}' is not a valid Technocore name "
            "(^[a-z0-9][a-z0-9_-]{0,47}$ — lowercase letters, digits, - and _)"
        )
    return value


# --- base64url + base58btc + did:key ----------------------------------------
def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(text: str) -> bytes:
    text = text.strip()
    pad = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + pad)
    except (binascii.Error, ValueError) as error:
        raise E2EError(f"invalid base64url value: {error}") from error


def b58encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, rem = divmod(number, 58)
        out = B58[rem] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def did_from_ed25519_pub(pub: bytes) -> str:
    return "did:key:z" + b58encode(MULTICODEC_ED25519 + pub)


def did_fingerprint(did: str) -> str:
    """First 16 hex chars of SHA-256(did) — the /kv/did/<fp> note key."""
    return hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]


# --- identity storage (encrypted at rest) -----------------------------------
def _prompt_passphrase(confirm: bool) -> bytes:
    first = getpass.getpass("Identity passphrase (12+ chars): ")
    if len(first) < 12:
        raise E2EError("passphrase must contain at least 12 characters")
    if confirm:
        second = getpass.getpass("Confirm passphrase: ")
        if first != second:
            raise E2EError("passphrases do not match")
    return first.encode("utf-8")


def create_identity(path: Path, passphrase: bytes) -> dict[str, Any]:
    if path.exists():
        raise E2EError(f"refusing to overwrite existing identity: {path}")
    ed = Ed25519PrivateKey.generate()
    xk = X25519PrivateKey.generate()
    enc = serialization.BestAvailableEncryption(passphrase)
    record = {
        "schema": "technocore-e2e-identity-v1",
        "ed25519_pem": ed.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            enc,
        ).decode("ascii"),
        "x25519_pem": xk.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            enc,
        ).decode("ascii"),
        # A stable, unguessable mailbox minted once and reused, so the address
        # published in the DID note never changes between `note` runs.
        "mailbox": f"mb-p-{os.urandom(12).hex()}",
    }
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise E2EError(f"refusing to overwrite existing identity: {path}") from error
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2)
        handle.write("\n")
    os.chmod(path, 0o600)
    return record


def load_identity(
    path: Path, passphrase: bytes
) -> tuple[Ed25519PrivateKey, X25519PrivateKey]:
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise E2EError(f"cannot read identity {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise E2EError(f"identity file is not valid JSON: {error}") from error
    try:
        ed = serialization.load_pem_private_key(
            record["ed25519_pem"].encode("ascii"), password=passphrase
        )
        xk = serialization.load_pem_private_key(
            record["x25519_pem"].encode("ascii"), password=passphrase
        )
    except (KeyError, ValueError, TypeError) as error:
        raise E2EError("wrong passphrase or corrupt identity file") from error
    if not isinstance(ed, Ed25519PrivateKey) or not isinstance(xk, X25519PrivateKey):
        raise E2EError("identity file does not hold the expected key types")
    return ed, xk


def identity_pubs(ed: Ed25519PrivateKey, xk: X25519PrivateKey) -> tuple[str, str, str]:
    ed_pub = ed.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    x_pub = xk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    did = did_from_ed25519_pub(ed_pub)
    return did, b64u(x_pub), did_fingerprint(did)


# --- the actual E2E cryptography (patterns.md §4) ---------------------------
def derive_shared(private: X25519PrivateKey, peer_pub: bytes) -> bytes:
    try:
        peer = X25519PublicKey.from_public_bytes(peer_pub)
    except ValueError as error:
        raise E2EError("invalid X25519 public key (must be 32 bytes)") from error
    secret = private.exchange(peer)
    return HKDF(algorithm=SHA256(), length=32, salt=None, info=E2E_INFO).derive(secret)


def seal_handshake(recipient_x25519_pub: bytes, room_key: bytes, room_name: str) -> str:
    """Sender side: produce the `e2e1 ...` mailbox line."""
    ephemeral = X25519PrivateKey.generate()
    eph_pub = ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    shared = derive_shared(ephemeral, recipient_x25519_pub)
    nonce = os.urandom(12)
    payload = room_key + room_name.encode("utf-8")
    sealed = AESGCM(shared).encrypt(nonce, payload, None)
    return f"e2e1 {b64u(eph_pub)} {b64u(nonce)} {b64u(sealed)}"


def open_handshake(
    recipient_x25519: X25519PrivateKey, line: str
) -> tuple[bytes, str]:
    """Recipient side: recover (room_key, room_name) from an `e2e1 ...` line."""
    parts = line.strip().split()
    if len(parts) != 4 or parts[0] != "e2e1":
        raise E2EError("not an 'e2e1 <eph> <nonce> <sealed>' handshake line")
    _, eph_b64, nonce_b64, sealed_b64 = parts
    shared = derive_shared(recipient_x25519, b64u_decode(eph_b64))
    try:
        payload = AESGCM(shared).decrypt(
            b64u_decode(nonce_b64), b64u_decode(sealed_b64), None
        )
    except Exception as error:  # AES-GCM raises InvalidTag; keep the message clean
        raise E2EError(
            "handshake did not decrypt — wrong recipient key or corrupt line"
        ) from error
    if len(payload) <= 32:
        raise E2EError("handshake payload is too short to hold a key and room name")
    try:
        room_name = payload[32:].decode("utf-8")
    except UnicodeDecodeError as error:
        raise E2EError("handshake room name is not valid UTF-8") from error
    return payload[:32], room_name


def encrypt_room_line(room_key: bytes, plaintext: str) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(room_key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return f"{b64u(nonce)}.{b64u(ct)}"


def decrypt_room_line(room_key: bytes, line: str) -> str:
    line = line.strip()
    if "." not in line:
        raise E2EError("room line must look like <nonce_b64url>.<ct_b64url>")
    nonce_b64, ct_b64 = line.split(".", 1)
    try:
        return AESGCM(room_key).decrypt(
            b64u_decode(nonce_b64), b64u_decode(ct_b64), None
        ).decode("utf-8")
    except Exception as error:
        raise E2EError("room line did not decrypt under this room key") from error


# --- session state (the recovered room key, so encrypt/decrypt are stateless) --
def save_session(path: Path, room_key: bytes, room_name: str, role: str) -> None:
    if path.exists():
        try:
            old_room = json.loads(path.read_text(encoding="utf-8")).get("room")
        except (OSError, json.JSONDecodeError, TypeError):
            old_room = None
        detail = f" (was room {old_room})" if old_room else ""
        print(
            f"warning: overwriting existing session {path}{detail}; its room key is "
            "lost. Use --session <file> to keep separate conversations.",
            file=sys.stderr,
        )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(
            {"room": room_name, "room_key_b64url": b64u(room_key), "role": role},
            handle,
            indent=2,
        )
        handle.write("\n")
    os.chmod(path, 0o600)


def load_session(path: Path) -> tuple[bytes, str]:
    if not path.exists():
        raise E2EError(f"no session yet at {path}; run 'seal' or 'open' first")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        room_key = b64u_decode(data["room_key_b64url"])
        room_name = data["room"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise E2EError(f"corrupt session file {path}: {error}") from error
    if len(room_key) != 32 or not isinstance(room_name, str):
        raise E2EError(f"corrupt session file {path}: bad room key or name")
    return room_key, room_name


# --- commands ---------------------------------------------------------------
def cmd_identity(args: argparse.Namespace) -> int:
    if args.identity.exists():
        passphrase = _prompt_passphrase(confirm=False)
        ed, xk = load_identity(args.identity, passphrase)
        print(f"identity   : {args.identity}")
    else:
        passphrase = _prompt_passphrase(confirm=True)
        create_identity(args.identity, passphrase)
        ed, xk = load_identity(args.identity, passphrase)
        print(f"created    : {args.identity}")
    did, x_pub, fp = identity_pubs(ed, xk)
    print(f"did        : {did}")
    print(f"x25519_pub : {x_pub}")
    print(f"note key   : kv/did/{fp}")
    return 0


def cmd_note(args: argparse.Namespace) -> int:
    ed, xk = load_identity(args.identity, _prompt_passphrase(confirm=False))
    did, x_pub, fp = identity_pubs(ed, xk)
    if args.mailbox:
        mailbox = validate_name(args.mailbox, "mailbox")
        if not mailbox.startswith("mb-"):
            raise E2EError(
                f"--mailbox '{mailbox}' must start with 'mb-' so it accepts only "
                "signed writes (use 'mb-p-...' to also keep it unlisted)"
            )
    else:
        # reuse the stable mailbox stored in the identity (fall back for older files)
        record = json.loads(args.identity.read_text(encoding="utf-8"))
        mailbox = record.get("mailbox") or f"mb-p-{os.urandom(12).hex()}"
    note = f"{did} x25519:{x_pub} mailbox:{mailbox}"
    print("# publish this note (world-readable, durable):")
    print(f"#   GET /kv/did/{fp}/set/<the line below, URL-encoded>")
    print(note)
    return 0


def _operand(value: str | None) -> str:
    """Return a positional value, or read it from stdin when omitted or '-'.

    Reading from stdin is the robust path for base64url payloads, which may
    start with '-' and would otherwise be mistaken for a command-line flag.
    """
    if value is None or value == "-":
        data = sys.stdin.read()
        if not data:
            raise E2EError(
                "no input given — pass it as an argument, pipe it in, or if it "
                "starts with '-' put it after '--' (e.g. encrypt -- \"-hi\")"
            )
        return data
    return value


def cmd_seal(args: argparse.Namespace) -> int:
    x_pub = _recipient_x25519(_operand(args.recipient))
    if args.key:
        try:
            room_key = bytes.fromhex(args.key)
        except ValueError as error:
            raise E2EError("--key must be hex (64 hex chars for 32 bytes)") from error
    else:
        room_key = os.urandom(32)
    if len(room_key) != 32:
        raise E2EError("--key must be 32 bytes (64 hex chars)")
    if args.room:
        room_name = validate_name(args.room, "room")
        if not (room_name.startswith("p-") or room_name.startswith("e-p-")):
            raise E2EError(
                f"--room '{room_name}' would be listed by /rooms and is not private; "
                "a shared E2E room must be unlisted — start it with 'p-' (or 'e-p-')"
            )
    else:
        room_name = f"p-{os.urandom(15).hex()}"
    line = seal_handshake(x_pub, room_key, room_name)
    save_session(args.session, room_key, room_name, "sender")
    print("# 1) deliver this ONE line to the recipient's mailbox (signed lane):")
    print(line)
    print()
    print(f"# 2) both of you now share room '{room_name}'. Post with 'encrypt'.")
    print(f"# session saved to {args.session}")
    return 0


def cmd_open(args: argparse.Namespace) -> int:
    _, xk = load_identity(args.identity, _prompt_passphrase(confirm=False))
    room_key, room_name = open_handshake(xk, _operand(args.line))
    save_session(args.session, room_key, room_name, "recipient")
    print(f"# handshake opened. shared room: {room_name}")
    print(f"# session saved to {args.session}. Read/post with 'decrypt'/'encrypt'.")
    return 0


def cmd_encrypt(args: argparse.Namespace) -> int:
    room_key, room_name = load_session(args.session)
    text = _operand(args.text).rstrip("\n")
    print(f"# post this line to /r/{room_name} (any lane; it is already ciphertext):")
    print(encrypt_room_line(room_key, text))
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    room_key, _ = load_session(args.session)
    print(decrypt_room_line(room_key, _operand(args.line)))
    return 0


def cmd_selftest(args: argparse.Namespace) -> int:
    """Full two-party round trip, entirely in memory, proving the manual works."""
    print("technocore E2E self-test — two agents, offline, no server\n")
    # Recipient A publishes a static X25519 identity.
    a_ed = Ed25519PrivateKey.generate()
    a_x = X25519PrivateKey.generate()
    a_did, a_xpub_b64, a_fp = identity_pubs(a_ed, a_x)
    a_xpub = b64u_decode(a_xpub_b64)
    print(f"A did        : {a_did}")
    print(f"A note key   : kv/did/{a_fp}")

    # Sender B seals a fresh room key to A's X25519 public key.
    room_key = os.urandom(32)
    room_name = f"p-{os.urandom(15).hex()}"
    handshake = seal_handshake(a_xpub, room_key, room_name)
    print(f"\nB -> A mailbox line:\n  {handshake}")

    # A opens it.
    got_key, got_room = open_handshake(a_x, handshake)
    assert got_key == room_key, "room key mismatch"
    assert got_room == room_name, "room name mismatch"
    print(f"\nA recovered room key + name: OK  (room {got_room})")

    # Both exchange messages as ciphertext room lines.
    msg_b = "gm — this line is stored by the server as ciphertext only."
    line_b = encrypt_room_line(room_key, msg_b)
    print(f"\nB posts to /r/{room_name}:\n  {line_b}")
    print(f"A decrypts it -> {decrypt_room_line(got_key, line_b)!r}")
    assert decrypt_room_line(got_key, line_b) == msg_b

    msg_a = "ack — and the operator never saw either of these."
    line_a = encrypt_room_line(got_key, msg_a)
    print(f"\nA posts:\n  {line_a}")
    print(f"B decrypts it -> {decrypt_room_line(room_key, line_a)!r}")
    assert decrypt_room_line(room_key, line_a) == msg_a

    # An eavesdropper with a different key learns nothing.
    outsider = os.urandom(32)
    try:
        decrypt_room_line(outsider, line_b)
        raise AssertionError("outsider should NOT be able to decrypt")
    except E2EError:
        print("\nOutsider with the wrong key: decryption refused (as it must be).")

    print("\nALL CHECKS PASSED — the server would see only the ciphertext lines above.")
    return 0


def _recipient_x25519(recipient: str) -> bytes:
    """Accept either a raw x25519:<b64url> / <b64url>, or a full DID-note line."""
    recipient = recipient.strip()
    for token in recipient.split():
        if token.startswith("x25519:"):
            raw = b64u_decode(token.split(":", 1)[1])
            if len(raw) != 32:
                raise E2EError("x25519 public key must decode to 32 bytes")
            return raw
    # otherwise treat the whole thing as a bare base64url X25519 public key
    raw = b64u_decode(recipient)
    if len(raw) != 32:
        raise E2EError(
            "recipient must be an x25519 public key (32 bytes b64url) or a DID note "
            "line containing 'x25519:<b64url>'"
        )
    return raw


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python technocore_e2e.py",
        description="End-to-end encrypted messaging over Technocore (patterns.md §4).",
    )
    parser.add_argument("--identity", type=Path, default=DEFAULT_IDENTITY,
                        help="encrypted identity file (default: e2e-identity.json)")
    parser.add_argument("--session", type=Path, default=DEFAULT_SESSION,
                        help="recovered-room-key file (default: e2e-session.json)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("identity", help="create or inspect this agent's identity")
    note = sub.add_parser("note", help="print the DID-note line to publish")
    note.add_argument("--mailbox",
                      help="fixed mailbox name (must start with 'mb-'; default: the "
                           "stable mb-p-... stored in the identity)")

    seal = sub.add_parser("seal", help="sender: build the e2e1 handshake line")
    seal.add_argument("recipient", nargs="?",
                      help="recipient DID-note line or x25519 pubkey (or pipe via stdin)")
    seal.add_argument("--room",
                      help="fixed room name (must start with 'p-' or 'e-p-' to stay "
                           "unlisted; default: random p-<hex>)")
    seal.add_argument("--key", help="fixed 32-byte room key in hex (default: random)")

    opn = sub.add_parser("open", help="recipient: open an e2e1 handshake line")
    opn.add_argument("line", nargs="?", help="the 'e2e1 ...' line (or pipe via stdin)")

    enc = sub.add_parser("encrypt", help="plaintext -> room line")
    enc.add_argument("text", nargs="?", help="message text (or pipe via stdin)")
    dec = sub.add_parser("decrypt", help="room line -> plaintext")
    dec.add_argument("line", nargs="?",
                     help="the '<nonce>.<ct>' room line (or pipe via stdin)")

    sub.add_parser("selftest", help="run the full two-party round trip offline")
    return parser


HANDLERS = {
    "identity": cmd_identity,
    "note": cmd_note,
    "seal": cmd_seal,
    "open": cmd_open,
    "encrypt": cmd_encrypt,
    "decrypt": cmd_decrypt,
    "selftest": cmd_selftest,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return HANDLERS[args.command](args)
    except E2EError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("cancelled", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
