# -*- coding: utf-8 -*-
"""
OnionShare | https://onionshare.org/

Copyright (C) 2014-2022 Micah Lee, et al. <micah@micahflee.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import base64
import hashlib
import importlib.resources
import json
import random
import re

import nacl.bindings
import nacl.public
import nacl.pwhash.argon2id as argon2id
import nacl.secret
import nacl.utils


# v1 envelope. Canonical JSON, no trailing newline. The passphrase never
# appears in the envelope. Argon2id is pinned to the interactive parameters
# (opslimit 2, memlimit 67108864). Libsodium's parallelism is fixed at 1, so
# readers require p == 1 and the KDF call does not take a parallelism argument.
#
# The onion private key is the Tor ED25519-V3 blob: 32-byte secret scalar
# followed by 32-byte PRF secret, standard base64, not a seed concatenated
# with a public key. The service id is checked by multiplying that scalar
# (nacl.bindings.crypto_scalarmult_ed25519_base_noclamp) and comparing the
# rend-spec-v3 address. PyNaCl's SigningKey cannot load this blob because the
# seed is not stored. The PRF half cannot be checked for the same reason.
# The address checksum is SHA3-256 from hashlib; nacl.hash has no SHA3.

_IDENTITY_KEYS = frozenset(
    {
        "mode",
        "service_id",
        "private_key",
        "client_auth_priv_key",
        "client_auth_pub_key",
        "public",
    }
)
_ENVELOPE_KEYS = frozenset({"v", "kdf", "t", "m", "p", "salt", "n", "ct"})
_MODES = frozenset({"share", "receive", "website", "chat"})
_SERVICE_ID_RE = re.compile(r"[a-z2-7]{56}\Z")
_B32_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

_VERSION = 1
_KDF_NAME = "argon2id"
_KDF_SIZE = 32
_KDF_OPSLIMIT = 2
_KDF_MEMLIMIT = 67108864
_KDF_PARALLELISM = 1
_SALT_BYTES = 16
_NONCE_BYTES = 24
_PRIVATE_KEY_BYTES = 64
_CLIENT_AUTH_BYTES = 32
_CLIENT_AUTH_CHARS = 52
_MIN_CIPHERTEXT_BYTES = 17
_MAX_INPUT_BYTES = 8192
_WORDLIST_SIZE = 7776
_PASSPHRASE_WORDS = 6
_ONION_CHECKSUM_PREFIX = b".onion checksum"
_ONION_VERSION = b"\x03"

__all__ = [
    "IdentityBackupError",
    "decrypt_identity",
    "encrypt_identity",
    "generate_passphrase",
    "identity_from_mode_settings",
    "validate_identity",
]


class IdentityBackupError(Exception):
    """Wrong passphrase or damaged backup.

    Every decrypt, parse, and validation failure uses this type and this
    message. Callers cannot tell those causes apart.
    """

    _MESSAGE = "wrong passphrase or damaged backup"

    def __init__(self):
        super().__init__(self._MESSAGE)


def _reject():
    raise IdentityBackupError()


def _canonical_json(obj):
    """Return canonical UTF-8 JSON text with no trailing newline."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def _parse_json_object(text):
    """Parse one JSON object, rejecting duplicates, NaN, and non-objects."""

    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                _reject()
            obj[key] = value
        return obj

    def reject_constant(_constant):
        _reject()

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
        )
    except IdentityBackupError:
        raise
    except Exception:
        raise IdentityBackupError() from None
    if not isinstance(value, dict):
        _reject()
    return value


def _pinned_int(value, expected):
    # bool is a subclass of int; JSON true/false must not pass as 1/0.
    if type(value) is not int or value != expected:
        _reject()


def _decode_canonical_b64(value, exact_len=None, min_len=None):
    """Decode standard base64 that re-encodes to the same string."""
    if type(value) is not str:
        _reject()
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        raise IdentityBackupError() from None
    if base64.b64encode(raw).decode("ascii") != value:
        _reject()
    if exact_len is not None and len(raw) != exact_len:
        _reject()
    if min_len is not None and len(raw) < min_len:
        _reject()
    return raw


def _decode_canonical_client_auth(value):
    """Decode uppercase unpadded base32 that is exactly 32 bytes."""
    if type(value) is not str or len(value) != _CLIENT_AUTH_CHARS:
        _reject()
    if any(char not in _B32_ALPHABET for char in value):
        _reject()
    padded = value + "===="
    try:
        raw = base64.b32decode(padded, casefold=False)
    except Exception:
        raise IdentityBackupError() from None
    if len(raw) != _CLIENT_AUTH_BYTES:
        _reject()
    if base64.b32encode(raw).decode("ascii") != padded:
        _reject()
    return raw


def _service_id_from_private_key(blob):
    """Return the v3 onion id for a Tor ED25519-V3 private key blob."""
    if len(blob) != _PRIVATE_KEY_BYTES:
        _reject()
    try:
        public_key = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(blob[:32])
    except Exception:
        raise IdentityBackupError() from None
    if len(public_key) != 32:
        _reject()
    checksum = hashlib.sha3_256(
        _ONION_CHECKSUM_PREFIX + public_key + _ONION_VERSION
    ).digest()[:2]
    address = base64.b32encode(public_key + checksum + _ONION_VERSION).decode("ascii")
    return address.lower()


def _client_auth_pair(priv, pub, is_public):
    if priv is None and pub is None:
        if not is_public:
            _reject()
        return None, None
    if type(priv) is not str or type(pub) is not str:
        _reject()
    priv_raw = _decode_canonical_client_auth(priv)
    pub_raw = _decode_canonical_client_auth(pub)
    try:
        derived = bytes(nacl.public.PrivateKey(priv_raw).public_key)
    except Exception:
        raise IdentityBackupError() from None
    if derived != pub_raw:
        _reject()
    return priv, pub


def _validate_identity(identity):
    if not isinstance(identity, dict) or set(identity) != _IDENTITY_KEYS:
        _reject()

    public = identity["public"]
    if type(public) is not bool:
        _reject()

    mode = identity["mode"]
    if type(mode) is not str or mode not in _MODES:
        _reject()

    service_id = identity["service_id"]
    if type(service_id) is not str or _SERVICE_ID_RE.fullmatch(service_id) is None:
        _reject()

    private_raw = _decode_canonical_b64(
        identity["private_key"], exact_len=_PRIVATE_KEY_BYTES
    )
    if _service_id_from_private_key(private_raw) != service_id:
        _reject()

    client_priv, client_pub = _client_auth_pair(
        identity["client_auth_priv_key"],
        identity["client_auth_pub_key"],
        public,
    )
    # Keep the caller's strings. They already matched the canonical encoding,
    # so restoring them does not re-encode the onion key.
    return {
        "mode": mode,
        "service_id": service_id,
        "private_key": identity["private_key"],
        "client_auth_priv_key": client_priv,
        "client_auth_pub_key": client_pub,
        "public": public,
    }


def _load_wordlist():
    resource = importlib.resources.files("onionshare_cli.resources") / "wordlist.txt"
    words = resource.read_text(encoding="utf-8").split()
    if len(words) != _WORDLIST_SIZE or len(set(words)) != _WORDLIST_SIZE:
        raise AssertionError("wordlist must contain 7,776 unique entries")
    return words


def _derive_key(password, salt):
    # Always pass the pinned costs. The library defaults are the 1 GiB preset.
    return argon2id.kdf(
        _KDF_SIZE,
        password,
        salt,
        opslimit=_KDF_OPSLIMIT,
        memlimit=_KDF_MEMLIMIT,
    )


def _reject_unpinned_envelope(envelope):
    if set(envelope) != _ENVELOPE_KEYS:
        _reject()
    _pinned_int(envelope["v"], _VERSION)
    if type(envelope["kdf"]) is not str or envelope["kdf"] != _KDF_NAME:
        _reject()
    _pinned_int(envelope["t"], _KDF_OPSLIMIT)
    _pinned_int(envelope["m"], _KDF_MEMLIMIT)
    _pinned_int(envelope["p"], _KDF_PARALLELISM)


def generate_passphrase():
    """Return six wordlist entries chosen with SystemRandom, joined by '-'."""
    words = _load_wordlist()
    rng = random.SystemRandom()
    return "-".join(rng.choice(words) for _ in range(_PASSPHRASE_WORDS))


def validate_identity(identity):
    """Return a new six-key identity, or raise IdentityBackupError."""
    try:
        return _validate_identity(identity)
    except IdentityBackupError:
        raise
    except Exception:
        raise IdentityBackupError() from None


def identity_from_mode_settings(mode_settings):
    """Copy the six identity fields off a ModeSettings-like object.

    Reads persistent.mode, general.service_id, onion.private_key,
    onion.client_auth_priv_key, onion.client_auth_pub_key, and general.public.
    """
    try:
        identity = {
            "mode": mode_settings.get("persistent", "mode"),
            "service_id": mode_settings.get("general", "service_id"),
            "private_key": mode_settings.get("onion", "private_key"),
            "client_auth_priv_key": mode_settings.get("onion", "client_auth_priv_key"),
            "client_auth_pub_key": mode_settings.get("onion", "client_auth_pub_key"),
            "public": mode_settings.get("general", "public"),
        }
    except IdentityBackupError:
        raise
    except Exception:
        raise IdentityBackupError() from None
    return validate_identity(identity)


def encrypt_identity(identity, passphrase):
    """Encrypt an identity. The result is canonical JSON with no trailing newline."""
    checked = validate_identity(identity)
    if type(passphrase) is not str:
        _reject()
    try:
        password = passphrase.strip().encode("utf-8")
        salt = nacl.utils.random(_SALT_BYTES)
        nonce = nacl.utils.random(_NONCE_BYTES)
        key = _derive_key(password, salt)
        encrypted = nacl.secret.SecretBox(key).encrypt(
            _canonical_json(checked).encode("utf-8"),
            nonce,
        )
    except IdentityBackupError:
        raise
    except Exception:
        raise IdentityBackupError() from None
    envelope = {
        "v": _VERSION,
        "kdf": _KDF_NAME,
        "t": _KDF_OPSLIMIT,
        "m": _KDF_MEMLIMIT,
        "p": _KDF_PARALLELISM,
        "salt": base64.b64encode(salt).decode("ascii"),
        "n": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(encrypted.ciphertext).decode("ascii"),
    }
    return _canonical_json(envelope)


def decrypt_identity(text, passphrase):
    """Decrypt an envelope and return the validated identity."""
    if type(text) is not str or type(passphrase) is not str:
        _reject()
    # UTF-8 length is measured inside the generic handler. A lone surrogate
    # cannot be encoded and must still be IdentityBackupError, before parse.
    try:
        if (
            len(text) > _MAX_INPUT_BYTES
            or len(text.encode("utf-8")) > _MAX_INPUT_BYTES
        ):
            _reject()
    except IdentityBackupError:
        raise
    except Exception:
        raise IdentityBackupError() from None
    envelope = _parse_json_object(text)
    _reject_unpinned_envelope(envelope)
    salt = _decode_canonical_b64(envelope["salt"], exact_len=_SALT_BYTES)
    nonce = _decode_canonical_b64(envelope["n"], exact_len=_NONCE_BYTES)
    ciphertext = _decode_canonical_b64(
        envelope["ct"], min_len=_MIN_CIPHERTEXT_BYTES
    )
    try:
        password = passphrase.strip().encode("utf-8")
        key = _derive_key(password, salt)
        plaintext = nacl.secret.SecretBox(key).decrypt(ciphertext, nonce)
        decoded = plaintext.decode("utf-8")
    except IdentityBackupError:
        raise
    except Exception:
        raise IdentityBackupError() from None
    return validate_identity(_parse_json_object(decoded))
