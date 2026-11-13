#!/usr/bin/env python3
"""Frozen identity-backup self-test for the fork release.

Runs inside a normal interpreter or a cx_Freeze build. Prints pass/fail
lines only. Does not print passphrases, private keys, service ids, onion
addresses, or backup text.
"""

import base64
import hashlib
import importlib.resources
import json
import os
import sys
import tempfile

import nacl.bindings
import nacl.public
import nacl.signing

from onionshare_cli.identity_backup import (
    IdentityBackupError,
    decrypt_identity,
    encrypt_identity,
    generate_passphrase,
    validate_identity,
)

GENERIC = "wrong passphrase or damaged backup"


def _sodium_basename():
    import glob

    import nacl._sodium as sodium

    path = getattr(sodium, "__file__", None) or ""
    if path:
        return os.path.basename(path)
    hits = []
    for entry in sys.path:
        if entry and os.path.isdir(entry):
            hits.extend(
                glob.glob(os.path.join(entry, "**", "_sodium*"), recursive=True)
            )
    if not hits:
        return ""
    return os.path.basename(hits[0])


def _b32_key(raw):
    encoded = base64.b32encode(raw)
    if not encoded.endswith(b"===="):
        raise AssertionError("client-auth encoding was not 32 bytes")
    return encoded[:-4].decode("ascii")


def _onion_address(public_key):
    version = b"\x03"
    checksum = hashlib.sha3_256(b".onion checksum" + public_key + version).digest()[:2]
    return base64.b32encode(public_key + checksum + version).decode("ascii").lower()


def _tor_ed25519():
    """Disposable Tor ED25519-V3 blob (scalar || PRF) and its service id."""
    signing_key = nacl.signing.SigningKey.generate()
    expanded = bytearray(hashlib.sha512(bytes(signing_key)).digest())
    expanded[0] &= 248
    expanded[31] &= 127
    expanded[31] |= 64
    scalar = bytes(expanded[:32])
    public = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(scalar)
    if public != bytes(signing_key.verify_key):
        raise AssertionError("generated ed25519 public key did not match")
    service_id = _onion_address(public)
    if len(service_id) != 56 or not service_id.islower():
        raise AssertionError("generated service id had the wrong shape")
    private_key = base64.b64encode(bytes(expanded)).decode("ascii")
    return private_key, service_id


def _x25519_pair():
    private = nacl.public.PrivateKey.generate()
    priv = _b32_key(bytes(private))
    pub = _b32_key(bytes(private.public_key))
    if len(priv) != 52 or len(pub) != 52:
        raise AssertionError("client-auth key had the wrong length")
    return priv, pub


def _identity():
    private_key, service_id = _tor_ed25519()
    priv, pub = _x25519_pair()
    return {
        "mode": "share",
        "service_id": service_id,
        "private_key": private_key,
        "client_auth_priv_key": priv,
        "client_auth_pub_key": pub,
        "public": False,
    }


def _wordlist():
    resource = importlib.resources.files("onionshare_cli.resources") / "wordlist.txt"
    return resource.read_text(encoding="utf-8").split()


def _is_six_words(value, wordset):
    def match(pos, count):
        if count == 6:
            return pos == len(value)
        for word in wordset:
            end = pos + len(word)
            if not value.startswith(word, pos):
                continue
            if count == 5 and end == len(value):
                return True
            if (
                count < 5
                and end < len(value)
                and value[end] == "-"
                and match(end + 1, count + 1)
            ):
                return True
        return False

    return match(0, 0)


def _generic(err):
    return (
        type(err) is IdentityBackupError
        and str(err) == GENERIC
        and err.__cause__ is None
        and err.__context__ is None
    )


def _expect_generic(func):
    try:
        func()
    except IdentityBackupError as err:
        return _generic(err)
    except Exception:
        return False
    return False


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def main():
    failures = 0

    def check(ok, message):
        nonlocal failures
        if ok:
            print("PASS: " + message)
        else:
            failures += 1
            print("FAIL: " + message)

    frozen = bool(getattr(sys, "frozen", False))
    print("frozen=" + ("true" if frozen else "false"))

    try:
        import nacl.pwhash.argon2id  # noqa: F401
        import nacl.secret  # noqa: F401

        sodium_basename = _sodium_basename()
    except Exception:
        print("FAIL: nacl.pwhash.argon2id, nacl.secret, or nacl._sodium did not import")
        print("SELFTEST FAILED")
        return 1
    check(bool(sodium_basename) and "_sodium" in sodium_basename, "nacl._sodium imported")
    if sodium_basename:
        print("nacl._sodium_basename=" + sodium_basename)

    try:
        identity = _identity()
        checked = validate_identity(identity)
    except Exception:
        print("FAIL: validate_identity rejected the disposable identity")
        print("SELFTEST FAILED")
        return 1
    check(checked == identity, "service-id and client-auth pair validated")

    bad_service = dict(identity)
    replacement = "b" if bad_service["service_id"][-1:] != "b" else "c"
    bad_service["service_id"] = bad_service["service_id"][:-1] + replacement
    check(
        _expect_generic(lambda: validate_identity(bad_service)),
        "service-id mismatch fails generically",
    )

    bad_client = dict(identity)
    bad_client["client_auth_pub_key"] = bad_client["client_auth_priv_key"]
    check(
        _expect_generic(lambda: validate_identity(bad_client)),
        "client-auth mismatch fails generically",
    )

    try:
        words = set(_wordlist())
        passphrase = generate_passphrase()
    except Exception:
        print("FAIL: could not load the wordlist or generate a passphrase")
        print("SELFTEST FAILED")
        return 1
    check(
        " " not in passphrase
        and "\n" not in passphrase
        and _is_six_words(passphrase, words),
        "passphrase is six wordlist entries",
    )

    try:
        envelope = encrypt_identity(identity, passphrase)
    except IdentityBackupError:
        print("FAIL: encrypt_identity rejected the disposable identity")
        print("SELFTEST FAILED")
        return 1
    except Exception as err:
        print("FAIL: encrypt_identity raised " + type(err).__name__)
        print("SELFTEST FAILED")
        return 1

    check(passphrase not in envelope, "passphrase is absent from the envelope")
    try:
        parsed = json.loads(envelope)
    except Exception:
        print("FAIL: envelope was not JSON")
        print("SELFTEST FAILED")
        return 1
    check(
        parsed.get("v") == 1
        and parsed.get("kdf") == "argon2id"
        and parsed.get("t") == 2
        and parsed.get("m") == 67108864
        and parsed.get("p") == 1
        and _canonical(parsed) == envelope,
        "envelope pins argon2id t=2 m=67108864 p=1",
    )

    path = None
    try:
        handle = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8")
        path = handle.name
        handle.write(envelope)
        handle.close()
        with open(path, encoding="utf-8") as handle:
            file_text = handle.read()
    except Exception:
        print("FAIL: could not round-trip the backup file")
        print("SELFTEST FAILED")
        return 1
    finally:
        if path and os.path.exists(path):
            os.remove(path)
    check(file_text == envelope, "backup file text matches the envelope")

    try:
        restored = decrypt_identity(envelope, passphrase)
    except Exception:
        print("FAIL: decrypt_identity did not return the identity")
        print("SELFTEST FAILED")
        return 1
    check(restored == checked, "decrypt matches the validated identity")

    check(
        _expect_generic(lambda: decrypt_identity(envelope, passphrase + "x")),
        "wrong passphrase fails generically",
    )

    tampered = dict(parsed)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    chars = list(tampered.get("ct") or "")
    flipped = False
    for index, char in enumerate(chars):
        if char in alphabet:
            chars[index] = alphabet[(alphabet.index(char) + 1) % len(alphabet)]
            flipped = True
            break
    tampered["ct"] = "".join(chars)
    tampered_text = _canonical(tampered)
    check(flipped and tampered_text != envelope, "tamper changed the envelope")
    check(
        _expect_generic(lambda: decrypt_identity(tampered_text, passphrase)),
        "tampered backup fails generically",
    )

    import onionshare_cli.identity_backup as identity_backup

    qr_names = [name for name in dir(identity_backup) if "qr" in name.lower()]
    if qr_names:
        check(False, "unexpected identity-backup QR helper; not calling it")
    else:
        print(
            "NOT PERFORMED: QR text equals backup file text "
            "(onionshare_cli.identity_backup has no QR helper)"
        )

    if failures:
        print("SELFTEST FAILED")
        return 1
    print("SELFTEST PASSED")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as err:
        print("FAIL: uncaught " + type(err).__name__)
        print("SELFTEST FAILED")
        sys.exit(1)
