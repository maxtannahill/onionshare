# -*- coding: utf-8 -*-
"""Tests for the v1 encrypted identity backup envelope."""

import base64
import hashlib
import importlib.resources
import json
import random

import nacl.bindings
import nacl.public
import nacl.pwhash.argon2id
import nacl.secret
import nacl.signing
import pytest

from onionshare_cli.identity_backup import (
    IdentityBackupError,
    decrypt_identity,
    encrypt_identity,
    generate_passphrase,
    identity_from_mode_settings,
    validate_identity,
)

GENERIC = "wrong passphrase or damaged backup"
WORDLIST_SHA256 = (
    "6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522"
)
HYPHENATED_WORDS = {"drop-down", "felt-tip", "t-shirt", "yo-yo"}
B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _wordlist_text():
    resource = importlib.resources.files("onionshare_cli.resources") / "wordlist.txt"
    return resource.read_text(encoding="utf-8")


def _wordlist():
    return _wordlist_text().split()


def _b32_key(raw):
    encoded = base64.b32encode(raw)
    assert encoded[-4:] == b"===="
    return encoded[:-4].decode("ascii")


def _x25519_pair():
    private = nacl.public.PrivateKey.generate()
    priv = _b32_key(bytes(private))
    pub = _b32_key(bytes(private.public_key))
    assert len(priv) == 52 and len(pub) == 52
    return priv, pub


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


def _identity(mode="share", public=False, client_auth=True):
    private_key, service_id = _tor_ed25519()
    if client_auth:
        priv, pub = _x25519_pair()
    else:
        priv = pub = None
    return {
        "mode": mode,
        "service_id": service_id,
        "private_key": private_key,
        "client_auth_priv_key": priv,
        "client_auth_pub_key": pub,
        "public": public,
    }


def _same_identity(left, right):
    keys = (
        "mode",
        "service_id",
        "private_key",
        "client_auth_priv_key",
        "client_auth_pub_key",
        "public",
    )
    if set(left) != set(keys) or set(right) != set(keys):
        return False
    return all(left[key] == right[key] for key in keys)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _skeleton(**overrides):
    envelope = {
        "v": 1,
        "kdf": "argon2id",
        "t": 2,
        "m": 67108864,
        "p": 1,
        "salt": base64.b64encode(b"\x11" * 16).decode("ascii"),
        "n": base64.b64encode(b"\x22" * 24).decode("ascii"),
        "ct": base64.b64encode(b"\x33" * 17).decode("ascii"),
    }
    envelope.update(overrides)
    return envelope


def _dumps(envelope):
    return _canonical(envelope)


def _expect_generic(func):
    try:
        func()
    except IdentityBackupError as err:
        return err
    except Exception as err:
        raise AssertionError("unexpected " + type(err).__name__) from None
    raise AssertionError("no error")


def _assert_generic(err):
    assert type(err) is IdentityBackupError
    assert str(err) == GENERIC
    assert err.args == (GENERIC,)
    assert err.__cause__ is None


def _block_kdf(monkeypatch):
    calls = []

    def spy(*args, **kwargs):
        calls.append((args, kwargs))
        return b"\x00" * 32

    monkeypatch.setattr(
        "onionshare_cli.identity_backup.argon2id.kdf",
        spy,
    )
    return calls


def _flip_unused_b64_bits(value):
    """Change only unused bits of a padded standard-base64 string."""
    core = value.rstrip("=")
    padding = value[len(core) :]
    index = B64_ALPHABET.index(core[-1])
    flipped = core[:-1] + B64_ALPHABET[index ^ 1] + padding
    assert flipped != value
    return flipped


def _seal(plaintext, passphrase):
    salt = b"\x41" * 16
    nonce = b"\x42" * 24
    key = nacl.pwhash.argon2id.kdf(
        32,
        passphrase.strip().encode("utf-8"),
        salt,
        opslimit=2,
        memlimit=67108864,
    )
    ciphertext = nacl.secret.SecretBox(key).encrypt(plaintext, nonce).ciphertext
    return _dumps(
        {
            "v": 1,
            "kdf": "argon2id",
            "t": 2,
            "m": 67108864,
            "p": 1,
            "salt": base64.b64encode(salt).decode("ascii"),
            "n": base64.b64encode(nonce).decode("ascii"),
            "ct": base64.b64encode(ciphertext).decode("ascii"),
        }
    )


def _flip_field(envelope_text, field):
    envelope = json.loads(envelope_text)
    raw = bytearray(base64.b64decode(envelope[field]))
    raw[0] ^= 0x01
    envelope[field] = base64.b64encode(bytes(raw)).decode("ascii")
    return _canonical(envelope)


class TestWordlistAndPassphrase:
    def test_wordlist_is_the_eff_long_list(self):
        text = _wordlist_text()
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        assert digest == WORDLIST_SHA256
        lines = text.splitlines()
        words = text.split()
        assert lines[-1] != ""
        assert len(lines) == 7776
        assert len(words) == 7776
        assert len(set(words)) == 7776
        assert set(word for word in words if "-" in word) == HYPHENATED_WORDS

    def test_generate_passphrase_uses_system_random(self, monkeypatch):
        created = []

        class RecordingSystemRandom(random.SystemRandom):
            def __init__(self):
                super().__init__()
                self.calls = []
                created.append(self)

            def choice(self, seq):
                self.calls.append(seq)
                return "abacus"

        monkeypatch.setattr(
            "onionshare_cli.identity_backup.random.SystemRandom",
            RecordingSystemRandom,
        )
        passphrase = generate_passphrase()
        assert created
        assert sum(len(rng.calls) for rng in created) == 6
        assert all(isinstance(rng, random.SystemRandom) for rng in created)
        assert all(list(call) == _wordlist() for rng in created for call in rng.calls)
        assert passphrase == "abacus-abacus-abacus-abacus-abacus-abacus"

    def test_generated_passphrase_is_six_wordlist_entries(self):
        words = _wordlist()
        wordset = set(words)
        passphrase = generate_passphrase()

        def is_six_words(value):
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

        ok = is_six_words(passphrase)
        assert ok is True
        assert " " not in passphrase
        assert "\n" not in passphrase

    def test_short_wordlist_is_asserted(self, monkeypatch):
        class _Resource:
            def read_text(self, encoding="utf-8"):
                return "one\ntwo\n"

        class _Root:
            def __truediv__(self, _name):
                return _Resource()

        monkeypatch.setattr(
            "onionshare_cli.identity_backup.importlib.resources.files",
            lambda _package: _Root(),
        )
        with pytest.raises(AssertionError):
            generate_passphrase()


class TestValidateIdentity:
    def test_public_false_requires_client_auth_pair(self):
        identity = _identity(public=False, client_auth=True)
        checked = validate_identity(identity)
        assert _same_identity(checked, identity)
        assert checked is not identity

        identity["client_auth_priv_key"] = None
        identity["client_auth_pub_key"] = None
        _assert_generic(_expect_generic(lambda: validate_identity(identity)))

    def test_public_true_accepts_null_pair_and_real_pair(self):
        null_keys = _identity("chat", public=True, client_auth=False)
        assert _same_identity(validate_identity(null_keys), null_keys)
        with_keys = _identity("website", public=True, client_auth=True)
        assert _same_identity(validate_identity(with_keys), with_keys)

    def test_mode_outside_the_four_server_modes_is_rejected(self):
        for mode in ("download", "share ", "Share", "", None, 1):
            identity = _identity()
            identity["mode"] = mode
            _assert_generic(_expect_generic(lambda: validate_identity(identity)))

    def test_extra_and_missing_identity_keys_are_rejected(self):
        for extra in ("filenames", "data_dir", "title"):
            identity = _identity()
            identity[extra] = []
            _assert_generic(_expect_generic(lambda: validate_identity(identity)))
        identity = _identity()
        del identity["public"]
        _assert_generic(_expect_generic(lambda: validate_identity(identity)))
        _assert_generic(_expect_generic(lambda: validate_identity([])))
        _assert_generic(_expect_generic(lambda: validate_identity(None)))

    def test_encoder_rejects_filenames_and_data_dir_without_kdf(self, monkeypatch):
        calls = _block_kdf(monkeypatch)
        for extra, value in (("filenames", ["/tmp/secret"]), ("data_dir", "/tmp")):
            identity = _identity()
            identity[extra] = value
            _assert_generic(
                _expect_generic(lambda: encrypt_identity(identity, "passphrase"))
            )
        assert calls == []

    def test_non_canonical_base64_private_key_is_rejected(self):
        identity = _identity()
        canonical = identity["private_key"]
        identity["private_key"] = canonical[:-1]
        _assert_generic(_expect_generic(lambda: validate_identity(identity)))

        identity = _identity()
        identity["private_key"] = _flip_unused_b64_bits(identity["private_key"])
        _assert_generic(_expect_generic(lambda: validate_identity(identity)))

        identity = _identity()
        canonical = identity["private_key"]
        identity["private_key"] = "ED25519-V3:" + canonical
        _assert_generic(_expect_generic(lambda: validate_identity(identity)))

        identity = _identity()
        canonical = identity["private_key"]
        if "+" in canonical:
            identity["private_key"] = canonical.replace("+", "-", 1)
        elif "/" in canonical:
            identity["private_key"] = canonical.replace("/", "_", 1)
        else:
            identity["private_key"] = "-" + canonical[1:]
        _assert_generic(_expect_generic(lambda: validate_identity(identity)))

    def test_wrong_length_private_key_and_service_id_are_rejected(self):
        identity = _identity()
        raw = base64.b64decode(identity["private_key"])
        for size in (63, 65):
            identity = _identity()
            identity["private_key"] = base64.b64encode(b"\x01" * size).decode("ascii")
            _assert_generic(_expect_generic(lambda: validate_identity(identity)))
        identity = _identity()
        identity["service_id"] = identity["service_id"][:-1]
        _assert_generic(_expect_generic(lambda: validate_identity(identity)))
        identity = _identity()
        identity["service_id"] = identity["service_id"] + "a"
        _assert_generic(_expect_generic(lambda: validate_identity(identity)))
        identity = _identity()
        identity["service_id"] = identity["service_id"].upper()
        _assert_generic(_expect_generic(lambda: validate_identity(identity)))
        identity = _identity()
        identity["service_id"] = "a" * 49 + ".onion"
        _assert_generic(_expect_generic(lambda: validate_identity(identity)))
        assert len(raw) == 64

    def test_non_canonical_and_wrong_length_client_auth_are_rejected(self):
        identity = _identity()
        identity["client_auth_priv_key"] = identity["client_auth_priv_key"].lower()
        _assert_generic(_expect_generic(lambda: validate_identity(identity)))

        identity = _identity()
        identity["client_auth_pub_key"] = identity["client_auth_pub_key"] + "===="
        _assert_generic(_expect_generic(lambda: validate_identity(identity)))

        identity = _identity()
        raw = base64.b32decode(identity["client_auth_priv_key"] + "====")
        encoded = base64.b32encode(raw).decode("ascii")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        body = encoded[:-4]
        flipped = body[:-1] + alphabet[alphabet.index(body[-1]) ^ 1]
        identity["client_auth_priv_key"] = flipped
        _assert_generic(_expect_generic(lambda: validate_identity(identity)))

        identity = _identity()
        short = base64.b32encode(b"\x01" * 31).decode("ascii").rstrip("=")
        identity["client_auth_priv_key"] = short
        _assert_generic(_expect_generic(lambda: validate_identity(identity)))

    def test_mismatched_client_auth_pair_is_rejected(self):
        identity = _identity()
        other_priv, other_pub = _x25519_pair()
        identity["client_auth_pub_key"] = other_pub
        _assert_generic(_expect_generic(lambda: validate_identity(identity)))
        identity = _identity()
        identity["client_auth_priv_key"] = other_priv
        _assert_generic(_expect_generic(lambda: validate_identity(identity)))
        identity = _identity()
        identity["client_auth_pub_key"] = None
        _assert_generic(_expect_generic(lambda: validate_identity(identity)))

    def test_public_must_be_a_boolean(self):
        for value in (0, 1, "false", "true", None):
            identity = _identity()
            identity["public"] = value
            _assert_generic(_expect_generic(lambda: validate_identity(identity)))

    def test_service_id_must_match_the_tor_scalar(self):
        identity = _identity()
        service_id = identity["service_id"]
        replacement = "a" if service_id[-1] != "a" else "b"
        identity["service_id"] = service_id[:-1] + replacement
        _assert_generic(_expect_generic(lambda: validate_identity(identity)))

        identity = _identity()
        raw = bytearray(base64.b64decode(identity["private_key"]))
        raw[10] ^= 0x01
        identity["private_key"] = base64.b64encode(bytes(raw)).decode("ascii")
        _assert_generic(_expect_generic(lambda: validate_identity(identity)))

    def test_seed_concatenated_with_pubkey_is_not_a_tor_blob(self):
        signing_key = nacl.signing.SigningKey.generate()
        seed = bytes(signing_key)
        public = bytes(signing_key.verify_key)
        identity = _identity(public=True, client_auth=False)
        identity["private_key"] = base64.b64encode(seed + public).decode("ascii")
        identity["service_id"] = _onion_address(public)
        _assert_generic(_expect_generic(lambda: validate_identity(identity)))

    def test_identity_from_mode_settings_reads_only_six_fields(self):
        identity = _identity("receive", public=False, client_auth=True)

        class Reader:
            def __init__(self):
                self.seen = []

            def get(self, group, key):
                self.seen.append((group, key))
                values = {
                    ("persistent", "mode"): identity["mode"],
                    ("general", "service_id"): identity["service_id"],
                    ("onion", "private_key"): identity["private_key"],
                    ("onion", "client_auth_priv_key"): identity["client_auth_priv_key"],
                    ("onion", "client_auth_pub_key"): identity["client_auth_pub_key"],
                    ("general", "public"): identity["public"],
                }
                if (group, key) not in values:
                    raise AssertionError("unexpected field")
                return values[(group, key)]

        reader = Reader()
        copied = identity_from_mode_settings(reader)
        assert _same_identity(copied, identity)
        assert set(reader.seen) == {
            ("persistent", "mode"),
            ("general", "service_id"),
            ("onion", "private_key"),
            ("onion", "client_auth_priv_key"),
            ("onion", "client_auth_pub_key"),
            ("general", "public"),
        }
        assert len(reader.seen) == 6

    def test_identity_from_mode_settings_failures_are_generic(self):
        class Broken:
            def get(self, _group, _key):
                raise KeyError("private_key")

        err = _expect_generic(lambda: identity_from_mode_settings(Broken()))
        _assert_generic(err)

        class Empty:
            def get(self, _group, _key):
                return None

        _assert_generic(_expect_generic(lambda: identity_from_mode_settings(Empty())))


class TestEnvelopeParsing:
    def test_booleans_and_unpinned_params_do_not_run_kdf(self, monkeypatch):
        calls = _block_kdf(monkeypatch)
        cases = []
        for field in ("v", "t", "m", "p"):
            cases.append(_dumps(_skeleton(**{field: True})))
        cases.extend(
            [
                _dumps(_skeleton(v=2)),
                _dumps(_skeleton(v=0)),
                _dumps(_skeleton(v=1.0)),
                _dumps(_skeleton(kdf="argon2i")),
                _dumps(_skeleton(kdf="Argon2id")),
                _dumps(_skeleton(kdf="scrypt")),
                _dumps(_skeleton(t=4)),
                _dumps(_skeleton(t=1)),
                _dumps(_skeleton(m=1073741824)),
                _dumps(_skeleton(m=65536)),
                _dumps(_skeleton(p=2)),
                _dumps(_skeleton(p=0)),
                _dumps(_skeleton()).replace('"t":2', '"t":NaN'),
                _dumps(_skeleton()).replace('"m":67108864', '"m":Infinity'),
            ]
        )
        for text in cases:
            _assert_generic(_expect_generic(lambda: decrypt_identity(text, "pw")))
        assert calls == []

    def test_duplicate_extra_and_missing_outer_keys_do_not_run_kdf(self, monkeypatch):
        calls = _block_kdf(monkeypatch)
        base = _dumps(_skeleton())
        duplicate = base.replace('"v":1', '"v":1,"v":1', 1)
        differing = base.replace('"kdf":"argon2id"', '"kdf":"argon2id","kdf":"scrypt"', 1)
        extra = base[:-1] + ',"extra":1}'
        missing = base.replace('"p":1,', "", 1)
        for text in (
            duplicate,
            differing,
            extra,
            missing,
            "[]",
            "null",
            '"text"',
            "1",
            "true",
            "",
        ):
            _assert_generic(_expect_generic(lambda: decrypt_identity(text, "pw")))
        assert calls == []

    def test_non_canonical_base64_envelope_fields_do_not_run_kdf(self, monkeypatch):
        calls = _block_kdf(monkeypatch)
        salt = _skeleton()["salt"]
        nonce = _skeleton()["n"]
        ct = _skeleton()["ct"]
        texts = [
            _dumps(_skeleton(salt=salt[:-1])),
            _dumps(_skeleton(salt=_flip_unused_b64_bits(salt))),
            _dumps(_skeleton(salt=salt[:4] + "\n" + salt[4:])),
            _dumps(_skeleton(n=nonce[:4] + "\n" + nonce[4:])),
            _dumps(_skeleton(n=nonce + "=")),
            _dumps(_skeleton(ct=ct[:-1])),
            _dumps(_skeleton(ct=_flip_unused_b64_bits(ct))),
            _dumps(_skeleton(salt=base64.b64encode(b"\x11" * 15).decode("ascii"))),
            _dumps(_skeleton(n=base64.b64encode(b"\x22" * 23).decode("ascii"))),
            _dumps(_skeleton(ct=base64.b64encode(b"\x33" * 16).decode("ascii"))),
        ]
        url_salt = base64.urlsafe_b64encode(b"\xfb" * 16).decode("ascii")
        assert "-" in url_salt or "_" in url_salt
        texts.append(_dumps(_skeleton(salt=url_salt)))
        for text in texts:
            _assert_generic(_expect_generic(lambda: decrypt_identity(text, "pw")))
        assert calls == []

    def test_oversized_input_is_rejected_before_parsing(self, monkeypatch):
        kdf_calls = _block_kdf(monkeypatch)
        parses = {"n": 0}
        real_loads = json.loads

        def spy_loads(*args, **kwargs):
            parses["n"] += 1
            return real_loads(*args, **kwargs)

        monkeypatch.setattr("onionshare_cli.identity_backup.json.loads", spy_loads)
        _assert_generic(_expect_generic(lambda: decrypt_identity("x" * 8193, "pw")))
        assert parses["n"] == 0
        _assert_generic(_expect_generic(lambda: decrypt_identity("x" * 8192, "pw")))
        assert parses["n"] == 1
        assert kdf_calls == []
        _assert_generic(_expect_generic(lambda: decrypt_identity(b"{}", "pw")))
        _assert_generic(_expect_generic(lambda: decrypt_identity("{}", None)))

    def test_lone_surrogate_is_a_generic_error(self, monkeypatch):
        kdf_calls = _block_kdf(monkeypatch)
        parses = {"n": 0}
        real_loads = json.loads

        def spy_loads(*args, **kwargs):
            parses["n"] += 1
            return real_loads(*args, **kwargs)

        monkeypatch.setattr("onionshare_cli.identity_backup.json.loads", spy_loads)
        _assert_generic(_expect_generic(lambda: decrypt_identity("\ud800", "pw")))
        assert parses["n"] == 0
        assert kdf_calls == []

    def test_decrypt_passes_pinned_kdf_arguments(self, monkeypatch):
        seen = {}

        def spy(size, password, salt, opslimit=None, memlimit=None, **kwargs):
            seen["size"] = size
            seen["password"] = password
            seen["salt"] = salt
            seen["opslimit"] = opslimit
            seen["memlimit"] = memlimit
            seen["kwargs"] = kwargs
            return b"\x22" * 32

        monkeypatch.setattr("onionshare_cli.identity_backup.argon2id.kdf", spy)
        text = _dumps(_skeleton())
        err = _expect_generic(
            lambda: decrypt_identity(text, "  t-shirt-yo-yo-drop-down \n")
        )
        _assert_generic(err)
        assert seen["size"] == 32
        assert seen["opslimit"] == 2
        assert seen["memlimit"] == 67108864
        assert seen["salt"] == b"\x11" * 16
        assert seen["password"] == b"t-shirt-yo-yo-drop-down"
        assert "encoder" not in seen["kwargs"] or seen["kwargs"]["encoder"] is None

    def test_encrypt_passes_pinned_kdf_arguments_and_omits_passphrase(self, monkeypatch):
        seen = {}

        def spy(size, password, salt, opslimit=None, memlimit=None, **_kwargs):
            seen["size"] = size
            seen["password"] = password
            seen["salt_len"] = len(salt)
            seen["opslimit"] = opslimit
            seen["memlimit"] = memlimit
            return b"\x7f" * 32

        monkeypatch.setattr("onionshare_cli.identity_backup.argon2id.kdf", spy)
        identity = _identity(public=True, client_auth=False)
        passphrase = "t-shirt-yo-yo-drop-down-felt-tip-abacus-zoom"
        text = encrypt_identity(identity, "  " + passphrase + "\n")
        assert seen["size"] == 32
        assert seen["opslimit"] == 2
        assert seen["memlimit"] == 67108864
        assert seen["salt_len"] == 16
        assert seen["password"] == passphrase.encode("utf-8")
        leaked = passphrase in text
        assert leaked is False
        assert "\n" not in text
        assert text == _canonical(json.loads(text))


class TestRoundTrip:
    @pytest.mark.parametrize(
        "mode,public,client_auth",
        (
            ("share", False, True),
            ("receive", False, True),
            ("website", True, True),
            ("chat", True, False),
        ),
    )
    def test_round_trip_for_each_mode(self, mode, public, client_auth):
        identity = _identity(mode, public=public, client_auth=client_auth)
        snapshot = dict(identity)
        passphrase = "t-shirt-yo-yo-drop-down-felt-tip-abacus-zoom"
        text = encrypt_identity(identity, passphrase)
        assert identity == snapshot
        assert type(text) is str
        assert text.endswith("\n") is False
        assert "\n" not in text
        assert " " not in text
        assert text == _canonical(json.loads(text))
        leaked = passphrase in text
        assert leaked is False
        parsed = json.loads(text)
        assert parsed["v"] == 1
        assert parsed["kdf"] == "argon2id"
        assert parsed["t"] == 2
        assert parsed["m"] == 67108864
        assert parsed["p"] == 1
        assert type(parsed["v"]) is int
        assert type(parsed["t"]) is int
        assert type(parsed["m"]) is int
        assert type(parsed["p"]) is int
        opened = decrypt_identity(text, " \t" + passphrase + "\n")
        assert _same_identity(opened, identity)

    def test_structure_is_deterministic_for_the_same_random_bytes(self, monkeypatch):
        calls = []

        def fake_random(size):
            calls.append(size)
            return bytes([size]) * size

        monkeypatch.setattr("onionshare_cli.identity_backup.nacl.utils.random", fake_random)
        identity = _identity("website", public=False, client_auth=True)
        passphrase = "correct horse battery staple does not apply"
        first = encrypt_identity(identity, passphrase)
        second = encrypt_identity(identity, passphrase)
        assert calls == [16, 24, 16, 24]
        assert first == second
        assert first.endswith("\n") is False
        parsed = json.loads(first)
        assert first.startswith('{"ct":')
        assert parsed["salt"] == base64.b64encode(bytes([16]) * 16).decode("ascii")
        assert parsed["n"] == base64.b64encode(bytes([24]) * 24).decode("ascii")
        opened = decrypt_identity(first, passphrase)
        assert _same_identity(opened, identity)

    def test_crypto_failures_share_one_error(self):
        identity = _identity("share", public=False, client_auth=True)
        passphrase = "one-time-backup-phrase"
        text = encrypt_identity(identity, passphrase)
        failures = [
            _expect_generic(lambda: decrypt_identity(text, "wrong-passphrase")),
            _expect_generic(lambda: decrypt_identity(_flip_field(text, "ct"), passphrase)),
            _expect_generic(lambda: decrypt_identity(_flip_field(text, "salt"), passphrase)),
            _expect_generic(lambda: decrypt_identity(_flip_field(text, "n"), passphrase)),
        ]
        for err in failures:
            _assert_generic(err)
        assert len({(type(err), str(err), err.args) for err in failures}) == 1

    def test_valid_envelope_with_a_duplicate_outer_key_is_rejected(self):
        identity = _identity(public=True, client_auth=False)
        passphrase = "duplicate-outer-key"
        text = encrypt_identity(identity, passphrase)
        duplicate = text.replace('"v":1', '"v":1,"v":1', 1)
        assert duplicate != text
        err = _expect_generic(lambda: decrypt_identity(duplicate, passphrase))
        _assert_generic(err)

    def test_inner_duplicate_and_extra_keys_are_rejected(self):
        identity = _identity("chat", public=True, client_auth=False)
        passphrase = "inner-plaintext"
        canonical = _canonical(identity)
        duplicate = '{"mode":"chat",' + canonical[1:]
        extra = canonical[:-1] + ',"filenames":[]}'
        for plaintext in (duplicate, extra):
            envelope = _seal(plaintext.encode("utf-8"), passphrase)
            err = _expect_generic(lambda: decrypt_identity(envelope, passphrase))
            _assert_generic(err)

    def test_module_does_not_log_secrets(self):
        import pathlib

        import onionshare_cli.identity_backup as module

        source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
        assert "common.log" not in source
        assert "print(" not in source
        assert "logging." not in source


_STUB_PASSPHRASE = "w4-stub-passphrase-value"
_PLAINTEXT_MARKER = "W4PLAINTEXTMARKER"


def _fast_kdf(size, password, salt, opslimit=None, memlimit=None, **kwargs):
    if isinstance(password, str):
        password = password.encode("utf-8")
    digest = hashlib.blake2s(bytes(password) + bytes(salt), digest_size=32).digest()
    return digest[:size]


def _envelope_over(plaintext, passphrase):
    salt = b"\x51" * 16
    nonce = b"\x52" * 24
    key = _fast_kdf(32, passphrase.strip().encode("utf-8"), salt)
    ciphertext = nacl.secret.SecretBox(key).encrypt(plaintext, nonce).ciphertext
    return _dumps(
        {
            "v": 1,
            "kdf": "argon2id",
            "t": 2,
            "m": 67108864,
            "p": 1,
            "salt": base64.b64encode(salt).decode("ascii"),
            "n": base64.b64encode(nonce).decode("ascii"),
            "ct": base64.b64encode(ciphertext).decode("ascii"),
        }
    )


def _inspect_failure(err):
    passphrase = _STUB_PASSPHRASE
    marker = _PLAINTEXT_MARKER
    if err is None or type(err) is not IdentityBackupError or str(err) != GENERIC:
        raise AssertionError("expected the generic identity backup error")
    if err.__context__ is not None or err.__cause__ is not None:
        raise AssertionError("generic error is chained")
    tb = err.__traceback__
    while tb is not None:
        filename = tb.tb_frame.f_code.co_filename
        if filename.endswith("/identity_backup.py") and _frame_holds_secret(
            tb.tb_frame, (passphrase, marker)
        ):
            raise AssertionError(
                "traceback frame holds a secret local: "
                + tb.tb_frame.f_code.co_name
            )
        tb = tb.tb_next
    passphrase = None
    marker = None


def _frame_holds_secret(frame, secrets):
    seen = set()

    def holds(value):
        if id(value) in seen:
            return False
        seen.add(id(value))
        if isinstance(value, str):
            return any(secret in value for secret in secrets)
        if isinstance(value, (bytes, bytearray)):
            return any(secret.encode("utf-8") in value for secret in secrets)
        if isinstance(value, dict):
            return any(holds(item) for item in value.values())
        if isinstance(value, (list, tuple)):
            return any(holds(item) for item in value)
        return False

    return any(holds(value) for value in frame.f_locals.values())


class TestGenericErrorDoesNotChainSecrets:
    def test_failures_have_no_context_cause_or_secret_locals(self, monkeypatch):
        monkeypatch.setattr(
            "onionshare_cli.identity_backup.argon2id.kdf",
            _fast_kdf,
        )
        good = _envelope_over(
            _canonical(
                _identity("share", public=True, client_auth=False)
            ).encode("utf-8"),
            _STUB_PASSPHRASE,
        )
        flipped = _flip_field(good, "ct")
        truncated = _envelope_over(
            ('{"marker":"' + _PLAINTEXT_MARKER).encode("utf-8"),
            _STUB_PASSPHRASE,
        )
        non_utf8 = _envelope_over(
            b"\xff" + _PLAINTEXT_MARKER.encode("utf-8") + b"\xfe",
            _STUB_PASSPHRASE,
        )
        wrong = (good, "not-the-stub-passphrase")
        same = (flipped, _STUB_PASSPHRASE)
        cases = (
            ("{", _STUB_PASSPHRASE),
            (_dumps(_skeleton(salt="!!!!")), _STUB_PASSPHRASE),
            ("\ud800", _STUB_PASSPHRASE),
            wrong,
            same,
            (truncated, _STUB_PASSPHRASE),
            (non_utf8, _STUB_PASSPHRASE),
        )
        seen = []
        for text, passphrase in cases:
            seen.append(_raise_clean(text, passphrase))
        if {(type(err), str(err)) for err in seen} != {(IdentityBackupError, GENERIC)}:
            raise AssertionError("wrong passphrase and tamper were distinguished")


def _raise_clean(text, passphrase):
    err = None
    try:
        decrypt_identity(text, passphrase)
    except IdentityBackupError as caught:
        err = caught
    text = None
    passphrase = None
    _inspect_failure(err)
    return err
