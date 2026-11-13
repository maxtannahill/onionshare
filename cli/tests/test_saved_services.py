import base64
import hashlib
import json
import os
import stat

import nacl.public
import nacl.signing
import pytest

from onionshare_cli import common, saved_services, settings
from onionshare_cli.identity_backup import validate_identity


_SAVED_AT = "2026-11-13T03:22:00Z"
_FORBIDDEN_TOKENS = (
    b'"filenames"',
    b'"data_dir"',
    b'"webhook"',
    b'"autostart"',
    b'"title"',
    b'"persistent"',
)


def _b32(raw):
    text = base64.b32encode(raw).decode("ascii")
    assert text.endswith("====")
    return text[:-4]


def _onion_address(public_key):
    checksum = hashlib.sha3_256(
        b".onion checksum" + public_key + b"\x03"
    ).digest()[:2]
    encoded = base64.b32encode(public_key + checksum + b"\x03").decode("ascii")
    return encoded.lower()


def _client_auth_pair():
    private = nacl.public.PrivateKey.generate()
    return _b32(bytes(private)), _b32(bytes(private.public_key))


def _identity(mode="share", public=False, client_auth=None):
    """Disposable Tor v3 identity. The seed never leaves this helper."""
    seed = os.urandom(32)
    expanded = bytearray(hashlib.sha512(seed).digest())
    expanded[0] &= 248
    expanded[31] &= 127
    expanded[31] |= 64
    # Independent of the archive's scalar multiplication: derive the public
    # key from the seed with PyNaCl's signing API.
    public_key = bytes(nacl.signing.SigningKey(seed).verify_key)
    identity = {
        "mode": mode,
        "service_id": _onion_address(public_key),
        "private_key": base64.b64encode(bytes(expanded)).decode("ascii"),
        "client_auth_priv_key": None,
        "client_auth_pub_key": None,
        "public": True,
    }
    if client_auth is None and not public:
        client_auth = _client_auth_pair()
    if not public:
        identity["public"] = False
        identity["client_auth_priv_key"] = client_auth[0]
        identity["client_auth_pub_key"] = client_auth[1]
    elif client_auth is not None:
        identity["client_auth_priv_key"] = client_auth[0]
        identity["client_auth_pub_key"] = client_auth[1]
    return identity


def _canonical(record):
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _record_path(store, service_id):
    return os.path.join(
        store.common.build_data_dir(), "saved_services", service_id + ".json"
    )


def _read(path):
    with open(path, "rb") as handle:
        return handle.read()


def _settings_bytes(store):
    with open(store.settings.filename, "rb") as handle:
        return handle.read()


def _reload(store):
    fresh = settings.Settings(store.common)
    fresh.load()
    return fresh


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    _common = common.Common()
    _settings = settings.Settings(_common)
    _settings.load()
    return saved_services.SavedServices(_common, _settings)


class TestSavedServices:
    def test_module_docstring_discloses_unencrypted_archive(self):
        document = saved_services.__doc__
        assert document is not None
        lowered = document.lower()
        assert "unencrypted" in lowered
        assert "persistent" in lowered

    def test_old_settings_without_key_load_as_empty_list(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        _common = common.Common()
        path = os.path.join(_common.build_data_dir(), "onionshare.json")
        document = {
            "version": "2.7.2",
            "persistent_tabs": ["one-two-three", "four-five-six"],
            "use_stealth": True,
        }
        with open(path, "w") as handle:
            json.dump(document, handle)

        loaded = settings.Settings(_common)
        loaded.load()
        assert loaded.get("saved_services") == []
        assert loaded.get("persistent_tabs") == [
            "one-two-three",
            "four-five-six",
        ]
        assert loaded.get("use_stealth") is True

        loaded.save()
        again = settings.Settings(_common)
        again.load()
        assert again.get("persistent_tabs") == ["one-two-three", "four-five-six"]
        assert again.get("saved_services") == []
        assert again.get("use_stealth") is True

    def test_record_shape_and_archive_location(self, store):
        identity = _identity(mode="receive")
        record = store.add(identity, "Receive copy", saved_at=_SAVED_AT)
        assert set(record) == {
            "mode",
            "service_id",
            "private_key",
            "client_auth_priv_key",
            "client_auth_pub_key",
            "public",
            "label",
            "saved_at",
        }
        assert record["mode"] == "receive"
        assert record["service_id"] == identity["service_id"]
        assert record["private_key"] == identity["private_key"]
        assert record["public"] is False
        assert record["label"] == "Receive copy"
        assert record["saved_at"] == _SAVED_AT
        assert record["client_auth_priv_key"] == identity["client_auth_priv_key"]
        assert record["client_auth_pub_key"] == identity["client_auth_pub_key"]

        path = _record_path(store, identity["service_id"])
        raw = _read(path)
        assert raw == _canonical(record)
        assert not raw.endswith(b"\n")
        for token in _FORBIDDEN_TOKENS:
            assert token not in raw
        assert os.path.basename(os.path.dirname(path)) == "saved_services"
        data_dir = store.common.build_data_dir()
        assert os.path.dirname(path) == os.path.join(data_dir, "saved_services")
        assert os.path.dirname(os.path.dirname(path)) == data_dir
        persistent = os.path.join(data_dir, "persistent")
        assert not os.path.exists(
            os.path.join(persistent, identity["service_id"] + ".json")
        )
        assert os.listdir(os.path.dirname(path)) == [identity["service_id"] + ".json"]
        assert store.list() == [record]
        assert store.get(identity["service_id"]) == record

    def test_list_is_empty_before_any_record(self, store):
        assert store.list() == []
        archive = os.path.join(store.common.build_data_dir(), "saved_services")
        assert not os.path.exists(archive)

    @pytest.mark.parametrize("mode", ["share", "receive", "website", "chat"])
    def test_server_modes_round_trip(self, store, mode):
        identity = _identity(mode=mode)
        store.add(identity, mode, saved_at=_SAVED_AT)
        assert store.get(identity["service_id"])["mode"] == mode

    def test_add_writes_settings_before_returning(self, store):
        identity = _identity(mode="website")
        store.add(identity, "site", saved_at=_SAVED_AT)
        fresh = _reload(store)
        assert fresh is not store.settings
        assert fresh.get("saved_services") == [identity["service_id"]]
        assert identity["service_id"] in _settings_bytes(store).decode("utf-8")
        assert fresh.get("persistent_tabs") == []

    def test_add_without_replace_keeps_original_bytes(self, store):
        identity = _identity(mode="chat")
        store.add(identity, "original", saved_at=_SAVED_AT)
        path = _record_path(store, identity["service_id"])
        before = _read(path)
        info = os.lstat(path)
        with pytest.raises(saved_services.SavedServicesError, match="already exists"):
            store.add(identity, "other", saved_at="2026-11-13T04:00:00Z")
        assert _read(path) == before
        info_after = os.lstat(path)
        assert info_after.st_ino == info.st_ino
        assert info_after.st_mtime_ns == info.st_mtime_ns
        assert store.settings.get("saved_services") == [identity["service_id"]]
        assert _reload(store).get("saved_services") == [identity["service_id"]]

    def test_replace_flag_updates_existing_record(self, store):
        identity = _identity()
        store.add(identity, "original", saved_at=_SAVED_AT)
        replaced = store.add(
            identity,
            "updated",
            replace=True,
            saved_at="2026-11-13T05:00:00Z",
        )
        assert replaced["label"] == "updated"
        assert replaced["saved_at"] == "2026-11-13T05:00:00Z"
        assert store.get(identity["service_id"])["label"] == "updated"
        assert store.settings.get("saved_services") == [identity["service_id"]]
        assert _reload(store).get("saved_services") == [identity["service_id"]]

    def test_delete_removes_record_and_id_only(self, store):
        data_dir = store.common.build_data_dir()
        persistent = os.path.join(data_dir, "persistent")
        os.makedirs(persistent, 0o700)
        sentinel = os.path.join(persistent, "alpha-bravo-charlie.json")
        payload = b'{"persistent":{"enabled":true},"share":{"filenames":["/tmp/a"]}}\n'
        with open(sentinel, "wb") as handle:
            handle.write(payload)
        store.settings.set("persistent_tabs", ["alpha-bravo-charlie"])
        store.settings.save()

        first = _identity(mode="share")
        second = _identity(mode="website", public=True)
        store.add(first, "one", saved_at=_SAVED_AT)
        store.add(second, "two", saved_at="2026-11-13T03:22:01Z")
        store.delete(first["service_id"])

        assert not os.path.exists(_record_path(store, first["service_id"]))
        assert os.path.isfile(_record_path(store, second["service_id"]))
        fresh = _reload(store)
        assert fresh.get("saved_services") == [second["service_id"]]
        assert fresh.get("persistent_tabs") == ["alpha-bravo-charlie"]
        assert _read(sentinel) == payload
        assert os.listdir(persistent) == ["alpha-bravo-charlie.json"]
        assert not os.path.exists(
            os.path.join(persistent, first["service_id"] + ".json")
        )
        listed = store.list()
        assert len(listed) == 1
        assert listed[0]["service_id"] == second["service_id"]
        for token in _FORBIDDEN_TOKENS:
            assert token not in _read(_record_path(store, second["service_id"]))

    def test_failed_validation_leaves_no_file_or_settings_change(self, store):
        store.settings.save()
        before = _settings_bytes(store)
        info = os.stat(store.settings.filename)
        base = _identity()
        cases = []

        download = dict(base)
        download["mode"] = "download"
        cases.append(download)

        upper_mode = dict(base)
        upper_mode["mode"] = "Share"
        cases.append(upper_mode)

        private_without_auth = _identity(public=True)
        private_without_auth["public"] = False
        cases.append(private_without_auth)

        mismatched = _identity()
        mismatched["client_auth_pub_key"] = _identity()["client_auth_pub_key"]
        cases.append(mismatched)

        one_null = _identity()
        one_null["client_auth_pub_key"] = None
        cases.append(one_null)

        as_int = _identity(public=True)
        as_int["public"] = 0
        cases.append(as_int)

        as_one = _identity(public=True)
        as_one["public"] = 1
        cases.append(as_one)

        other = _identity(public=True)
        wrong_id = dict(other)
        wrong_id["service_id"] = _identity(public=True)["service_id"]
        cases.append(wrong_id)

        prefixed = dict(base)
        prefixed["private_key"] = "ED25519-V3:" + base["private_key"]
        cases.append(prefixed)

        unpadded = dict(base)
        unpadded["private_key"] = base["private_key"][:-2]
        cases.append(unpadded)

        lowered = _identity()
        lowered["client_auth_priv_key"] = "a" + lowered["client_auth_priv_key"][1:]
        cases.append(lowered)

        extra = dict(base)
        extra["filenames"] = ["/tmp/foo"]
        extra["data_dir"] = "/tmp/incoming"
        extra["webhook_url"] = "https://example.invalid/hook"
        extra["autostart_on_launch"] = True
        cases.append(extra)

        for identity in cases:
            with pytest.raises(saved_services.SavedServicesError):
                store.add(identity, "label", saved_at=_SAVED_AT)

        with pytest.raises(saved_services.SavedServicesError):
            store.add(base, "bad\nlabel", saved_at=_SAVED_AT)
        with pytest.raises(saved_services.SavedServicesError):
            store.add(base, "a" * 101, saved_at=_SAVED_AT)
        with pytest.raises(saved_services.SavedServicesError):
            store.add(base, "ok", saved_at="2026-11-13T03:22:00+00:00")
        with pytest.raises(saved_services.SavedServicesError):
            store.add(base, "ok", saved_at="2026-02-31T00:00:00Z")
        with pytest.raises(saved_services.SavedServicesError):
            saved_services.build_record(extra, "label")

        archive = os.path.join(store.common.build_data_dir(), "saved_services")
        assert not os.path.exists(archive)
        assert _settings_bytes(store) == before
        assert os.stat(store.settings.filename).st_mtime_ns == info.st_mtime_ns
        assert store.settings.get("saved_services") == []

    def test_label_bounds_and_unicode(self, store):
        identity = _identity(public=True)
        stored = store.add(identity, "a" * 100, saved_at=_SAVED_AT)
        assert stored["label"] == "a" * 100
        empty = _identity(public=True)
        assert store.add(empty, "", saved_at=_SAVED_AT)["label"] == ""
        cafe = _identity(public=True)
        store.add(cafe, "caf\u00e9", saved_at=_SAVED_AT)
        raw = _read(_record_path(store, cafe["service_id"]))
        assert b"\\u00e9" in raw
        assert store.get(cafe["service_id"])["label"] == "caf\u00e9"
        with pytest.raises(saved_services.SavedServicesError, match="invalid label"):
            store.add(_identity(public=True), "line\nbreak", saved_at=_SAVED_AT)
        with pytest.raises(saved_services.SavedServicesError, match="invalid label"):
            store.add(_identity(public=True), "null\x00byte", saved_at=_SAVED_AT)

    def test_public_service_may_keep_or_omit_client_auth(self, store):
        omitted = _identity(public=True)
        assert omitted["client_auth_priv_key"] is None
        assert omitted["client_auth_pub_key"] is None
        stored = store.add(omitted, "public", saved_at=_SAVED_AT)
        assert stored["public"] is True
        kept = _identity(public=False)
        kept["public"] = True
        stored_kept = store.add(kept, "leftover", saved_at=_SAVED_AT)
        assert stored_kept["public"] is True
        assert stored_kept["client_auth_priv_key"] == kept["client_auth_priv_key"]

    def test_prf_half_does_not_have_to_be_the_public_key(self, store):
        identity = _identity(public=True)
        raw = bytearray(base64.b64decode(identity["private_key"]))
        raw[-1] ^= 0x01
        identity["private_key"] = base64.b64encode(bytes(raw)).decode("ascii")
        stored = store.add(identity, "prf", saved_at=_SAVED_AT)
        assert stored["private_key"] == identity["private_key"]

    def test_rename_updates_label_only(self, store):
        identity = _identity(mode="chat")
        store.add(identity, "old", saved_at=_SAVED_AT)
        path = _record_path(store, identity["service_id"])
        updated = store.rename(identity["service_id"], "new")
        assert updated["label"] == "new"
        assert updated["saved_at"] == _SAVED_AT
        assert updated["private_key"] == identity["private_key"]
        assert updated["mode"] == "chat"
        assert store.get(identity["service_id"])["label"] == "new"
        assert _reload(store).get("saved_services") == [identity["service_id"]]
        before = _read(path)
        info = os.lstat(path)
        with pytest.raises(saved_services.SavedServicesError, match="invalid label"):
            store.rename(identity["service_id"], "bad\nname")
        assert _read(path) == before
        assert os.lstat(path).st_mtime_ns == info.st_mtime_ns

    def test_path_traversal_ids_are_rejected(self, store, tmp_path):
        store.settings.save()
        before = _settings_bytes(store)
        info = os.stat(store.settings.filename)
        absolute = tmp_path / "absolute-target"
        samples = [
            "../x",
            str(absolute),
            os.path.join(os.sep, "tmp", "onionshare-saved-services-escape"),
            "A" * 56,
            "a" * 55,
            "a" * 57,
            "a" * 20 + "/" + "b" * 35,
        ]
        for service_id in samples:
            with pytest.raises(saved_services.SavedServicesError):
                store.get(service_id)
            with pytest.raises(saved_services.SavedServicesError):
                store.delete(service_id)
            with pytest.raises(saved_services.SavedServicesError):
                store.rename(service_id, "label")
            identity = _identity(public=True)
            identity["service_id"] = service_id
            with pytest.raises(saved_services.SavedServicesError):
                store.add(identity, "label", saved_at=_SAVED_AT)

        data_dir = store.common.build_data_dir()
        assert not absolute.exists()
        assert not os.path.exists(str(absolute) + ".json")
        escape = os.path.join(os.sep, "tmp", "onionshare-saved-services-escape")
        assert not os.path.exists(escape)
        assert not os.path.exists(escape + ".json")
        assert not os.path.exists(os.path.join(data_dir, "x"))
        assert not os.path.exists(os.path.join(data_dir, "x.json"))
        archive = os.path.join(data_dir, "saved_services")
        assert not os.path.exists(archive)
        assert _settings_bytes(store) == before
        assert os.stat(store.settings.filename).st_mtime_ns == info.st_mtime_ns

    def test_symlink_record_is_rejected_and_kept(self, store, tmp_path):
        identity = _identity()
        store.add(identity, "kept", saved_at=_SAVED_AT)
        path = _record_path(store, identity["service_id"])
        payload = _read(path)
        outside = tmp_path / "outside.json"
        outside.write_bytes(payload)
        os.remove(path)
        os.symlink(outside, path)
        with pytest.raises(saved_services.SavedServicesError, match="symlink"):
            store.get(identity["service_id"])
        with pytest.raises(saved_services.SavedServicesError, match="symlink"):
            store.list()
        with pytest.raises(saved_services.SavedServicesError, match="symlink"):
            store.delete(identity["service_id"])
        with pytest.raises(saved_services.SavedServicesError, match="symlink"):
            store.rename(identity["service_id"], "other")
        assert os.path.islink(path)
        assert _read(outside) == payload
        assert _reload(store).get("saved_services") == [identity["service_id"]]

    def test_duplicate_key_record_is_rejected_and_kept(self, store):
        identity = _identity(public=True)
        store.add(identity, "label", saved_at=_SAVED_AT)
        path = _record_path(store, identity["service_id"])
        original = _read(path).decode("utf-8")
        duplicated = '{"label":"other",' + original[1:]
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(duplicated)
        with pytest.raises(saved_services.SavedServicesError, match="duplicate"):
            store.get(identity["service_id"])
        with pytest.raises(saved_services.SavedServicesError, match="duplicate"):
            store.list()
        assert _read(path).decode("utf-8") == duplicated

    def test_corrupted_record_raises_and_is_kept(self, store):
        identity = _identity(public=True)
        store.add(identity, "label", saved_at=_SAVED_AT)
        path = _record_path(store, identity["service_id"])
        blob = b"{"
        with open(path, "wb") as handle:
            handle.write(blob)
        with pytest.raises(saved_services.SavedServicesError, match="corrupt"):
            store.get(identity["service_id"])
        with pytest.raises(saved_services.SavedServicesError, match="corrupt"):
            store.list()
        assert _read(path) == blob

        nan = (
            b'{"client_auth_priv_key":null,"client_auth_pub_key":null,'
            b'"label":"x","mode":"share","private_key":"abc","public":NaN,'
            b'"saved_at":"2026-11-13T03:22:00Z","service_id":"'
            + identity["service_id"].encode("ascii")
            + b'"}'
        )
        with open(path, "wb") as handle:
            handle.write(nan)
        with pytest.raises(saved_services.SavedServicesError, match="corrupt"):
            store.get(identity["service_id"])
        assert _read(path) == nan

    def test_extra_or_missing_keys_are_rejected_and_kept(self, store):
        identity = _identity(public=True)
        store.add(identity, "label", saved_at=_SAVED_AT)
        path = _record_path(store, identity["service_id"])
        document = json.loads(_read(path))
        document["filenames"] = ["/tmp/foo"]
        extra = json.dumps(document).encode("utf-8")
        with open(path, "wb") as handle:
            handle.write(extra)
        with pytest.raises(saved_services.SavedServicesError, match="missing or extra"):
            store.get(identity["service_id"])
        assert _read(path) == extra

        missing = dict(document)
        del missing["filenames"]
        del missing["label"]
        raw_missing = json.dumps(missing).encode("utf-8")
        with open(path, "wb") as handle:
            handle.write(raw_missing)
        with pytest.raises(saved_services.SavedServicesError, match="missing or extra"):
            store.get(identity["service_id"])
        assert _read(path) == raw_missing

    def test_record_service_id_must_match_filename(self, store):
        first = _identity(public=True)
        second = _identity(public=True)
        store.add(first, "one", saved_at=_SAVED_AT)
        payload = _read(_record_path(store, first["service_id"]))
        foreign = _record_path(store, second["service_id"])
        with open(foreign, "wb") as handle:
            handle.write(payload)
        with pytest.raises(saved_services.SavedServicesError, match="does not match"):
            store.get(second["service_id"])
        assert _read(foreign) == payload

    def test_logs_do_not_include_secrets(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        _common = common.Common(verbose=True)
        archive = saved_services.SavedServices(_common)
        identity = _identity()
        archive.add(identity, "label", saved_at=_SAVED_AT)
        archive.rename(identity["service_id"], "renamed")
        archive.delete(identity["service_id"])
        captured = capsys.readouterr()
        output = captured.out + captured.err
        assert identity["private_key"] not in output
        assert identity["client_auth_priv_key"] not in output
        assert identity["client_auth_pub_key"] not in output

    @pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
    def test_posix_permissions(self, store):
        previous = os.umask(0o777)
        try:
            identity = _identity()
            store.add(identity, "perms", saved_at=_SAVED_AT)
        finally:
            os.umask(previous)
        directory = os.path.join(store.common.build_data_dir(), "saved_services")
        path = _record_path(store, identity["service_id"])
        assert stat.S_IMODE(os.lstat(directory).st_mode) == 0o700
        assert stat.S_IMODE(os.lstat(path).st_mode) == 0o600

    def test_build_record_copies_identity_and_label_only(self):
        identity = _identity(mode="website", public=True)
        record = saved_services.build_record(identity, "offline", saved_at=_SAVED_AT)
        assert record["label"] == "offline"
        assert record["saved_at"] == _SAVED_AT
        assert record["mode"] == "website"
        assert record["private_key"] == identity["private_key"]
        assert set(record) == set(identity) | {"label", "saved_at"}
        for token in ("filenames", "data_dir", "webhook", "autostart", "title"):
            assert token not in record

    def test_persistent_json_fixture_identity_is_accepted(self, store):
        path = os.path.join(os.path.dirname(__file__), "persistent.json")
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
        identity = {
            "mode": document["persistent"]["mode"],
            "service_id": document["general"]["service_id"],
            "private_key": document["onion"]["private_key"],
            "client_auth_priv_key": document["onion"]["client_auth_priv_key"],
            "client_auth_pub_key": document["onion"]["client_auth_pub_key"],
            "public": document["general"]["public"],
        }
        assert validate_identity(identity) == identity
        record = saved_services.build_record(identity, "fixture", saved_at=_SAVED_AT)
        assert record["service_id"] == identity["service_id"]
        assert record["private_key"] == identity["private_key"]
        stored = store.add(identity, "fixture", saved_at=_SAVED_AT)
        assert stored["private_key"] == identity["private_key"]
        assert store.get(identity["service_id"])["client_auth_pub_key"] == (
            identity["client_auth_pub_key"]
        )

    def test_symlinked_archive_directory_is_rejected(self, store, tmp_path):
        data_dir = store.common.build_data_dir()
        target = tmp_path / "archive-target"
        target.mkdir()
        link = os.path.join(data_dir, "saved_services")
        os.symlink(target, link)
        identity = _identity(public=True)
        with pytest.raises(saved_services.SavedServicesError, match="symlink"):
            store.add(identity, "label", saved_at=_SAVED_AT)
        assert os.path.islink(link)
        assert os.listdir(target) == []
        assert store.settings.get("saved_services") == []
        assert _reload(store).get("saved_services") == []

    def test_failed_replace_leaves_no_temp_file_or_record(self, store, monkeypatch):
        identity = _identity(public=True)

        def fail_replace(source, destination):
            raise OSError("replace failed")

        monkeypatch.setattr(saved_services.os, "replace", fail_replace)
        with pytest.raises(OSError, match="replace failed"):
            store.add(identity, "label", saved_at=_SAVED_AT)
        archive = os.path.join(store.common.build_data_dir(), "saved_services")
        assert os.path.isdir(archive)
        assert not os.path.islink(archive)
        assert os.listdir(archive) == []
        assert stat.S_IMODE(os.lstat(archive).st_mode) == 0o700
        assert not os.path.exists(_record_path(store, identity["service_id"]))
        assert store.settings.get("saved_services") == []
        assert _reload(store).get("saved_services") == []

    def test_fractional_saved_at_is_accepted_on_read(self, store):
        identity = _identity(public=True)
        stored = store.add(identity, "label")
        assert "." not in stored["saved_at"]
        assert len(stored["saved_at"]) == len("2026-11-13T03:22:00Z")
        assert stored["saved_at"].endswith("Z")
        path = _record_path(store, identity["service_id"])
        document = json.loads(_read(path))
        document["saved_at"] = "2026-11-13T03:22:00.123456Z"
        with open(path, "wb") as handle:
            handle.write(_canonical(document))
        loaded = store.get(identity["service_id"])
        assert loaded["saved_at"] == "2026-11-13T03:22:00.123456Z"
        assert loaded["private_key"] == identity["private_key"]

    def test_deeply_nested_record_is_saved_services_error(self, store):
        identity = _identity(public=True)
        store.add(identity, "label", saved_at=_SAVED_AT)
        path = _record_path(store, identity["service_id"])
        nested = ('{"k":' * 10000) + "null" + ("}" * 10000)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(nested)
        with pytest.raises(saved_services.SavedServicesError, match="corrupt") as caught:
            store.get(identity["service_id"])
        assert caught.value.__cause__ is None
        assert _read(path) == nested.encode("utf-8")

    def test_regular_file_at_archive_path_is_saved_services_error(self, store):
        path = os.path.join(store.common.build_data_dir(), "saved_services")
        payload = b"not a directory"
        with open(path, "wb") as handle:
            handle.write(payload)
        identity = _identity(public=True)
        with pytest.raises(
            saved_services.SavedServicesError, match="could not be created"
        ) as caught:
            store.add(identity, "label", saved_at=_SAVED_AT)
        assert caught.value.__cause__ is None
        assert not os.path.isdir(path)
        assert _read(path) == payload
        assert store.settings.get("saved_services") == []

    def test_record_with_an_extra_key_is_rejected(self, store):
        identity = _identity(public=True)
        store.add(identity, "label", saved_at=_SAVED_AT)
        path = _record_path(store, identity["service_id"])
        document = json.loads(_read(path))
        document["filenames"] = ["/tmp/foo"]
        extra = _canonical(document)
        with open(path, "wb") as handle:
            handle.write(extra)
        with pytest.raises(
            saved_services.SavedServicesError, match="missing or extra"
        ) as caught:
            store.get(identity["service_id"])
        assert caught.value.__cause__ is None
        assert _read(path) == extra
        with pytest.raises(
            saved_services.SavedServicesError, match="exactly the six"
        ):
            saved_services.build_record(document, "label", saved_at=_SAVED_AT)
        projection = {key: document[key] for key in identity}
        assert validate_identity(projection) == identity

    def test_invalid_utf8_record_has_no_cause(self, store):
        identity = _identity(public=True)
        store.add(identity, "label", saved_at=_SAVED_AT)
        path = _record_path(store, identity["service_id"])
        blob = b"\xff"
        with open(path, "wb") as handle:
            handle.write(blob)
        with pytest.raises(saved_services.SavedServicesError, match="corrupt") as caught:
            store.get(identity["service_id"])
        assert caught.value.__cause__ is None
        assert _read(path) == blob
