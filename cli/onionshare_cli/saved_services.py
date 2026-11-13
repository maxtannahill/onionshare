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

Saved Services archive.

Records under ``<data_dir>/saved_services/`` are stored unencrypted on
disk, like persistent tabs. The directory is mode 0o700 and each record
is mode 0o600, but the onion private key and client-auth keys inside a
record are plaintext. This archive is not an encrypted backup.
"""

import base64
import errno
import hashlib
import json
import os
import re
import stat
import tempfile
import unicodedata
from datetime import datetime, timezone

import nacl.bindings
import nacl.public
from nacl.exceptions import UnavailableError

from .settings import Settings


class SavedServicesError(Exception):
    """
    A saved-services operation failed validation or a safety check.

    Messages name the rule that failed. They do not include private keys,
    client-auth keys, or record contents.
    """


_IDENTITY_KEYS = (
    "mode",
    "service_id",
    "private_key",
    "client_auth_priv_key",
    "client_auth_pub_key",
    "public",
)
_RECORD_KEYS = _IDENTITY_KEYS + ("label", "saved_at")
_MODES = {"share", "receive", "website", "chat"}
_SERVICE_ID_RE = re.compile(r"^[a-z2-7]{56}$")
_PRIVATE_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{86}==$")
_CLIENT_AUTH_RE = re.compile(r"^[A-Z2-7]{52}$")
_SAVED_AT_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)
_ONION_CHECKSUM_PREFIX = b".onion checksum"
_ONION_VERSION = b"\x03"


def _canonical_bytes(record):
    """
    UTF-8 canonical JSON: sorted keys, compact separators, ASCII escapes,
    and no trailing newline.
    """
    text = json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return text.encode("utf-8")


def _reject_duplicate_keys(pairs):
    values = {}
    for key, value in pairs:
        if key in values:
            raise SavedServicesError("saved service record has duplicate keys")
        values[key] = value
    return values


def _reject_non_finite(constant):
    raise SavedServicesError("saved service record is corrupted")


def _validate_label(label):
    if type(label) is not str or len(label) > 100:
        raise SavedServicesError("invalid label")
    for character in label:
        if unicodedata.category(character) == "Cc":
            raise SavedServicesError("invalid label")
    return label


def _validate_saved_at(saved_at):
    if type(saved_at) is not str or _SAVED_AT_RE.fullmatch(saved_at) is None:
        raise SavedServicesError("invalid saved_at")
    try:
        datetime.fromisoformat(saved_at[:-1] + "+00:00")
    except ValueError:
        raise SavedServicesError("invalid saved_at")
    return saved_at


def _utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _decode_private_key(value):
    if type(value) is not str or _PRIVATE_KEY_RE.fullmatch(value) is None:
        raise SavedServicesError("invalid private_key")
    if value.startswith("ED25519-V3:") or "ED25519-V3:" in value:
        raise SavedServicesError("invalid private_key")
    try:
        raw = base64.b64decode(value)
    except Exception:
        raise SavedServicesError("invalid private_key")
    canonical = base64.b64encode(raw).decode("ascii")
    if len(raw) != 64 or canonical != value:
        raise SavedServicesError("invalid private_key")
    return raw


def _decode_client_auth(value):
    if type(value) is not str or _CLIENT_AUTH_RE.fullmatch(value) is None:
        raise SavedServicesError("invalid client-auth key")
    try:
        raw = base64.b32decode(value + "====", casefold=False)
    except Exception:
        raise SavedServicesError("invalid client-auth key")
    canonical = base64.b32encode(raw).decode("ascii")
    if canonical.endswith("===="):
        canonical = canonical[:-4]
    if len(raw) != 32 or canonical != value:
        raise SavedServicesError("invalid client-auth key")
    return raw


def _service_id_for_scalar(scalar):
    """
    Tor v3 address of an ed25519 public key.

    The ED25519-V3 blob OnionShare stores is the secret scalar concatenated
    with the PRF secret, not the seed and not the public key. PyNaCl can
    recompute the public key from that scalar.
    """
    try:
        public_key = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(scalar)
    except UnavailableError:
        raise SavedServicesError(
            "cannot validate private_key with this libsodium build"
        )
    except Exception:
        raise SavedServicesError("invalid private_key")
    if type(public_key) is not bytes or len(public_key) != 32:
        raise SavedServicesError("invalid private_key")
    checksum = hashlib.sha3_256(
        _ONION_CHECKSUM_PREFIX + public_key + _ONION_VERSION
    ).digest()[:2]
    raw_address = public_key + checksum + _ONION_VERSION
    return base64.b32encode(raw_address).decode("ascii").lower()


def _validate_identity(fields):
    """
    Validate the six identity fields.

    This is the archive's private copy of the identity rules. Callers must
    already have decided whether extra keys are allowed; this function only
    reads the six identity fields.
    """
    for key in _IDENTITY_KEYS:
        if key not in fields:
            raise SavedServicesError(
                "identity must contain exactly the six identity keys"
            )

    mode = fields["mode"]
    if type(mode) is not str or mode not in _MODES:
        raise SavedServicesError("invalid mode")

    service_id = fields["service_id"]
    if type(service_id) is not str or _SERVICE_ID_RE.fullmatch(service_id) is None:
        raise SavedServicesError("invalid service_id")

    raw_private = _decode_private_key(fields["private_key"])
    derived_id = _service_id_for_scalar(raw_private[:32])
    if derived_id != service_id:
        raise SavedServicesError("service_id does not match private_key")

    public = fields["public"]
    if type(public) is not bool:
        raise SavedServicesError("public must be a boolean")

    priv = fields["client_auth_priv_key"]
    pub = fields["client_auth_pub_key"]
    if priv is None and pub is None:
        if public is False:
            raise SavedServicesError("a private service requires client-auth keys")
    elif priv is None or pub is None:
        raise SavedServicesError(
            "client-auth keys must both be null or both be valid"
        )
    else:
        priv_raw = _decode_client_auth(priv)
        pub_raw = _decode_client_auth(pub)
        try:
            derived_pub = bytes(nacl.public.PrivateKey(priv_raw).public_key)
        except Exception:
            raise SavedServicesError("invalid client-auth key")
        if derived_pub != pub_raw:
            raise SavedServicesError("client-auth key pair does not match")

    return {
        "mode": mode,
        "service_id": service_id,
        "private_key": fields["private_key"],
        "client_auth_priv_key": priv,
        "client_auth_pub_key": pub,
        "public": public,
    }


def _parse_record(text):
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
        )
    except SavedServicesError:
        raise
    except Exception:
        raise SavedServicesError("saved service record is corrupted") from None
    if type(value) is not dict:
        raise SavedServicesError("saved service record must be a JSON object")
    if set(value) != set(_RECORD_KEYS):
        raise SavedServicesError("saved service record has missing or extra keys")
    identity = _validate_identity(value)
    record = dict(identity)
    record["label"] = _validate_label(value["label"])
    record["saved_at"] = _validate_saved_at(value["saved_at"])
    return record


def build_record(identity, label, saved_at=None):
    """
    Build an archive record from an identity dict and a label.

    ``identity`` must contain exactly the six identity keys. Filenames,
    data directories, webhooks, titles, and persistent/autostart flags are
    rejected. Nothing is read from or written to disk.
    """
    if type(identity) is not dict or set(identity) != set(_IDENTITY_KEYS):
        raise SavedServicesError(
            "identity must contain exactly the six identity keys"
        )
    checked = _validate_identity(identity)
    record = dict(checked)
    record["label"] = _validate_label(label)
    if saved_at is None:
        saved_at = _utc_now()
    record["saved_at"] = _validate_saved_at(saved_at)
    return record


def _fsync_directory(directory):
    """Fsync a directory when the platform supports it."""
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        descriptor = os.open(directory, flags)
    except OSError:
        return
    try:
        try:
            os.fsync(descriptor)
        except OSError as exc:
            unsupported = {errno.EINVAL}
            for name in ("ENOTSUP", "EOPNOTSUPP"):
                value = getattr(errno, name, None)
                if value is not None:
                    unsupported.add(value)
            if exc.errno not in unsupported:
                raise
    finally:
        os.close(descriptor)


class SavedServices(object):
    """
    Plaintext archive of onion-service identities.

    The archive is stored unencrypted on disk, like persistent tabs. It
    never reads or writes ``persistent_tabs`` or ``persistent/*.json``.
    """

    def __init__(self, common, settings=None):
        """
        ``common`` supplies the data directory.

        ``settings``, when given, must already be loaded. Successful adds
        and deletes update that object and call ``Settings.save()`` before
        returning. When ``settings`` is omitted, one is created and loaded
        from the default path.
        """
        self.common = common
        if settings is None:
            settings = Settings(common)
            settings.load()
        self.settings = settings

    def add(self, identity, label, *, replace=False, saved_at=None):
        """
        Validate and durably store a record, then update ``saved_services``.

        Raises ``SavedServicesError`` if this service id is already archived
        unless ``replace`` is true. ``replace`` is the explicit replace/update
        flag; there is no silent overwrite. Returns the stored record.
        """
        if type(replace) is not bool:
            raise SavedServicesError("replace must be a boolean")
        record = build_record(identity, label, saved_at=saved_at)
        service_id = record["service_id"]
        ids = self._saved_id_list()
        directory = self._archive_dir(create=True)
        path = self._record_path(directory, service_id)
        if (os.path.exists(path) or service_id in ids) and not replace:
            raise SavedServicesError("saved service already exists")
        self._durable_write(directory, path, _canonical_bytes(record))
        if service_id not in ids:
            ids.append(service_id)
        self.settings.set("saved_services", ids)
        self.settings.save()
        self.common.log("SavedServices", "add", service_id)
        return record

    def list(self):
        """Return the archived records in ``saved_services`` order."""
        return [self.get(service_id) for service_id in self._saved_id_list()]

    def get(self, service_id):
        """
        Load and strictly validate one record.

        A symlink, a corrupt file, or a failed check raises
        ``SavedServicesError`` and leaves the file in place.
        """
        directory = self._archive_dir(create=False)
        path = self._record_path(directory, service_id)
        if not os.path.isfile(path):
            raise SavedServicesError("saved service record was not found")
        return self._read_record(path)

    def delete(self, service_id):
        """
        Remove the record file and the id from ``saved_services`` only.

        Does not change ``persistent_tabs`` or anything under ``persistent/``.
        """
        ids = self._saved_id_list()
        directory = self._archive_dir(create=False)
        path = self._record_path(directory, service_id)
        existed = os.path.isfile(path)
        listed = service_id in ids
        if not existed and not listed:
            raise SavedServicesError("saved service record was not found")
        if existed:
            os.remove(path)
            _fsync_directory(directory)
        if listed:
            remaining = [item for item in ids if item != service_id]
            self.settings.set("saved_services", remaining)
            self.settings.save()
        self.common.log("SavedServices", "delete", service_id)

    def rename(self, service_id, label):
        """
        Update the record's label and write it durably.

        The identity fields and ``saved_at`` are preserved. An invalid label
        or a corrupt record leaves the existing file unchanged.
        """
        new_label = _validate_label(label)
        current = self.get(service_id)
        identity = {key: current[key] for key in _IDENTITY_KEYS}
        updated = build_record(identity, new_label, saved_at=current["saved_at"])
        directory = self._archive_dir(create=True)
        path = self._record_path(directory, service_id)
        self._durable_write(directory, path, _canonical_bytes(updated))
        ids = self._saved_id_list()
        if service_id not in ids:
            ids.append(service_id)
        self.settings.set("saved_services", ids)
        self.settings.save()
        self.common.log("SavedServices", "rename", service_id)
        return updated

    def _saved_id_list(self):
        try:
            current = self.settings.get("saved_services")
        except KeyError:
            raise SavedServicesError(
                "saved_services settings must be a list of strings"
            )
        if type(current) is not list or any(type(item) is not str for item in current):
            raise SavedServicesError(
                "saved_services settings must be a list of strings"
            )
        return list(current)

    def _archive_dir(self, create):
        data_dir = self.common.build_data_dir()
        directory = os.path.join(data_dir, "saved_services")
        if os.path.islink(directory):
            raise SavedServicesError("saved_services directory is a symlink")
        if create:
            os.makedirs(directory, 0o700, True)
            os.chmod(directory, 0o700)
        return directory

    def _record_path(self, directory, service_id):
        if (
            type(service_id) is not str
            or _SERVICE_ID_RE.fullmatch(service_id) is None
        ):
            raise SavedServicesError("invalid service_id")
        record_path = os.path.join(directory, service_id + ".json")
        if os.path.islink(record_path):
            raise SavedServicesError("record file is a symlink")
        directory_real = os.path.realpath(directory)
        record_real = os.path.realpath(record_path)
        try:
            inside = (
                os.path.commonpath([directory_real, record_real]) == directory_real
            )
        except ValueError:
            inside = False
        if not inside or os.path.basename(record_path) != service_id + ".json":
            raise SavedServicesError(
                "record path is outside the archive directory"
            )
        return record_path

    def _read_record(self, path):
        if os.path.islink(path):
            raise SavedServicesError("record file is a symlink")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.EMLINK):
                raise SavedServicesError("record file is a symlink") from exc
            if exc.errno == errno.ENOENT:
                raise SavedServicesError(
                    "saved service record was not found"
                ) from exc
            raise SavedServicesError("saved service record is corrupted") from exc
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise SavedServicesError("record file is a symlink")
            chunks = []
            while True:
                block = os.read(descriptor, 65536)
                if not block:
                    break
                chunks.append(block)
        finally:
            os.close(descriptor)
        try:
            text = b"".join(chunks).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SavedServicesError("saved service record is corrupted") from exc
        record = _parse_record(text)
        if os.path.basename(path) != record["service_id"] + ".json":
            raise SavedServicesError(
                "record service_id does not match its file"
            )
        return record

    def _durable_write(self, directory, final_path, payload):
        """
        Write ``payload`` via a temp file in ``directory``, fsync it, then
        ``os.replace`` onto ``final_path`` and fsync the directory.
        """
        if os.path.islink(final_path):
            raise SavedServicesError("record file is a symlink")
        descriptor, tmp_path = tempfile.mkstemp(prefix=".tmp-", dir=directory)
        replaced = False
        try:
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "wb") as handle:
                    descriptor = None
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            if os.path.islink(final_path):
                raise SavedServicesError("record file is a symlink")
            os.replace(tmp_path, final_path)
            replaced = True
            os.chmod(final_path, 0o600)
            _fsync_directory(directory)
        except Exception:
            if not replaced:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            raise
