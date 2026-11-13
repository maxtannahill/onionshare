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

import errno
import json
import os
import re
import stat
import tempfile
import unicodedata
from datetime import datetime, timezone

from .identity_backup import IdentityBackupError, validate_identity
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
_SERVICE_ID_RE = re.compile(r"^[a-z2-7]{56}$")
_SAVED_AT_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)


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
    """
    Accept an ISO 8601 UTC timestamp ending in ``Z``.

    Readers tolerate an optional fractional second of 1 to 6 digits.
    Writers still emit no fraction: ``_utc_now`` uses ``%Y-%m-%dT%H:%M:%SZ``.
    """
    if type(saved_at) is not str or _SAVED_AT_RE.fullmatch(saved_at) is None:
        raise SavedServicesError("invalid saved_at")
    try:
        datetime.fromisoformat(saved_at[:-1] + "+00:00")
    except ValueError:
        raise SavedServicesError("invalid saved_at")
    return saved_at


def _utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_identity(fields):
    """
    Validate a six-key projection with identity_backup.validate_identity.

    ``label`` and ``saved_at`` are not passed through: they would look like
    extra keys. Exact key sets for an on-disk record and for ``build_record``
    input are checked by those callers. IdentityBackupError becomes
    SavedServicesError so archive callers do not see the envelope error.
    """
    if type(fields) is not dict or any(key not in fields for key in _IDENTITY_KEYS):
        raise SavedServicesError(
            "identity must contain exactly the six identity keys"
        )
    projection = {key: fields[key] for key in _IDENTITY_KEYS}
    try:
        return validate_identity(projection)
    except IdentityBackupError:
        raise SavedServicesError("invalid identity") from None


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
        post = self._durable_write(directory, path, _canonical_bytes(record))
        if service_id not in ids:
            ids.append(service_id)
        self.settings.set("saved_services", ids)
        self.settings.save()
        self.common.log("SavedServices", "add", service_id)
        if post is not None:
            raise post
        return record

    def list(self):
        """Return readable archived records in ``saved_services`` order.

        A missing, damaged, or symlinked id is skipped. ``get`` still raises
        for that id, and one bad entry does not hide the others.
        """
        records = []
        for service_id in self._saved_id_list():
            try:
                records.append(self.get(service_id))
            except SavedServicesError:
                continue
        return records

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
        A symlink is unlinked itself and is not followed, so its target is
        left untouched. A directory or fifo is left in place; the settings
        id is still dropped.
        """
        ids = self._saved_id_list()
        directory = self._archive_dir(create=False)
        path = self._service_record_path(directory, service_id)
        # isfile() follows symlinks. Classify the directory entry first so
        # unlink removes the link and never opens its target.
        link = os.path.islink(path)
        regular = (not link) and os.path.isfile(path)
        listed = service_id in ids
        if not link and not regular and not listed:
            raise SavedServicesError("saved service record was not found")
        post = None
        if link or regular:
            os.unlink(path)
            try:
                _fsync_directory(directory)
            except OSError as exc:
                post = exc
        if listed:
            remaining = [item for item in ids if item != service_id]
            self.settings.set("saved_services", remaining)
            self.settings.save()
        self.common.log("SavedServices", "delete", service_id)
        if post is not None:
            raise post

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
        post = self._durable_write(directory, path, _canonical_bytes(updated))
        ids = self._saved_id_list()
        if service_id not in ids:
            ids.append(service_id)
        self.settings.set("saved_services", ids)
        self.settings.save()
        self.common.log("SavedServices", "rename", service_id)
        if post is not None:
            raise post
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
            try:
                os.makedirs(directory, 0o700, True)
                os.chmod(directory, 0o700)
            except OSError:
                raise SavedServicesError(
                    "saved_services directory could not be created"
                ) from None
        return directory

    def _service_record_path(self, directory, service_id):
        """
        Return the record path for a validated id.

        The final path component is not followed, so a symlink stays inside
        this check even when its target is outside the archive.
        """
        if (
            type(service_id) is not str
            or _SERVICE_ID_RE.fullmatch(service_id) is None
        ):
            raise SavedServicesError("invalid service_id")
        record_path = os.path.join(directory, service_id + ".json")
        if os.path.basename(record_path) != service_id + ".json":
            raise SavedServicesError(
                "record path is outside the archive directory"
            )
        directory_real = os.path.realpath(directory)
        parent_real = os.path.realpath(os.path.dirname(record_path))
        try:
            inside = (
                os.path.commonpath([directory_real, parent_real]) == directory_real
            )
        except ValueError:
            inside = False
        if not inside:
            raise SavedServicesError(
                "record path is outside the archive directory"
            )
        return record_path

    def _record_path(self, directory, service_id):
        record_path = self._service_record_path(directory, service_id)
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
        if not inside:
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
        except UnicodeDecodeError:
            raise SavedServicesError("saved service record is corrupted") from None
        record = _parse_record(text)
        if os.path.basename(path) != record["service_id"] + ".json":
            raise SavedServicesError(
                "record service_id does not match its file"
            )
        return record

    def _durable_write(self, directory, final_path, payload):
        """
        Write ``payload`` via a temp file in ``directory``, fsync it, then
        ``os.replace`` onto ``final_path``.

        ``fchmod`` before replace is the permission guarantee. A later
        ``chmod`` or directory fsync error is returned, not raised, so the
        caller can still update ``saved_services`` for the committed file.
        Errors before replace still propagate and the temp file is removed.
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
        except Exception:
            if not replaced:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            raise
        post = None
        try:
            os.chmod(final_path, 0o600)
        except OSError as exc:
            post = exc
        try:
            _fsync_directory(directory)
        except OSError as exc:
            if post is None:
                post = exc
        return post
