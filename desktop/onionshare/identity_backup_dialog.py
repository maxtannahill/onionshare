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

import errno
import json
import os
import tempfile

from PySide6 import QtCore, QtGui, QtWidgets

from onionshare_cli.identity_backup import (
    IdentityBackupError,
    encrypt_identity,
    generate_passphrase,
    identity_from_mode_settings,
)
from onionshare_cli.saved_services import SavedServices, SavedServicesError

from . import strings
from .gui_common import GuiCommon
from .widgets import Alert, qr_code_pixmap


class _ModeSettingsIdentityView(object):
    """
    ModeSettings-like view used only to build an identity.

    A tab that has never been marked persistent still has ``persistent.mode``
    null. The open tab's mode is used in that case. This does not call
    ``ModeSettings.set``, which would log the value and might write the tab
    file.
    """

    def __init__(self, mode_settings, mode):
        self._mode_settings = mode_settings
        self._mode = mode

    def get(self, group, key):
        value = self._mode_settings.get(group, key)
        if group == "persistent" and key == "mode" and not value:
            return self._mode
        return value


def identity_for_open_tab(mode_settings, mode):
    """
    Return the six-key identity for an open tab.

    Raises IdentityBackupError when the tab has no exportable identity.
    """
    return identity_from_mode_settings(_ModeSettingsIdentityView(mode_settings, mode))


class EncryptIdentityThread(QtCore.QThread):
    """
    Run encrypt_identity off the GUI thread.

    Modeled on CompressThread: run() emits a result and does not touch widgets.
    The passphrase and identity are not logged.
    """

    success = QtCore.Signal(str)
    error = QtCore.Signal()

    def __init__(self, identity, passphrase):
        super(EncryptIdentityThread, self).__init__()
        self._identity = identity
        self._passphrase = passphrase
        # Set inside run() to the QThread that actually encrypted.
        self.worker_thread = None

    def run(self):
        self.worker_thread = QtCore.QThread.currentThread()
        identity = self._identity
        passphrase = self._passphrase
        self._identity = None
        self._passphrase = None
        try:
            envelope = encrypt_identity(identity, passphrase)
        except Exception:
            self.error.emit()
            return
        self.success.emit(envelope)


# One timed wait for the Argon2id worker. Interactive KDF is far shorter than
# this; if it is still running afterwards a user close stays open. Quit and
# DeferredDelete do not use this wait: they leave the worker disconnected and
# keep the QThread alive without blocking the caller.
_ENCRYPT_THREAD_WAIT_MS = 180000

# Quit and DeferredDelete. Zero does not block. A running QThread is retained
# until it finishes and is never destroyed while running.
_ABANDON_THREAD_WAIT_MS = 0

# Display size for the export QR. Scaling uses Qt.FastTransformation.
_QR_DISPLAY_SIDE = 280

_IDENTITY_FIELD_KEYS = (
    "mode",
    "service_id",
    "private_key",
    "client_auth_priv_key",
    "client_auth_pub_key",
    "public",
)


class _AbandonedThreadKeeper(QtCore.QObject):
    """Hold QThreads that outlive the dialog so Qt does not abort on quit."""

    def __init__(self):
        super(_AbandonedThreadKeeper, self).__init__()
        self._threads = []

    def retain(self, thread):
        if thread not in self._threads:
            self._threads.append(thread)
            try:
                thread.finished.connect(
                    self._release, QtCore.Qt.ConnectionType.QueuedConnection
                )
            except RuntimeError:
                pass
        self._release_if_finished(thread)

    def _release(self):
        self._release_thread(self.sender())

    def _release_if_finished(self, thread):
        try:
            finished = bool(thread.isFinished())
        except RuntimeError:
            return
        if finished:
            self._release_thread(thread)

    def _release_thread(self, thread):
        if thread is None:
            return
        try:
            if hasattr(thread, "_identity"):
                thread._identity = None
        except RuntimeError:
            pass
        try:
            self._threads.remove(thread)
        except ValueError:
            pass
        try:
            thread.deleteLater()
        except RuntimeError:
            pass


_abandoned_thread_keeper = None


def _retain_thread(thread):
    """Keep a running QThread referenced until its finished signal."""
    global _abandoned_thread_keeper
    if thread is None:
        return
    if _abandoned_thread_keeper is None:
        _abandoned_thread_keeper = _AbandonedThreadKeeper()
    _abandoned_thread_keeper.retain(thread)


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


def _write_exact_bytes(path, payload):
    """
    Replace ``path`` with ``payload`` via a temp file in the same directory.

    The destination is not opened for writing, so a failure leaves any
    existing file byte-for-byte intact and removes the temp file.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    descriptor, tmp_path = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    replaced = False
    try:
        try:
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = None
                written = handle.write(payload)
                if written != len(payload):
                    raise OSError("short write")
                handle.flush()
                os.fsync(handle.fileno())
                if os.fstat(handle.fileno()).st_size != len(payload):
                    raise OSError("short write")
        finally:
            if descriptor is not None:
                os.close(descriptor)
        os.replace(tmp_path, path)
        replaced = True
        _fsync_directory(directory)
    except Exception:
        if not replaced:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        raise


def _archive_failure_message(error):
    """Map a SavedServicesError to UI text. The label and error text are not logged."""
    if str(error) == "invalid label":
        return strings._("gui_identity_backup_invalid_label")
    return strings._("gui_identity_backup_archive_error")


def _record_was_committed(archive, identity, label):
    """True when the archive file already holds this identity and label."""
    try:
        record = archive.get(identity["service_id"])
    except Exception:
        return False
    if type(record) is not dict:
        return False
    for key in _IDENTITY_FIELD_KEYS:
        if record.get(key) != identity.get(key):
            return False
    return record.get("label") == label


def _saved_id_listed(archive, service_id):
    try:
        archive.settings.load()
        current = archive.settings.get("saved_services")
    except Exception:
        return False
    return type(current) is list and service_id in current


def _ensure_saved_id(archive, service_id):
    """
    Make ``saved_services`` include ``service_id`` after the record file exists.

    A settings save that failed after ``os.replace`` is tried again. The
    service id is the only value written.
    """
    if _saved_id_listed(archive, service_id):
        return

    def include(current):
        if service_id not in current:
            current.append(service_id)
        return current

    archive._save_saved_ids(include)


def store_saved_identity(archive, identity, label, replace):
    """
    Store a record and say whether the file was committed.

    Returns ``(saved, post_commit_warning)``. ``SavedServicesError`` still
    propagates for validation and the duplicate check, which happen before
    the record is replaced. When ``os.replace`` has committed the file and a
    later chmod, directory fsync, or settings update fails, ``saved`` is
    True and the settings id is repaired when it is missing.
    """
    try:
        archive.add(identity, label, replace=replace)
        return True, False
    except SavedServicesError:
        raise
    except Exception:
        if not _record_was_committed(archive, identity, label):
            return False, False
        try:
            _ensure_saved_id(archive, identity["service_id"])
        except Exception:
            pass
        return True, True


def _report_stored_identity(common, saved, warning):
    """Tell the user the save succeeded, or that nothing was written."""
    if not saved:
        Alert(common, strings._("gui_identity_backup_archive_error"))
        return False
    Alert(common, strings._("gui_identity_backup_archive_saved"))
    if warning:
        Alert(
            common,
            strings._("gui_identity_backup_archive_saved_warning"),
            icon=QtWidgets.QMessageBox.Icon.Information,
        )
    return True


def _confirm(common, message, icon, buttons, accept_button):
    box = Alert(
        common,
        message,
        icon=icon,
        buttons=buttons,
        autostart=False,
    )
    return box.exec() == accept_button


def save_identity_to_saved_services(common, parent, identity):
    """
    Store an identity in Saved Services after a plaintext-archive warning.

    An existing record is not overwritten unless the user confirms. Returns
    True when a record was written. Nothing about the identity is logged.
    """
    disclosed = _confirm(
        common,
        strings._("gui_identity_backup_archive_disclosure"),
        QtWidgets.QMessageBox.Icon.Warning,
        QtWidgets.QMessageBox.StandardButton.Ok
        | QtWidgets.QMessageBox.StandardButton.Cancel,
        QtWidgets.QMessageBox.StandardButton.Ok,
    )
    if not disclosed:
        return False

    label, accepted = QtWidgets.QInputDialog.getText(
        parent,
        strings._("gui_identity_backup_archive_label_title"),
        strings._("gui_identity_backup_archive_label_prompt"),
    )
    if not accepted:
        return False

    archive = SavedServices(common, common.settings)
    try:
        saved, warning = store_saved_identity(archive, identity, label, False)
    except SavedServicesError as error:
        if str(error) != "saved service already exists":
            Alert(common, _archive_failure_message(error))
            return False
        replace = _confirm(
            common,
            strings._("gui_identity_backup_archive_duplicate"),
            QtWidgets.QMessageBox.Icon.Warning,
            QtWidgets.QMessageBox.StandardButton.Yes
            | QtWidgets.QMessageBox.StandardButton.No,
            QtWidgets.QMessageBox.StandardButton.Yes,
        )
        if not replace:
            Alert(common, strings._("gui_identity_backup_archive_not_replaced"))
            return False
        try:
            saved, warning = store_saved_identity(archive, identity, label, True)
        except SavedServicesError as replace_error:
            Alert(common, _archive_failure_message(replace_error))
            return False
    return _report_stored_identity(common, saved, warning)


class ExportIdentityBackupDialog(QtWidgets.QDialog):
    """
    Export an encrypted identity backup.

    The passphrase is shown so it can be written down. The QR code and the
    file are the same envelope string: the file is that string encoded as
    UTF-8 with no trailing newline, and the passphrase is not in either one.
    Encryption runs on EncryptIdentityThread. This constructor does not call
    exec(); the caller shows the dialog.
    """

    def __init__(self, common, identity, passphrase, parent=None):
        super(ExportIdentityBackupDialog, self).__init__(parent)
        self.common = common
        self.identity = identity
        self.passphrase = None
        self._next_passphrase = passphrase
        self.envelope = None
        self.qr_text = None
        self.pending_bytes = None
        self.encrypt_thread = None
        self.encrypt_threads = []
        self.is_busy = False
        self.generation = 0
        self._accepting_results = True
        self._shutting_down = False
        self._shutdown_complete = False
        self._close_in_progress = False

        self.common.log("ExportIdentityBackupDialog", "__init__")

        self.setWindowTitle(strings._("gui_identity_backup_dialog_title"))
        self.setWindowIcon(QtGui.QIcon(GuiCommon.get_resource_path("images/logo.png")))
        self.setMinimumWidth(480)
        self.setSizeGripEnabled(True)
        self._qr_source = None

        fixed = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont)

        self.instructions = QtWidgets.QLabel(
            strings._("gui_identity_backup_instructions")
        )
        self.instructions.setWordWrap(True)

        self.local_encryption_label = QtWidgets.QLabel(
            strings._("gui_identity_backup_local_encryption")
        )
        self.local_encryption_label.setWordWrap(True)

        self.recovery_group = QtWidgets.QGroupBox(
            strings._("gui_identity_backup_passphrase_label")
        )
        self.passphrase_label = QtWidgets.QLabel("")
        self.passphrase_label.setFont(fixed)
        self.passphrase_label.setWordWrap(True)
        self.passphrase_label.setTextInteractionFlags(
            QtCore.Qt.TextInteractionFlag.TextSelectableByMouse
            | QtCore.Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        self.passphrase_warning = QtWidgets.QLabel(
            strings._("gui_identity_backup_passphrase_warning")
        )
        self.passphrase_warning.setWordWrap(True)
        self.copy_passphrase_button = QtWidgets.QPushButton(
            strings._("gui_identity_backup_copy_passphrase_button")
        )
        self.copy_passphrase_button.setAutoDefault(False)
        self.copy_passphrase_button.clicked.connect(self.copy_passphrase)
        phrase_row = QtWidgets.QHBoxLayout()
        phrase_row.setSpacing(8)
        phrase_row.addWidget(self.passphrase_label, 1)
        phrase_row.addWidget(
            self.copy_passphrase_button, alignment=QtCore.Qt.AlignmentFlag.AlignTop
        )
        recovery_layout = QtWidgets.QVBoxLayout()
        recovery_layout.setContentsMargins(12, 12, 12, 12)
        recovery_layout.setSpacing(8)
        recovery_layout.addLayout(phrase_row)
        recovery_layout.addWidget(self.passphrase_warning)
        self.recovery_group.setLayout(recovery_layout)

        self.encrypted_group = QtWidgets.QGroupBox(
            strings._("gui_identity_backup_encrypted_heading")
        )
        self.qr_caption = QtWidgets.QLabel(strings._("gui_identity_backup_qr_caption"))
        self.qr_caption.setWordWrap(True)
        self.qr_label = QtWidgets.QLabel()
        self.qr_label.setScaledContents(False)
        self.qr_label.setMinimumSize(_QR_DISPLAY_SIDE + 24, _QR_DISPLAY_SIDE + 24)
        self.qr_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self._whiten_qr_label()
        encrypted_layout = QtWidgets.QVBoxLayout()
        encrypted_layout.setContentsMargins(12, 12, 12, 12)
        encrypted_layout.setSpacing(12)
        encrypted_layout.addWidget(self.qr_caption)
        encrypted_layout.addWidget(
            self.qr_label, alignment=QtCore.Qt.AlignmentFlag.AlignHCenter
        )
        self.encrypted_group.setLayout(encrypted_layout)

        self.status_label = QtWidgets.QLabel(strings._("gui_identity_backup_encrypting"))
        self.status_label.setWordWrap(True)

        self.save_button = QtWidgets.QPushButton(
            strings._("gui_identity_backup_save_button")
        )
        self.save_button.setDefault(True)
        self.save_button.setAutoDefault(True)
        self.save_button.clicked.connect(self.save_to_file)

        self.save_qr_button = QtWidgets.QPushButton(
            strings._("gui_identity_backup_save_qr_button")
        )
        self.save_qr_button.setAutoDefault(False)
        self.save_qr_button.clicked.connect(self.save_qr_image)

        self.copy_encrypted_button = QtWidgets.QPushButton(
            strings._("gui_identity_backup_copy_encrypted_button")
        )
        self.copy_encrypted_button.setAutoDefault(False)
        self.copy_encrypted_button.clicked.connect(self.copy_encrypted_text)

        self.regenerate_button = QtWidgets.QPushButton(
            strings._("gui_identity_backup_regenerate_button")
        )
        self.regenerate_button.setAutoDefault(False)
        self.regenerate_button.clicked.connect(self.regenerate_passphrase)

        self.save_to_saved_services_button = QtWidgets.QPushButton(
            strings._("gui_identity_backup_save_archive_button")
        )
        self.save_to_saved_services_button.setAutoDefault(False)
        self.save_to_saved_services_button.clicked.connect(
            self.save_to_saved_services_clicked
        )

        self.close_button = QtWidgets.QPushButton(
            strings._("gui_identity_backup_close_button")
        )
        self.close_button.setAutoDefault(False)
        self.close_button.clicked.connect(self.accept)

        primary_row = QtWidgets.QHBoxLayout()
        primary_row.setSpacing(8)
        primary_row.addWidget(self.save_button)
        primary_row.addStretch()

        secondary_row = QtWidgets.QHBoxLayout()
        secondary_row.setSpacing(8)
        secondary_row.addWidget(self.save_qr_button)
        secondary_row.addWidget(self.copy_encrypted_button)
        secondary_row.addWidget(self.regenerate_button)
        secondary_row.addWidget(self.save_to_saved_services_button)
        secondary_row.addStretch()
        secondary_row.addWidget(self.close_button)

        self.advanced_toggle = QtWidgets.QPushButton(
            strings._("gui_identity_backup_advanced_show")
        )
        self.advanced_toggle.setAutoDefault(False)
        self.advanced_toggle.setCheckable(True)
        self.advanced_toggle.setChecked(False)
        self.advanced_toggle.clicked.connect(self._toggle_advanced)
        self.advanced_details = QtWidgets.QLabel(
            strings._("gui_identity_backup_advanced_details")
        )
        self.advanced_details.setWordWrap(True)
        self.advanced_text = QtWidgets.QPlainTextEdit()
        self.advanced_text.setReadOnly(True)
        self.advanced_text.setFont(fixed)
        self.advanced_text.setMinimumHeight(120)
        self.advanced_text.setPlainText("")
        advanced_layout = QtWidgets.QVBoxLayout()
        advanced_layout.setContentsMargins(0, 8, 0, 0)
        advanced_layout.setSpacing(8)
        advanced_layout.addWidget(self.advanced_details)
        advanced_layout.addWidget(self.advanced_text)
        self.advanced_widget = QtWidgets.QWidget()
        self.advanced_widget.setLayout(advanced_layout)
        self.advanced_widget.hide()

        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)
        layout.addWidget(self.instructions)
        layout.addWidget(self.local_encryption_label)
        layout.addSpacing(4)
        layout.addWidget(self.recovery_group)
        layout.addWidget(self.encrypted_group)
        layout.addWidget(self.status_label)
        layout.addLayout(primary_row)
        layout.addLayout(secondary_row)
        layout.addWidget(self.advanced_toggle)
        layout.addWidget(self.advanced_widget)
        self.setLayout(layout)

        self._set_busy(True)
        self._start_encryption(passphrase)

    def showEvent(self, event):
        super(ExportIdentityBackupDialog, self).showEvent(event)
        self._whiten_qr_label()
        if not self.is_busy and self.pending_bytes is not None:
            self.save_button.setDefault(True)

    def _whiten_qr_label(self):
        """Keep the QR plate white in light and dark palettes."""
        white = QtGui.QColor(255, 255, 255)
        palette = self.qr_label.palette()
        palette.setColor(QtGui.QPalette.ColorRole.Window, white)
        palette.setColor(QtGui.QPalette.ColorRole.Base, white)
        self.qr_label.setPalette(palette)
        self.qr_label.setAutoFillBackground(True)

    def _toggle_advanced(self):
        show = self.advanced_toggle.isChecked()
        self.advanced_widget.setVisible(show)
        if show:
            self.advanced_toggle.setText(strings._("gui_identity_backup_advanced_hide"))
        else:
            self.advanced_toggle.setText(strings._("gui_identity_backup_advanced_show"))

    def _fill_advanced(self, envelope):
        """Show the envelope and its public parameters. Nothing is logged."""
        details = envelope
        try:
            parsed = json.loads(envelope)
        except Exception:
            parsed = None
        if type(parsed) is dict:
            lines = [
                "v: {0}".format(parsed.get("v")),
                "kdf: {0}".format(parsed.get("kdf")),
                "t: {0}".format(parsed.get("t")),
                "m: {0}".format(parsed.get("m")),
                "p: {0}".format(parsed.get("p")),
                "",
                envelope,
            ]
            details = "\n".join(str(line) for line in lines)
        self.advanced_text.setPlainText(details)

    def _apply_qr_pixmap(self, text):
        """
        Draw the QR black on white, keep its quiet zone, and scale crisply.

        ``setScaledContents`` uses smooth scaling, so the pixmap is scaled
        here with ``Qt.FastTransformation`` instead.
        """
        source = qr_code_pixmap(text)
        self._qr_source = source
        scaled = source.scaled(
            _QR_DISPLAY_SIDE,
            _QR_DISPLAY_SIDE,
            QtCore.Qt.AspectRatioMode.KeepAspectRatio,
            QtCore.Qt.TransformationMode.FastTransformation,
        )
        self._whiten_qr_label()
        self.qr_label.setPixmap(scaled)

    def _set_busy(self, busy):
        self.is_busy = busy
        ready = (not busy) and self.pending_bytes is not None
        self.save_button.setEnabled(ready)
        self.save_qr_button.setEnabled(ready)
        self.copy_encrypted_button.setEnabled(ready)
        self.copy_passphrase_button.setEnabled((not busy) and bool(self.passphrase))
        self.regenerate_button.setEnabled(not busy)
        self.save_to_saved_services_button.setEnabled(not busy)
        if ready:
            self.save_button.setDefault(True)
        if busy:
            self.status_label.setText(strings._("gui_identity_backup_encrypting"))
            self.status_label.show()
        else:
            self.status_label.hide()

    def _start_encryption(self, passphrase):
        """
        Encrypt on a new QThread. The previous payload stays in place until
        this run succeeds, and Save stays disabled while it runs.
        """
        self._set_busy(True)
        self._next_passphrase = passphrase
        thread = EncryptIdentityThread(self.identity, passphrase)
        self.encrypt_thread = thread
        self.encrypt_threads.append(thread)
        thread.success.connect(
            self._encrypt_succeeded, QtCore.Qt.ConnectionType.QueuedConnection
        )
        thread.error.connect(
            self._encrypt_failed, QtCore.Qt.ConnectionType.QueuedConnection
        )
        thread.start()

    def _encrypt_succeeded(self, envelope):
        thread = self.sender()
        if not self._accepting_results or thread is not self.encrypt_thread:
            return
        if type(envelope) is not str:
            self._encrypt_failed()
            return
        # One assignment feeds both the QR and the bytes a save would write.
        pending = envelope.encode("utf-8")
        self.passphrase = self._next_passphrase
        self.envelope = envelope
        self.qr_text = envelope
        self.pending_bytes = pending
        self.passphrase_label.setText(self.passphrase)
        self._apply_qr_pixmap(self.qr_text)
        self._fill_advanced(envelope)
        self.generation += 1
        self._set_busy(False)

    def _encrypt_failed(self):
        thread = self.sender()
        if thread is not None and thread is not self.encrypt_thread:
            return
        if not self._accepting_results:
            return
        self._next_passphrase = self.passphrase
        self._set_busy(False)
        Alert(self.common, strings._("gui_identity_backup_error"))

    def regenerate_passphrase(self):
        """
        New passphrase, new salt, and new nonce. Replaces the QR and the
        pending save payload only after the new envelope is ready.
        """
        if self.is_busy:
            return
        self.common.log("ExportIdentityBackupDialog", "regenerate_passphrase")
        self._start_encryption(generate_passphrase())

    def save_to_file(self):
        """
        Write the pending envelope bytes. No trailing newline is added, and
        the passphrase is not written.
        """
        if self.is_busy or self.pending_bytes is None:
            return
        filename, _selected_filter = QtWidgets.QFileDialog.getSaveFileName(
            self,
            strings._("gui_identity_backup_save_file_title"),
            "onionshare-identity-backup.json",
            strings._("gui_identity_backup_save_file_filter"),
        )
        if not filename:
            return
        try:
            _write_exact_bytes(filename, self.pending_bytes)
        except OSError:
            Alert(self.common, strings._("gui_identity_backup_save_error"))
            return
        self.common.log("ExportIdentityBackupDialog", "save_to_file")

    def save_qr_image(self):
        """Save the unscaled black-on-white QR, including its quiet zone."""
        if self.is_busy or self._qr_source is None or self.qr_text is None:
            return
        filename, _selected_filter = QtWidgets.QFileDialog.getSaveFileName(
            self,
            strings._("gui_identity_backup_save_qr_title"),
            "onionshare-identity-backup-qr.png",
            strings._("gui_identity_backup_save_qr_filter"),
        )
        if not filename:
            return
        if not self._qr_source.save(filename, "PNG"):
            Alert(self.common, strings._("gui_identity_backup_save_qr_error"))
            return
        self.common.log("ExportIdentityBackupDialog", "save_qr_image")

    def copy_passphrase(self):
        """Copy the recovery phrase. The phrase is not logged."""
        if self.is_busy or not self.passphrase:
            return
        clipboard = QtWidgets.QApplication.clipboard()
        if clipboard is None:
            return
        clipboard.setText(self.passphrase)

    def copy_encrypted_text(self):
        """Copy the envelope string. It matches the backup file bytes."""
        if self.is_busy or not self.qr_text:
            return
        clipboard = QtWidgets.QApplication.clipboard()
        if clipboard is None:
            return
        clipboard.setText(self.qr_text)

    def _disconnect_thread(self, thread):
        if thread is None:
            return
        try:
            thread.success.disconnect(self._encrypt_succeeded)
        except (RuntimeError, TypeError):
            pass
        try:
            thread.error.disconnect(self._encrypt_failed)
        except (RuntimeError, TypeError):
            pass

    def _reconnect_thread(self, thread):
        if thread is None:
            return
        thread.success.connect(
            self._encrypt_succeeded, QtCore.Qt.ConnectionType.QueuedConnection
        )
        thread.error.connect(
            self._encrypt_failed, QtCore.Qt.ConnectionType.QueuedConnection
        )

    def _any_thread_running(self):
        for thread in self.encrypt_threads:
            try:
                if thread.isRunning():
                    return True
            except RuntimeError:
                continue
        return False

    def shutdown_encrypt_thread(self, abandon=False):
        """
        Stop accepting encrypt results and wait until the worker has finished.

        accept, reject, and closeEvent all use this. A nested call (closeEvent
        leading into reject) does not wait a second time. A timed-out user
        close leaves the dialog open and accepting results again. Quit and
        DeferredDelete pass abandon=True: the worker stays disconnected and a
        still-running QThread is kept alive until it finishes.
        Returns True when no encrypt thread is still running.
        """
        if self._shutdown_complete:
            return not self._any_thread_running()
        if self._shutting_down:
            return not self._any_thread_running()

        self._shutting_down = True
        self._accepting_results = False
        threads = list(self.encrypt_threads)
        for thread in threads:
            self._disconnect_thread(thread)

        abandoned = False
        for thread in threads:
            try:
                running = thread.isRunning()
            except RuntimeError:
                continue
            if not running:
                continue
            wait_ms = _ABANDON_THREAD_WAIT_MS if abandon else _ENCRYPT_THREAD_WAIT_MS
            finished = thread.wait(wait_ms)
            try:
                still_running = thread.isRunning()
            except RuntimeError:
                still_running = False
            if not finished or still_running:
                if abandon:
                    try:
                        if hasattr(thread, "_identity"):
                            thread._identity = None
                    except RuntimeError:
                        pass
                    _retain_thread(thread)
                    abandoned = True
                    continue
                self._shutting_down = False
                self._accepting_results = True
                self._reconnect_thread(self.encrypt_thread)
                return False

        if abandoned:
            # Do not reconnect. A later close must not wait or re-arm.
            self._accepting_results = False
            self._shutting_down = False
            self._shutdown_complete = True
            return False

        self._shutdown_complete = True
        self._shutting_down = False
        return True

    def _clear_sensitive_fields(self):
        """Drop identity and passphrase references. This does not zero memory."""
        self.identity = None
        self.passphrase = None
        self._next_passphrase = None
        label = getattr(self, "passphrase_label", None)
        if label is not None:
            try:
                label.setText("")
            except RuntimeError:
                pass
        advanced = getattr(self, "advanced_text", None)
        if advanced is not None:
            try:
                advanced.setPlainText("")
            except RuntimeError:
                pass

    def accept(self):
        if self._close_in_progress:
            return
        if not self.shutdown_encrypt_thread():
            return
        self._clear_sensitive_fields()
        self._close_in_progress = True
        super(ExportIdentityBackupDialog, self).accept()

    def reject(self):
        # closeEvent's QDialog implementation calls reject. The outer close
        # already waited; calling wait again from here would nest.
        if self._close_in_progress:
            self._clear_sensitive_fields()
            super(ExportIdentityBackupDialog, self).reject()
            return
        if not self.shutdown_encrypt_thread():
            return
        self._clear_sensitive_fields()
        self._close_in_progress = True
        super(ExportIdentityBackupDialog, self).reject()

    def closeEvent(self, event):
        if self._close_in_progress:
            super(ExportIdentityBackupDialog, self).closeEvent(event)
            return
        if not self.shutdown_encrypt_thread():
            event.ignore()
            return
        self._clear_sensitive_fields()
        self._close_in_progress = True
        super(ExportIdentityBackupDialog, self).closeEvent(event)

    def save_to_saved_services_clicked(self):
        if self.is_busy:
            return
        self.common.log("ExportIdentityBackupDialog", "save_to_saved_services_clicked")
        save_identity_to_saved_services(self.common, self, self.identity)

