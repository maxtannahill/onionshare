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

Import an encrypted identity backup from a file or from pasted text.

The passphrase is one string, the hyphen-joined words. This dialog does
not split on hyphens. decrypt_identity strips only leading and trailing
whitespace. Decryption runs on DecryptIdentityThread. run() does not
touch widgets. Close, Escape, and shutdown_decrypt_thread disconnect the
worker before waiting, and a queued result that arrives afterwards is
ignored, so it cannot alert, write an archive record, or open a tab.

Side effects happen only after a successful decrypt, in this order:
plaintext-archive disclosure, label, then SavedServices.add (or no write
when the archived identity keys are already identical, or when the user
declines a replace), then TabWidget.open_saved_service. That helper is
called unchanged and is the only way a tab is opened. This module does
not call start_server and has no camera or QR-decoding path. Passphrases,
envelopes, and identity material are not logged.
"""

import os

from PySide6 import QtCore, QtGui, QtWidgets

from onionshare_cli.identity_backup import decrypt_identity, validate_identity
from onionshare_cli.identity_backup import IdentityBackupError
from onionshare_cli.saved_services import SavedServices, SavedServicesError

from . import strings
from .gui_common import GuiCommon
from .widgets import Alert


# Readers reject envelopes larger than this before parsing. A chosen file
# is capped here, before UTF-8 decoding, so a huge file is not decoded.
_MAX_ENVELOPE_BYTES = 8192

# One timed wait for the Argon2id worker. Interactive KDF is far shorter
# than this; if it is still running afterwards the dialog stays open.
_DECRYPT_THREAD_WAIT_MS = 180000

_IDENTITY_KEYS = (
    "mode",
    "service_id",
    "private_key",
    "client_auth_priv_key",
    "client_auth_pub_key",
    "public",
)

_MODE_STRINGS = {
    "share": "gui_tab_name_share",
    "receive": "gui_tab_name_receive",
    "website": "gui_tab_name_website",
    "chat": "gui_tab_name_chat",
}


class _ImportInputError(Exception):
    """The file or pasted text cannot be decrypted. The UI uses one string."""


class DecryptIdentityThread(QtCore.QThread):
    """
    Run decrypt_identity off the GUI thread.

    Modeled on EncryptIdentityThread: run() emits a result and does not
    touch widgets. The passphrase and envelope are dropped before the
    KDF returns, and neither is logged. The identity stays on this object
    until the GUI slot copies it; the signal itself carries no payload.
    """

    success = QtCore.Signal()
    error = QtCore.Signal()

    def __init__(self, text, passphrase):
        super(DecryptIdentityThread, self).__init__()
        self._text = text
        self._passphrase = passphrase
        self._identity = None
        # Set inside run() to the QThread that actually decrypted.
        self.worker_thread = None

    def run(self):
        self.worker_thread = QtCore.QThread.currentThread()
        text = self._text
        passphrase = self._passphrase
        self._text = None
        self._passphrase = None
        try:
            identity = decrypt_identity(text, passphrase)
        except Exception:
            self.error.emit()
            return
        self._identity = identity
        self.success.emit()


def read_envelope_file(path):
    """
    Read a backup file as text.

    At most _MAX_ENVELOPE_BYTES + 1 bytes are read. A longer file raises
    before those bytes are decoded as UTF-8. Decoding is strict. The path
    and the bytes are not logged.
    """
    try:
        with open(path, "rb") as handle:
            payload = handle.read(_MAX_ENVELOPE_BYTES + 1)
    except OSError:
        raise _ImportInputError()
    if len(payload) > _MAX_ENVELOPE_BYTES:
        raise _ImportInputError()
    try:
        return payload.decode("utf-8")
    except UnicodeError:
        raise _ImportInputError()


def _within_cap(text):
    """True when text is a str of at most 8192 UTF-8 bytes."""
    if type(text) is not str:
        return False
    try:
        encoded = text.encode("utf-8")
    except UnicodeError:
        return False
    return len(text) <= _MAX_ENVELOPE_BYTES and len(encoded) <= _MAX_ENVELOPE_BYTES


def _copy_identity(identity):
    """Return the six identity keys, or None when the shape is wrong."""
    if type(identity) is not dict or set(identity) != set(_IDENTITY_KEYS):
        return None
    return {key: identity[key] for key in _IDENTITY_KEYS}


def _same_identity(record, identity):
    """True when the archived record has the same six identity keys."""
    for key in _IDENTITY_KEYS:
        if record.get(key) != identity[key]:
            return False
    return True


def _default_label(identity):
    """A mode name for the label field. Empty when the mode is unknown."""
    key = _MODE_STRINGS.get(identity.get("mode"))
    if key is None:
        return ""
    return strings._(key)


def _archive_failure_message(error):
    """Map a SavedServicesError to fixed UI text. The error text is not logged."""
    if str(error) == "invalid label":
        return strings._("gui_identity_backup_invalid_label")
    return strings._("gui_identity_backup_archive_error")


def _confirm(common, message, icon, buttons, accept_button):
    box = Alert(
        common,
        message,
        icon=icon,
        buttons=buttons,
        autostart=False,
    )
    return box.exec() == accept_button


class ImportIdentityDialog(QtWidgets.QDialog):
    """
    Import a backup from a file or from pasted envelope text.

    The constructor does not call exec() and does not decrypt. The caller
    shows the dialog. Import reads the selected source, then decrypts on
    DecryptIdentityThread.
    """

    def __init__(self, common, tab_widget, on_imported=None, parent=None):
        super(ImportIdentityDialog, self).__init__(parent)
        self.common = common
        self.tab_widget = tab_widget
        self._on_imported = on_imported
        self._envelope_path = None
        self.decrypt_thread = None
        self.decrypt_threads = []
        self.is_busy = False
        self._accepting_results = True
        self._shutting_down = False
        self._shutdown_complete = False
        self._close_in_progress = False

        self.common.log("ImportIdentityDialog", "__init__")

        self.setWindowTitle(strings._("gui_identity_import_dialog_title"))
        self.setWindowIcon(QtGui.QIcon(GuiCommon.get_resource_path("images/logo.png")))
        self.setMinimumWidth(460)
        self.setModal(True)

        self.instructions = QtWidgets.QLabel(
            strings._("gui_identity_import_instructions")
        )
        self.instructions.setWordWrap(True)

        self.paste_radio = QtWidgets.QRadioButton(
            strings._("gui_identity_import_paste_radio")
        )
        self.paste_radio.setObjectName("identity_import_paste_radio")
        self.file_radio = QtWidgets.QRadioButton(
            strings._("gui_identity_import_file_radio")
        )
        self.file_radio.setObjectName("identity_import_file_radio")
        self.source_group = QtWidgets.QButtonGroup(self)
        self.source_group.addButton(self.paste_radio)
        self.source_group.addButton(self.file_radio)
        self.paste_radio.setChecked(True)
        self.paste_radio.toggled.connect(lambda _checked: self._apply_source_enabled())

        self.envelope_edit = QtWidgets.QPlainTextEdit()
        self.envelope_edit.setObjectName("identity_import_paste_edit")
        self.envelope_edit.setPlaceholderText(
            strings._("gui_identity_import_paste_label")
        )
        self.envelope_edit.setFixedHeight(120)

        self.choose_file_button = QtWidgets.QPushButton(
            strings._("gui_identity_import_choose_file_button")
        )
        self.choose_file_button.setObjectName("identity_import_choose_file_button")
        self.choose_file_button.clicked.connect(self.choose_file)
        self.choose_file_button.setAutoDefault(False)
        self.file_label = QtWidgets.QLabel(strings._("gui_identity_import_no_file"))
        self.file_label.setObjectName("identity_import_file_label")
        self.file_label.setWordWrap(True)
        file_row = QtWidgets.QHBoxLayout()
        file_row.addWidget(self.choose_file_button)
        file_row.addWidget(self.file_label, stretch=1)

        passphrase_heading = QtWidgets.QLabel(
            strings._("gui_identity_import_passphrase_label")
        )
        # One field. The text is handed to decrypt_identity unchanged.
        self.passphrase_edit = QtWidgets.QLineEdit()
        self.passphrase_edit.setObjectName("identity_import_passphrase_edit")
        self.passphrase_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Normal)

        self.status_label = QtWidgets.QLabel(
            strings._("gui_identity_import_decrypting")
        )
        self.status_label.setWordWrap(True)
        self.status_label.hide()

        self.import_button = QtWidgets.QPushButton(
            strings._("gui_identity_import_button")
        )
        self.import_button.setObjectName("identity_import_import_button")
        self.import_button.clicked.connect(self.import_clicked)
        self.import_button.setAutoDefault(False)
        self.close_button = QtWidgets.QPushButton(
            strings._("gui_identity_import_close_button")
        )
        self.close_button.setObjectName("identity_import_close_button")
        self.close_button.clicked.connect(self.reject)
        self.close_button.setAutoDefault(False)

        button_row = QtWidgets.QHBoxLayout()
        button_row.addWidget(self.import_button)
        button_row.addStretch()
        button_row.addWidget(self.close_button)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.instructions)
        layout.addWidget(self.paste_radio)
        layout.addWidget(self.envelope_edit)
        layout.addWidget(self.file_radio)
        layout.addLayout(file_row)
        layout.addWidget(passphrase_heading)
        layout.addWidget(self.passphrase_edit)
        layout.addWidget(self.status_label)
        layout.addLayout(button_row)
        self.setLayout(layout)
        self._apply_source_enabled()

    def _apply_source_enabled(self):
        if self.is_busy:
            return
        paste = self.paste_radio.isChecked()
        self.envelope_edit.setEnabled(paste)
        self.choose_file_button.setEnabled(not paste)

    def _set_busy(self, busy):
        self.is_busy = busy
        self.paste_radio.setEnabled(not busy)
        self.file_radio.setEnabled(not busy)
        self.passphrase_edit.setEnabled(not busy)
        self.import_button.setEnabled(not busy)
        if busy:
            self.envelope_edit.setEnabled(False)
            self.choose_file_button.setEnabled(False)
            self.status_label.setText(strings._("gui_identity_import_decrypting"))
            self.status_label.show()
        else:
            self.status_label.hide()
            self._apply_source_enabled()

    def choose_file(self):
        """Remember a path. The bytes are read later, when Import is clicked."""
        if self.is_busy:
            return
        filename, _selected_filter = QtWidgets.QFileDialog.getOpenFileName(
            self,
            strings._("gui_identity_import_choose_file_title"),
            "",
            strings._("gui_identity_import_choose_file_filter"),
        )
        if not filename:
            return
        self._envelope_path = filename
        self.file_label.setText(os.path.basename(filename))
        self.common.log("ImportIdentityDialog", "choose_file")

    def import_clicked(self):
        """Read the selected source and decrypt it on a worker thread."""
        if self.is_busy or not self._accepting_results:
            return
        self.common.log("ImportIdentityDialog", "import_clicked")
        try:
            text = self._envelope_text()
        except _ImportInputError:
            self._show_generic_error()
            return
        self._start_decrypt(text, self.passphrase_edit.text())

    def _envelope_text(self):
        if self.file_radio.isChecked():
            if not self._envelope_path:
                raise _ImportInputError()
            return read_envelope_file(self._envelope_path)
        text = self.envelope_edit.toPlainText()
        if not _within_cap(text):
            raise _ImportInputError()
        return text

    def _show_generic_error(self):
        if not self._accepting_results:
            return
        self._set_busy(False)
        Alert(self.common, strings._("gui_identity_import_error"))

    def _start_decrypt(self, text, passphrase):
        self._set_busy(True)
        thread = DecryptIdentityThread(text, passphrase)
        self.decrypt_thread = thread
        self.decrypt_threads.append(thread)
        thread.success.connect(
            self._decrypt_succeeded, QtCore.Qt.ConnectionType.QueuedConnection
        )
        thread.error.connect(
            self._decrypt_failed, QtCore.Qt.ConnectionType.QueuedConnection
        )
        thread.start()

    def _decrypt_succeeded(self):
        thread = self.sender()
        if not self._accepting_results or thread is not self.decrypt_thread:
            return
        identity = getattr(thread, "_identity", None)
        thread._identity = None
        checked = _copy_identity(identity)
        if checked is None:
            self._show_generic_error()
            return
        try:
            checked = validate_identity(checked)
        except IdentityBackupError:
            self._show_generic_error()
            return
        try:
            self._finish_import(checked)
        finally:
            if self._accepting_results:
                self._set_busy(False)

    def _decrypt_failed(self):
        thread = self.sender()
        if thread is not None and thread is not self.decrypt_thread:
            return
        if not self._accepting_results:
            return
        if thread is not None:
            thread._identity = None
        self._show_generic_error()

    def _finish_import(self, identity):
        """
        Disclosure, label, archive, then open.

        Returning before open_saved_service writes nothing and opens nothing,
        except the identical-keys path, which opens without writing. A
        declined replace does neither.
        """
        if not self._accepting_results:
            return
        disclosed = _confirm(
            self.common,
            strings._("gui_identity_backup_archive_disclosure"),
            QtWidgets.QMessageBox.Icon.Warning,
            QtWidgets.QMessageBox.StandardButton.Ok
            | QtWidgets.QMessageBox.StandardButton.Cancel,
            QtWidgets.QMessageBox.StandardButton.Ok,
        )
        if not disclosed or not self._accepting_results:
            return

        label, accepted = QtWidgets.QInputDialog.getText(
            self,
            strings._("gui_identity_backup_archive_label_title"),
            strings._("gui_identity_backup_archive_label_prompt"),
            QtWidgets.QLineEdit.EchoMode.Normal,
            _default_label(identity),
        )
        if not accepted or not self._accepting_results:
            return
        if type(label) is not str:
            return

        if not self._commit_archive(identity, label):
            return
        if not self._accepting_results:
            return
        self.common.log("ImportIdentityDialog", "open_saved_service")
        self.tab_widget.open_saved_service(identity, label)
        if self._on_imported is not None:
            self._on_imported()

    def _listed(self, service_id):
        try:
            ids = self.common.settings.get("saved_services")
        except KeyError:
            return False
        return type(ids) is list and service_id in ids

    def _commit_archive(self, identity, label):
        """
        Store the identity, or skip the write when the keys already match.

        Returns True when the caller should open a tab. Returns False when
        nothing was written and nothing should be opened.
        """
        if not self._accepting_results:
            return False
        archive = SavedServices(self.common, self.common.settings)
        service_id = identity["service_id"]
        listed = self._listed(service_id)
        try:
            existing = archive.get(service_id)
        except SavedServicesError as error:
            if str(error) != "saved service record was not found":
                Alert(self.common, strings._("gui_identity_backup_archive_error"))
                return False
            existing = None

        if existing is not None and _same_identity(existing, identity):
            self.common.log("ImportIdentityDialog", "identical_archive")
            return True

        if existing is not None or listed:
            replace = _confirm(
                self.common,
                strings._("gui_identity_backup_archive_duplicate"),
                QtWidgets.QMessageBox.Icon.Warning,
                QtWidgets.QMessageBox.StandardButton.Yes
                | QtWidgets.QMessageBox.StandardButton.No,
                QtWidgets.QMessageBox.StandardButton.Yes,
            )
            if not replace or not self._accepting_results:
                if not replace:
                    Alert(
                        self.common,
                        strings._("gui_identity_backup_archive_not_replaced"),
                    )
                return False
            try:
                archive.add(identity, label, replace=True)
            except SavedServicesError as error:
                Alert(self.common, _archive_failure_message(error))
                return False
            except Exception:
                Alert(self.common, strings._("gui_identity_backup_archive_error"))
                return False
            self.common.log("ImportIdentityDialog", "archive_replaced")
            return True

        try:
            archive.add(identity, label, replace=False)
        except SavedServicesError as error:
            Alert(self.common, _archive_failure_message(error))
            return False
        except Exception:
            Alert(self.common, strings._("gui_identity_backup_archive_error"))
            return False
        self.common.log("ImportIdentityDialog", "archive_added")
        return True

    def _disconnect_thread(self, thread):
        if thread is None:
            return
        try:
            thread.success.disconnect(self._decrypt_succeeded)
        except (RuntimeError, TypeError):
            pass
        try:
            thread.error.disconnect(self._decrypt_failed)
        except (RuntimeError, TypeError):
            pass

    def _reconnect_thread(self, thread):
        if thread is None:
            return
        thread.success.connect(
            self._decrypt_succeeded, QtCore.Qt.ConnectionType.QueuedConnection
        )
        thread.error.connect(
            self._decrypt_failed, QtCore.Qt.ConnectionType.QueuedConnection
        )

    def _any_thread_running(self):
        for thread in self.decrypt_threads:
            try:
                if thread.isRunning():
                    return True
            except RuntimeError:
                continue
        return False

    def shutdown_decrypt_thread(self):
        """
        Stop accepting decrypt results and wait until the worker has finished.

        accept, reject, and closeEvent all use this. A nested call does not
        wait a second time. A timed-out wait leaves the dialog open and
        accepting results again. Returns True when no decrypt thread is
        still running.
        """
        if self._shutdown_complete:
            return not self._any_thread_running()
        if self._shutting_down:
            return not self._any_thread_running()

        self._shutting_down = True
        self._accepting_results = False
        threads = list(self.decrypt_threads)
        for thread in threads:
            self._disconnect_thread(thread)

        for thread in threads:
            try:
                running = thread.isRunning()
            except RuntimeError:
                continue
            if not running:
                continue
            finished = thread.wait(_DECRYPT_THREAD_WAIT_MS)
            try:
                still_running = thread.isRunning()
            except RuntimeError:
                still_running = False
            if not finished or still_running:
                self._shutting_down = False
                self._accepting_results = True
                self._reconnect_thread(self.decrypt_thread)
                return False

        self._shutdown_complete = True
        self._shutting_down = False
        return True

    def accept(self):
        if self._close_in_progress:
            return
        if not self.shutdown_decrypt_thread():
            return
        self._close_in_progress = True
        super(ImportIdentityDialog, self).accept()

    def reject(self):
        # closeEvent's QDialog implementation calls reject. The outer close
        # already waited; calling wait again from here would nest.
        if self._close_in_progress:
            super(ImportIdentityDialog, self).reject()
            return
        if not self.shutdown_decrypt_thread():
            return
        self._close_in_progress = True
        super(ImportIdentityDialog, self).reject()

    def closeEvent(self, event):
        if self._close_in_progress:
            super(ImportIdentityDialog, self).closeEvent(event)
            return
        if not self.shutdown_decrypt_thread():
            event.ignore()
            return
        self._close_in_progress = True
        super(ImportIdentityDialog, self).closeEvent(event)
