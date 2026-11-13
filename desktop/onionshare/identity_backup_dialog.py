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
        archive.add(identity, label, replace=False)
    except SavedServicesError as error:
        if str(error) != "saved service already exists":
            Alert(common, strings._("gui_identity_backup_archive_error"))
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
            archive.add(identity, label, replace=True)
        except SavedServicesError:
            Alert(common, strings._("gui_identity_backup_archive_error"))
            return False

    Alert(common, strings._("gui_identity_backup_archive_saved"))
    return True


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

        self.common.log("ExportIdentityBackupDialog", "__init__")

        self.setWindowTitle(strings._("gui_identity_backup_dialog_title"))
        self.setWindowIcon(QtGui.QIcon(GuiCommon.get_resource_path("images/logo.png")))
        self.setMinimumWidth(420)

        self.instructions = QtWidgets.QLabel(
            strings._("gui_identity_backup_instructions")
        )
        self.instructions.setWordWrap(True)

        passphrase_heading = QtWidgets.QLabel(
            strings._("gui_identity_backup_passphrase_label")
        )
        self.passphrase_label = QtWidgets.QLabel("")
        self.passphrase_label.setFont(
            QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont)
        )
        self.passphrase_label.setWordWrap(True)
        self.passphrase_label.setTextInteractionFlags(
            QtCore.Qt.TextInteractionFlag.TextSelectableByMouse
            | QtCore.Qt.TextInteractionFlag.TextSelectableByKeyboard
        )

        self.qr_caption = QtWidgets.QLabel(strings._("gui_identity_backup_qr_caption"))
        self.qr_caption.setWordWrap(True)

        self.qr_label = QtWidgets.QLabel()
        self.qr_label.setScaledContents(True)
        self.qr_label.setFixedSize(350, 350)
        self.qr_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)

        self.status_label = QtWidgets.QLabel(strings._("gui_identity_backup_encrypting"))
        self.status_label.setWordWrap(True)

        self.save_button = QtWidgets.QPushButton(
            strings._("gui_identity_backup_save_button")
        )
        self.save_button.clicked.connect(self.save_to_file)

        self.regenerate_button = QtWidgets.QPushButton(
            strings._("gui_identity_backup_regenerate_button")
        )
        self.regenerate_button.clicked.connect(self.regenerate_passphrase)

        self.save_to_saved_services_button = QtWidgets.QPushButton(
            strings._("gui_identity_backup_save_archive_button")
        )
        self.save_to_saved_services_button.clicked.connect(
            self.save_to_saved_services_clicked
        )

        self.close_button = QtWidgets.QPushButton(
            strings._("gui_identity_backup_close_button")
        )
        self.close_button.clicked.connect(self.accept)

        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.regenerate_button)
        button_layout.addWidget(self.save_to_saved_services_button)
        button_layout.addStretch()
        button_layout.addWidget(self.close_button)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.instructions)
        layout.addWidget(passphrase_heading)
        layout.addWidget(self.passphrase_label)
        layout.addWidget(self.qr_caption)
        layout.addWidget(self.qr_label, alignment=QtCore.Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(self.status_label)
        layout.addLayout(button_layout)
        self.setLayout(layout)

        self._set_busy(True)
        self._start_encryption(passphrase)

    def _set_busy(self, busy):
        self.is_busy = busy
        self.save_button.setEnabled(not busy and self.pending_bytes is not None)
        self.regenerate_button.setEnabled(not busy)
        self.save_to_saved_services_button.setEnabled(not busy)
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
        thread.success.connect(self._encrypt_succeeded)
        thread.error.connect(self._encrypt_failed)
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
        self.qr_label.setPixmap(qr_code_pixmap(self.qr_text))
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
            with open(filename, "wb") as handle:
                handle.write(self.pending_bytes)
        except OSError:
            Alert(self.common, strings._("gui_identity_backup_save_error"))
            return
        self.common.log("ExportIdentityBackupDialog", "save_to_file")

    def save_to_saved_services_clicked(self):
        if self.is_busy:
            return
        self.common.log("ExportIdentityBackupDialog", "save_to_saved_services_clicked")
        save_identity_to_saved_services(self.common, self, self.identity)

    def closeEvent(self, event):
        self._accepting_results = False
        thread = self.encrypt_thread
        if thread is not None and thread.isRunning():
            thread.wait(180000)
        super(ExportIdentityBackupDialog, self).closeEvent(event)
