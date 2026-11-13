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

Saved Services manager.

Records under ``<data_dir>/saved_services/`` are stored unencrypted on
this computer, like persistent tabs. The onion private key and
client-auth keys inside a record are plaintext. This archive is not an
encrypted backup. The disclosure in this dialog says so.

Open calls ``TabWidget.open_saved_service`` and does not call
``start_server``. Import backup opens ImportIdentityDialog, which
decrypts on a worker thread and then calls that same helper. Neither
path starts a server.
"""

from PySide6 import QtCore, QtWidgets

from onionshare_cli.saved_services import SavedServices, SavedServicesError

from . import strings
from .identity_import_dialog import ImportIdentityDialog
from .widgets import Alert


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


def _confirm(common, message, icon, buttons, accept_button):
    box = Alert(
        common,
        message,
        icon=icon,
        buttons=buttons,
        autostart=False,
    )
    return box.exec() == accept_button


def _fixed_error(error, invalid_label, generic):
    """Map a SavedServicesError to a fixed string. The error text is not logged."""
    if str(error) == "invalid label":
        return invalid_label
    return generic


class SavedServicesDialog(QtWidgets.QDialog):
    """
    List archived services and open, rename, or delete them.

    The plaintext-archive disclosure stays visible. Nothing secret is logged.
    This constructor does not call exec(); the caller shows the dialog.
    """

    def __init__(self, common, tab_widget, parent=None):
        super(SavedServicesDialog, self).__init__(parent)
        self.common = common
        self.common.log("SavedServicesDialog", "__init__")
        self.tab_widget = tab_widget
        self._records = {}
        self.import_dialog = None
        self._close_in_progress = False

        self.setWindowTitle(strings._("gui_saved_services_dialog_title"))
        self.setModal(True)
        self.resize(760, 440)

        self.disclosure_label = QtWidgets.QLabel(
            strings._("gui_saved_services_disclosure")
        )
        self.disclosure_label.setObjectName("saved_services_disclosure")
        self.disclosure_label.setWordWrap(True)

        self.empty_label = QtWidgets.QLabel(strings._("gui_saved_services_empty"))
        self.empty_label.setWordWrap(True)

        self.table = QtWidgets.QTableWidget(0, 5)
        self.table.setObjectName("saved_services_table")
        self.table.setHorizontalHeaderLabels(
            [
                strings._("gui_saved_services_column_label"),
                strings._("gui_saved_services_column_mode"),
                strings._("gui_saved_services_column_service_id"),
                strings._("gui_saved_services_column_saved_at"),
                strings._("gui_saved_services_column_visibility"),
            ]
        )
        self.table.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.table.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.SingleSelection
        )
        self.table.setEditTriggers(
            QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.table.verticalHeader().setVisible(False)
        self.table.setWordWrap(False)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(
            2, QtWidgets.QHeaderView.ResizeMode.Stretch
        )
        self.table.itemSelectionChanged.connect(self._update_buttons)
        self.table.itemDoubleClicked.connect(lambda _item: self.open_selected())

        self.import_button = QtWidgets.QPushButton(
            strings._("gui_saved_services_import_button")
        )
        self.import_button.setObjectName("saved_services_import_button")
        self.import_button.clicked.connect(self.import_clicked)
        self.open_button = QtWidgets.QPushButton(
            strings._("gui_saved_services_open_button")
        )
        self.open_button.setObjectName("saved_services_open_button")
        self.open_button.clicked.connect(self.open_selected)
        self.rename_button = QtWidgets.QPushButton(
            strings._("gui_saved_services_rename_button")
        )
        self.rename_button.setObjectName("saved_services_rename_button")
        self.rename_button.clicked.connect(self.rename_selected)
        self.delete_button = QtWidgets.QPushButton(
            strings._("gui_saved_services_delete_button")
        )
        self.delete_button.setObjectName("saved_services_delete_button")
        self.delete_button.clicked.connect(self.delete_selected)
        self.close_button = QtWidgets.QPushButton(
            strings._("gui_saved_services_close_button")
        )
        self.close_button.clicked.connect(self.reject)

        buttons = QtWidgets.QHBoxLayout()
        buttons.addWidget(self.import_button)
        buttons.addWidget(self.open_button)
        buttons.addWidget(self.rename_button)
        buttons.addWidget(self.delete_button)
        buttons.addStretch()
        buttons.addWidget(self.close_button)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.disclosure_label)
        layout.addWidget(self.empty_label)
        layout.addWidget(self.table)
        layout.addLayout(buttons)
        self.setLayout(layout)

        self.reload()

    def import_clicked(self):
        """Open the backup importer. It decrypts, archives, then opens stopped."""
        self.common.log("SavedServicesDialog", "import_clicked")
        previous = self.import_dialog
        if previous is not None:
            try:
                if not previous.shutdown_decrypt_thread():
                    return
            except RuntimeError:
                pass
        self.import_dialog = ImportIdentityDialog(
            self.common,
            self.tab_widget,
            on_imported=self.reload,
            parent=self,
        )
        self.import_dialog.exec()
        self.reload()

    def shutdown_identity_import(self):
        """
        Wait out an in-progress import decrypt before this dialog is destroyed.

        Returns False when the worker is still running after the timed wait.
        """
        dialog = self.import_dialog
        if dialog is None:
            return True
        try:
            return dialog.shutdown_decrypt_thread()
        except RuntimeError:
            return True

    def reject(self):
        if self._close_in_progress:
            super(SavedServicesDialog, self).reject()
            return
        if not self.shutdown_identity_import():
            return
        self._close_in_progress = True
        super(SavedServicesDialog, self).reject()

    def closeEvent(self, event):
        if self._close_in_progress:
            super(SavedServicesDialog, self).closeEvent(event)
            return
        if not self.shutdown_identity_import():
            event.ignore()
            return
        self._close_in_progress = True
        super(SavedServicesDialog, self).closeEvent(event)

    def reload(self):
        """Replace the table with the current archive. Errors use a fixed string."""
        self.table.setRowCount(0)
        self._records = {}
        try:
            records = SavedServices(self.common, self.common.settings).list()
        except SavedServicesError:
            Alert(self.common, strings._("gui_saved_services_list_error"))
            self.empty_label.show()
            self._update_buttons()
            return

        self.empty_label.setVisible(len(records) == 0)
        self.table.setRowCount(len(records))
        for row, record in enumerate(records):
            service_id = record["service_id"]
            self._records[service_id] = record
            if record["public"] is True:
                visibility = strings._("gui_saved_services_public")
            else:
                visibility = strings._("gui_saved_services_private")
            mode_key = _MODE_STRINGS.get(record["mode"])
            mode_text = strings._(mode_key) if mode_key else ""
            values = [
                record["label"],
                mode_text,
                service_id,
                record["saved_at"],
                visibility,
            ]
            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setFlags(
                    item.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable
                )
                if column == 0:
                    item.setData(QtCore.Qt.ItemDataRole.UserRole, service_id)
                self.table.setItem(row, column, item)
        self._update_buttons()

    def open_selected(self):
        """Open the selected identity stopped. A duplicate warns and opens nothing."""
        self.common.log("SavedServicesDialog", "open_selected")
        record = self._selected_record()
        if record is None:
            return
        identity = {key: record[key] for key in _IDENTITY_KEYS}
        self.tab_widget.open_saved_service(identity, label=record["label"])

    def rename_selected(self):
        """Update the selected record's label. The identity and saved_at stay."""
        self.common.log("SavedServicesDialog", "rename_selected")
        record = self._selected_record()
        if record is None:
            return
        label, accepted = QtWidgets.QInputDialog.getText(
            self,
            strings._("gui_saved_services_rename_title"),
            strings._("gui_saved_services_rename_prompt"),
            QtWidgets.QLineEdit.EchoMode.Normal,
            record["label"],
        )
        if not accepted:
            return
        service_id = record["service_id"]
        try:
            SavedServices(self.common, self.common.settings).rename(service_id, label)
        except SavedServicesError as error:
            Alert(
                self.common,
                _fixed_error(
                    error,
                    strings._("gui_saved_services_invalid_label"),
                    strings._("gui_saved_services_rename_error"),
                ),
            )
            return
        self.reload()
        self._select_service_id(service_id)

    def delete_selected(self):
        """
        Delete the selected archive record after confirmation.

        SavedServices.delete removes that record and its id only. The open
        tab, if any, is not started or stopped, and persistent tabs are not
        changed.
        """
        self.common.log("SavedServicesDialog", "delete_selected")
        record = self._selected_record()
        if record is None:
            return
        confirmed = _confirm(
            self.common,
            strings._("gui_saved_services_delete_confirm"),
            QtWidgets.QMessageBox.Icon.Warning,
            QtWidgets.QMessageBox.StandardButton.Yes
            | QtWidgets.QMessageBox.StandardButton.No,
            QtWidgets.QMessageBox.StandardButton.Yes,
        )
        if not confirmed:
            return
        service_id = record["service_id"]
        try:
            SavedServices(self.common, self.common.settings).delete(service_id)
        except SavedServicesError:
            Alert(self.common, strings._("gui_saved_services_delete_error"))
            return
        self.reload()

    def _selected_service_id(self):
        row = self.table.currentRow()
        if row < 0:
            return None
        item = self.table.item(row, 0)
        if item is None:
            return None
        service_id = item.data(QtCore.Qt.ItemDataRole.UserRole)
        if type(service_id) is not str:
            return None
        return service_id

    def _selected_record(self):
        service_id = self._selected_service_id()
        if service_id is None:
            return None
        return self._records.get(service_id)

    def _select_service_id(self, service_id):
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item is None:
                continue
            if item.data(QtCore.Qt.ItemDataRole.UserRole) == service_id:
                self.table.selectRow(row)
                return

    def _update_buttons(self):
        enabled = self._selected_service_id() is not None
        self.open_button.setEnabled(enabled)
        self.rename_button.setEnabled(enabled)
        self.delete_button.setEnabled(enabled)
