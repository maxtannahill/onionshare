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

import re

from PySide6 import QtCore, QtGui, QtWidgets

from onionshare_cli.identity_backup import generate_passphrase
from onionshare_cli.saved_services import SavedServices, SavedServicesError

from . import strings
from .identity_backup_dialog import ExportIdentityBackupDialog
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

# Same service-id rule the archive uses before it builds a record path.
_SERVICE_ID_RE = re.compile(r"^[a-z2-7]{56}$")


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


def _short_service_id(service_id):
    """Short form for a list row. The full id stays in the details pane."""
    if type(service_id) is not str or len(service_id) <= 16:
        return "" if service_id is None else str(service_id)
    return service_id[:8] + "\u2026" + service_id[-6:]


class _TreeCell(object):
    """One column of a tree row, with the text/data calls the tests use."""

    def __init__(self, item, column):
        self._item = item
        self._column = column

    def text(self):
        return self._item.text(self._column)

    def data(self, role):
        return self._item.data(self._column, role)


class _ServiceTree(QtWidgets.QTreeWidget):
    """
    Standard tree used as the saved-service list.

    ``rowCount``, ``item``, and ``selectRow`` match the manager tests.
    """

    def rowCount(self):
        return self.topLevelItemCount()

    def item(self, row, column):
        entry = self.topLevelItem(row)
        if entry is None:
            return None
        return _TreeCell(entry, column)

    def selectRow(self, row):
        entry = self.topLevelItem(row)
        if entry is None:
            return
        self.setCurrentItem(entry)
        entry.setSelected(True)


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
        self._damaged_ids = set()
        self.import_dialog = None
        self.export_dialog = None
        self._close_in_progress = False

        self.setWindowTitle(strings._("gui_saved_services_dialog_title"))
        self.setModal(True)
        self.setSizeGripEnabled(True)
        self.resize(840, 480)
        self.setMinimumSize(640, 360)

        self.import_button = QtWidgets.QPushButton(
            strings._("gui_saved_services_import_button")
        )
        self.import_button.setObjectName("saved_services_import_button")
        self.import_button.setDefault(True)
        self.import_button.setAutoDefault(True)
        self.import_button.clicked.connect(self.import_clicked)
        self.close_button = QtWidgets.QPushButton(
            strings._("gui_saved_services_close_button")
        )
        self.close_button.setAutoDefault(False)
        self.close_button.clicked.connect(self.reject)
        header = QtWidgets.QHBoxLayout()
        header.setSpacing(12)
        header.addWidget(self.import_button)
        header.addStretch()
        header.addWidget(self.close_button)

        self.disclosure_label = QtWidgets.QLabel(
            strings._("gui_saved_services_disclosure")
        )
        self.disclosure_label.setObjectName("saved_services_disclosure")
        self.disclosure_label.setWordWrap(True)

        self.empty_label = QtWidgets.QLabel(strings._("gui_saved_services_empty"))
        self.empty_label.setWordWrap(True)

        self.table = _ServiceTree()
        self.table.setObjectName("saved_services_table")
        self.table.setColumnCount(5)
        self.table.setHeaderLabels(
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
        self.table.setRootIsDecorated(False)
        self.table.setTextElideMode(QtCore.Qt.TextElideMode.ElideMiddle)
        self.table.setUniformRowHeights(True)
        self.table.setAllColumnsShowFocus(True)
        self.table.itemSelectionChanged.connect(self._update_buttons)
        self.table.itemDoubleClicked.connect(lambda _item, _column: self.open_selected())

        fixed = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont)
        self.details_heading = QtWidgets.QLabel(
            strings._("gui_saved_services_details_heading")
        )
        self.detail_label = QtWidgets.QLabel("")
        self.detail_label.setWordWrap(True)
        self.detail_label.setTextInteractionFlags(
            QtCore.Qt.TextInteractionFlag.TextSelectableByMouse
            | QtCore.Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        self.detail_mode = QtWidgets.QLabel("")
        self.detail_access = QtWidgets.QLabel("")
        self.detail_onion = QtWidgets.QLabel("")
        self.detail_onion.setFont(fixed)
        self.detail_onion.setWordWrap(True)
        self.detail_onion.setTextInteractionFlags(
            QtCore.Qt.TextInteractionFlag.TextSelectableByMouse
            | QtCore.Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        self.detail_saved = QtWidgets.QLabel("")
        self.detail_saved.setFont(fixed)
        self.detail_saved.setTextInteractionFlags(
            QtCore.Qt.TextInteractionFlag.TextSelectableByMouse
            | QtCore.Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        form = QtWidgets.QFormLayout()
        form.setSpacing(8)
        form.setContentsMargins(0, 0, 0, 0)
        form.addRow(strings._("gui_saved_services_column_label"), self.detail_label)
        form.addRow(strings._("gui_saved_services_column_mode"), self.detail_mode)
        form.addRow(strings._("gui_saved_services_column_visibility"), self.detail_access)
        form.addRow(strings._("gui_saved_services_details_onion"), self.detail_onion)
        form.addRow(strings._("gui_saved_services_column_saved_at"), self.detail_saved)

        self.open_button = QtWidgets.QPushButton(
            strings._("gui_saved_services_open_button")
        )
        self.open_button.setObjectName("saved_services_open_button")
        self.open_button.setAutoDefault(False)
        self.open_button.clicked.connect(self.open_selected)
        self.export_button = QtWidgets.QPushButton(
            strings._("gui_saved_services_export_button")
        )
        self.export_button.setObjectName("saved_services_export_button")
        self.export_button.setAutoDefault(False)
        self.export_button.clicked.connect(self.export_selected)
        self.rename_button = QtWidgets.QPushButton(
            strings._("gui_saved_services_rename_button")
        )
        self.rename_button.setObjectName("saved_services_rename_button")
        self.rename_button.setAutoDefault(False)
        self.rename_button.clicked.connect(self.rename_selected)
        self.delete_button = QtWidgets.QPushButton(
            strings._("gui_saved_services_delete_button")
        )
        self.delete_button.setObjectName("saved_services_delete_button")
        self.delete_button.setAutoDefault(False)
        self.delete_button.clicked.connect(self.delete_selected)
        actions = QtWidgets.QHBoxLayout()
        actions.setSpacing(8)
        actions.addWidget(self.open_button)
        actions.addWidget(self.export_button)
        actions.addWidget(self.rename_button)
        actions.addWidget(self.delete_button)
        actions.addStretch()

        details_layout = QtWidgets.QVBoxLayout()
        details_layout.setContentsMargins(0, 0, 0, 0)
        details_layout.setSpacing(12)
        details_layout.addWidget(self.details_heading)
        details_layout.addLayout(form)
        details_layout.addLayout(actions)
        details_layout.addStretch()
        self.details_widget = QtWidgets.QWidget()
        self.details_widget.setLayout(details_layout)

        body = QtWidgets.QHBoxLayout()
        body.setSpacing(16)
        body.addWidget(self.table, 3)
        body.addWidget(self.details_widget, 2)

        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)
        layout.addLayout(header)
        layout.addWidget(self.disclosure_label)
        layout.addWidget(self.empty_label)
        layout.addLayout(body)
        self.setLayout(layout)

        self.reload()

    def showEvent(self, event):
        super(SavedServicesDialog, self).showEvent(event)
        self.import_button.setDefault(True)

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

    def shutdown_identity_import(self, abandon=False):
        """
        Wait out an in-progress import or export before this dialog is destroyed.

        Returns False when a worker is still running after the timed wait.
        A user close leaves ``abandon`` false. Quit passes true and does not
        block on the worker.
        """
        import_ok = True
        dialog = self.import_dialog
        if dialog is not None:
            try:
                import_ok = dialog.shutdown_decrypt_thread(abandon=abandon)
            except RuntimeError:
                import_ok = True
        export_ok = True
        export_dialog = getattr(self, "export_dialog", None)
        if export_dialog is not None:
            try:
                export_ok = export_dialog.shutdown_encrypt_thread(abandon=abandon)
            except RuntimeError:
                export_ok = True
        return bool(import_ok) and bool(export_ok)

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

    def _restore_headers(self):
        self.table.setColumnCount(5)
        self.table.setHeaderLabels(
            [
                strings._("gui_saved_services_column_label"),
                strings._("gui_saved_services_column_mode"),
                strings._("gui_saved_services_column_service_id"),
                strings._("gui_saved_services_column_saved_at"),
                strings._("gui_saved_services_column_visibility"),
            ]
        )
        tree_header = self.table.header()
        tree_header.setStretchLastSection(False)
        tree_header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeMode.Stretch)
        tree_header.setSectionResizeMode(
            1, QtWidgets.QHeaderView.ResizeMode.ResizeToContents
        )
        tree_header.setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeMode.Stretch)
        tree_header.setSectionResizeMode(
            3, QtWidgets.QHeaderView.ResizeMode.ResizeToContents
        )
        tree_header.setSectionResizeMode(
            4, QtWidgets.QHeaderView.ResizeMode.ResizeToContents
        )

    def _listed_ids(self):
        try:
            current = self.common.settings.get("saved_services")
        except Exception:
            return []
        if type(current) is not list:
            return []
        return [item for item in current if type(item) is str]

    def _display_rows(self, records):
        """
        Valid records from ``list()``, plus a damaged id for each listed id
        ``list()`` omitted.

        ``list()`` itself is not changed. A damaged id is the service id
        only. The record body is not returned. Ids that fail the archive's
        service-id check are left out, because delete validates that shape
        before it unlinks.
        """
        pending = [record for record in records if type(record) is dict]
        rows = []
        damaged_ids = []
        seen_damaged = set()
        archive = None
        for service_id in self._listed_ids():
            if pending and pending[0].get("service_id") == service_id:
                rows.append(pending.pop(0))
                continue
            if service_id in seen_damaged:
                continue
            if _SERVICE_ID_RE.fullmatch(service_id) is None:
                continue
            if any(item.get("service_id") == service_id for item in pending):
                continue
            if archive is None:
                archive = SavedServices(self.common, self.common.settings)
            try:
                loaded = archive.get(service_id)
            except SavedServicesError:
                rows.append(service_id)
                damaged_ids.append(service_id)
                seen_damaged.add(service_id)
                continue
            if type(loaded) is dict and loaded.get("service_id") == service_id:
                rows.append(loaded)
        rows.extend(pending)
        return rows, damaged_ids

    def reload(self):
        """Replace the table with the current archive. Errors use a fixed string."""
        self._records = {}
        self._damaged_ids = set()
        try:
            records = SavedServices(self.common, self.common.settings).list()
        except SavedServicesError:
            Alert(self.common, strings._("gui_saved_services_list_error"))
            self.table.clear()
            self._restore_headers()
            self.empty_label.show()
            self.table.hide()
            self.details_widget.hide()
            self._update_buttons()
            return

        rows, damaged_ids = self._display_rows(records)
        self._damaged_ids = set(damaged_ids)
        self.table.clear()
        self._restore_headers()
        empty = len(rows) == 0
        self.empty_label.setVisible(empty)
        self.table.setVisible(not empty)
        self.details_widget.setVisible(not empty)
        fixed = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont)
        damaged_label = strings._("gui_saved_services_damaged_record")
        damaged_details = strings._("gui_saved_services_damaged_details")
        for entry in rows:
            if type(entry) is str:
                service_id = entry
                values = [
                    damaged_label,
                    "",
                    _short_service_id(service_id),
                    "",
                    "",
                ]
                item = QtWidgets.QTreeWidgetItem(values)
                item.setFlags(item.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)
                item.setData(0, QtCore.Qt.ItemDataRole.UserRole, service_id)
                item.setFont(2, fixed)
                item.setToolTip(0, damaged_details)
                item.setToolTip(2, service_id)
                self.table.addTopLevelItem(item)
                continue
            record = entry
            service_id = record["service_id"]
            self._records[service_id] = record
            if record["public"] is True:
                visibility = strings._("gui_saved_services_public")
            else:
                visibility = strings._("gui_saved_services_private")
            mode_key = _MODE_STRINGS.get(record["mode"])
            mode_text = strings._(mode_key) if mode_key else ""
            short_id = _short_service_id(service_id)
            values = [
                record["label"],
                mode_text,
                short_id,
                record["saved_at"],
                visibility,
            ]
            item = QtWidgets.QTreeWidgetItem(values)
            item.setFlags(item.flags() & ~QtCore.Qt.ItemFlag.ItemIsEditable)
            item.setData(0, QtCore.Qt.ItemDataRole.UserRole, service_id)
            item.setFont(2, fixed)
            item.setToolTip(2, service_id)
            item.setToolTip(0, record["label"])
            self.table.addTopLevelItem(item)
        self._update_buttons()

    def open_selected(self):
        """Open the selected identity stopped. A duplicate warns and opens nothing."""
        self.common.log("SavedServicesDialog", "open_selected")
        if self._selected_is_damaged():
            return
        record = self._selected_record()
        if record is None:
            return
        identity = {key: record[key] for key in _IDENTITY_KEYS}
        self.tab_widget.open_saved_service(identity, label=record["label"])

    def export_selected(self):
        """Open the backup dialog for the selected identity. The service stays stopped."""
        self.common.log("SavedServicesDialog", "export_selected")
        if self._selected_is_damaged():
            return
        record = self._selected_record()
        if record is None:
            return
        previous = self.export_dialog
        if previous is not None:
            try:
                if not previous.shutdown_encrypt_thread():
                    return
            except RuntimeError:
                pass
        identity = {key: record[key] for key in _IDENTITY_KEYS}
        self.export_dialog = ExportIdentityBackupDialog(
            self.common,
            identity,
            generate_passphrase(),
            parent=self,
        )
        self.export_dialog.exec()

    def rename_selected(self):
        """Update the selected record's label. The identity and saved_at stay."""
        self.common.log("SavedServicesDialog", "rename_selected")
        if self._selected_is_damaged():
            return
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
        except Exception:
            Alert(self.common, strings._("gui_saved_services_rename_error"))
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
        service_id = self._selected_service_id()
        damaged = self._selected_is_damaged()
        record = None if damaged else self._selected_record()
        if record is None and not damaged:
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
        if record is not None:
            service_id = record["service_id"]
        try:
            SavedServices(self.common, self.common.settings).delete(service_id)
        except SavedServicesError:
            Alert(self.common, strings._("gui_saved_services_delete_error"))
        except Exception:
            Alert(self.common, strings._("gui_saved_services_delete_error"))
        self.reload()

    def _selected_service_id(self):
        entry = self.table.currentItem()
        if entry is None:
            return None
        service_id = entry.data(0, QtCore.Qt.ItemDataRole.UserRole)
        if type(service_id) is not str:
            return None
        return service_id

    def _selected_is_damaged(self):
        service_id = self._selected_service_id()
        return service_id is not None and service_id in self._damaged_ids

    def _selected_record(self):
        service_id = self._selected_service_id()
        if service_id is None or service_id in self._damaged_ids:
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

    def _show_details(self, record):
        if record is None:
            self.detail_label.setText("")
            self.detail_mode.setText("")
            self.detail_access.setText("")
            self.detail_onion.setText("")
            self.detail_saved.setText("")
            return
        if record["public"] is True:
            visibility = strings._("gui_saved_services_public")
        else:
            visibility = strings._("gui_saved_services_private")
        mode_key = _MODE_STRINGS.get(record["mode"])
        mode_text = strings._(mode_key) if mode_key else ""
        self.detail_label.setText(record["label"])
        self.detail_mode.setText(mode_text)
        self.detail_access.setText(visibility)
        self.detail_onion.setText(record["service_id"])
        self.detail_saved.setText(record["saved_at"])

    def _show_damaged_details(self, service_id):
        """Text label for an unreadable record. The record body is not shown."""
        self.detail_label.setText(
            strings._("gui_saved_services_damaged_record")
            + "\n"
            + strings._("gui_saved_services_damaged_details")
        )
        self.detail_mode.setText("")
        self.detail_access.setText("")
        self.detail_onion.setText(service_id)
        self.detail_saved.setText("")

    def _update_buttons(self):
        damaged = self._selected_is_damaged()
        record = None if damaged else self._selected_record()
        self.open_button.setEnabled(record is not None)
        self.export_button.setEnabled(record is not None)
        self.rename_button.setEnabled(record is not None)
        self.delete_button.setEnabled(damaged or record is not None)
        if damaged:
            self._show_damaged_details(self._selected_service_id())
        else:
            self._show_details(record)
