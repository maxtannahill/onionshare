# -*- coding: utf-8 -*-
"""
GUI tests for the Saved Services manager.

Opening an archived identity must not start the server, must not create a
persistent tab file, and must not append to persistent_tabs. Assertions that
compare secrets use assertTrue/assertFalse so a failure does not print
private keys or client-auth keys.
"""

import base64
import errno
import hashlib
import inspect
import json
import logging
import os
import tempfile
from unittest import mock

import pytest
from PySide6 import QtCore, QtWidgets

from onionshare_cli.mode_settings import ModeSettings
from onionshare_cli.saved_services import SavedServices, SavedServicesError

from onionshare import strings
from onionshare.saved_services_dialog import SavedServicesDialog
from onionshare.settings_parent_tab import SettingsParentTab
from onionshare.tab.mode import Mode
from onionshare.tab.server_status import ServerStatus
from onionshare.tab.tab import Tab
from onionshare.tab_widget import TabWidget
from onionshare.widgets import Alert

from .gui_base_test import GuiBaseTest


_MODE_CLASS = {
    "share": "ShareMode",
    "receive": "ReceiveMode",
    "website": "WebsiteMode",
    "chat": "ChatMode",
}


def _onion_address(public_key):
    checksum = hashlib.sha3_256(
        b".onion checksum" + public_key + b"\x03"
    ).digest()[:2]
    encoded = base64.b32encode(public_key + checksum + b"\x03").decode("ascii")
    return encoded.lower()


def _sibling_identity():
    """A second disposable identity so delete can be shown to remove only one."""
    import nacl.signing

    seed = os.urandom(32)
    expanded = bytearray(hashlib.sha512(seed).digest())
    expanded[0] &= 248
    expanded[31] &= 127
    expanded[31] |= 64
    public_key = bytes(nacl.signing.SigningKey(seed).verify_key)
    return {
        "mode": "share",
        "service_id": _onion_address(public_key),
        "private_key": base64.b64encode(bytes(expanded)).decode("ascii"),
        "client_auth_priv_key": None,
        "client_auth_pub_key": None,
        "public": True,
    }


def _fixture_identity(mode):
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "cli",
        "tests",
        "persistent.json",
    )
    with open(path, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    return {
        "mode": mode,
        "service_id": document["general"]["service_id"],
        "private_key": document["onion"]["private_key"],
        "client_auth_priv_key": document["onion"]["client_auth_priv_key"],
        "client_auth_pub_key": document["onion"]["client_auth_pub_key"],
        "public": document["general"]["public"],
    }


def _secrets_of(*identities):
    values = []
    for identity in identities:
        for key in ("private_key", "client_auth_priv_key", "client_auth_pub_key"):
            value = identity.get(key)
            if value:
                values.append(value)
    return values


class SavedServicesCase(GuiBaseTest):
    """
    Window lifecycle is GuiBaseTest's. The parametrized test below owns the
    cases; this class has no test methods, because pytest's unittest
    collector does not expand pytest.mark.parametrize.
    """

    def setUp(self):
        self.gui.common.gui.onion.connected_to_tor = False
        self._quiesce_tabs()
        self.gui.tabs.close_settings_tab()
        self._close_feature_tabs()
        self._leave_one_chooser()
        self._clear_archive()
        self.gui.qtapp.processEvents()

    def tearDown(self):
        self.gui.common.gui.onion.connected_to_tor = False
        dialog = getattr(self, "_dialog", None)
        self._dialog = None
        if dialog is not None:
            try:
                dialog.close()
            except RuntimeError:
                pass
        self._quiesce_tabs()
        self.gui.tabs.close_settings_tab()
        self._close_feature_tabs()
        self._leave_one_chooser()
        self._clear_archive()

    def _quiesce_tabs(self):
        for tab in list(self.gui.tabs.tabs.values()):
            get_mode = getattr(tab, "get_mode", None)
            if get_mode is None:
                continue
            try:
                mode = get_mode()
            except Exception:
                continue
            if mode is None:
                continue
            mode.server_status.status = ServerStatus.STATUS_STOPPED
            settings = getattr(tab, "settings", None)
            if settings is not None and hasattr(settings, "_settings"):
                settings._settings["persistent"]["enabled"] = False
                settings._settings["persistent"]["autostart_on_launch"] = False

    def _close_feature_tabs(self):
        for _ in range(12):
            closed = False
            for index in range(self.gui.tabs.count()):
                tab = self.gui.tabs.widget(index)
                if type(tab) is SettingsParentTab:
                    continue
                if not isinstance(tab, Tab) or tab.mode is None:
                    continue
                self.gui.tabs.close_tab(index)
                closed = True
                break
            if not closed:
                break

    def _leave_one_chooser(self):
        chooser_indexes = []
        for index in range(self.gui.tabs.count()):
            tab = self.gui.tabs.widget(index)
            if isinstance(tab, Tab) and tab.mode is None:
                chooser_indexes.append(index)
        for index in reversed(chooser_indexes[1:]):
            self.gui.tabs.close_tab(index)

    def _clear_archive(self):
        common = self.gui.common
        try:
            ids = list(common.settings.get("saved_services"))
        except Exception:
            ids = []
        archive = SavedServices(common, common.settings)
        for service_id in ids:
            try:
                archive.delete(service_id)
            except SavedServicesError:
                pass
        directory = os.path.join(common.build_data_dir(), "saved_services")
        if os.path.isdir(directory) and not os.path.islink(directory):
            for name in os.listdir(directory):
                path = os.path.join(directory, name)
                if os.path.isfile(path) and not os.path.islink(path):
                    os.remove(path)
        if common.settings.get("saved_services") != []:
            common.settings.set("saved_services", [])
            common.settings.save()

    def _persistent_tabs(self):
        self.gui.common.settings.load()
        return list(self.gui.common.settings.get("persistent_tabs"))

    def _persistent_names(self):
        directory = self.gui.common.build_persistent_dir()
        return sorted(os.listdir(directory))

    def _tabs_for_service(self, service_id):
        found = []
        for tab in self.gui.tabs.tabs.values():
            if not isinstance(tab, Tab):
                continue
            settings = getattr(tab, "settings", None)
            if settings is None:
                continue
            try:
                current = settings.get("general", "service_id")
            except Exception:
                continue
            if current == service_id:
                found.append(tab)
        return found

    def _select(self, dialog, service_id):
        for row in range(dialog.table.rowCount()):
            item = dialog.table.item(row, 0)
            if item is None:
                continue
            if item.data(QtCore.Qt.ItemDataRole.UserRole) == service_id:
                dialog.table.selectRow(row)
                return row
        self.fail("saved service row was not listed")

    def _close_service_tab(self, tab):
        index = self.gui.tabs.indexOf(tab)
        button = self.gui.tabs.tabBar().tabButton(
            index, QtWidgets.QTabBar.ButtonPosition.RightSide
        )
        button.click()

    def _settings_tab(self):
        for tab in self.gui.tabs.tabs.values():
            if type(tab) is SettingsParentTab:
                return tab.widget(0)
        return None

    def _assert_secrets_absent(self, secrets, alerts):
        captured = self.capsys.readouterr()
        blobs = [self.caplog.text, captured.out, captured.err]
        blobs.extend(alerts)
        for module, func, msg in self._log_messages:
            blobs.append(module)
            blobs.append(func)
            if msg is not None:
                blobs.append(msg)
        for blob in blobs:
            if blob is None:
                continue
            text = blob if isinstance(blob, str) else str(blob)
            for secret in secrets:
                self.assertFalse(secret in text)

    def run_open_saved_service(self, mode):
        """
        Save an injected identity and open it from the manager.

        Persistence and autostart are already false when the mode is
        constructed. The tab stays stopped when Tor is already connected.
        A duplicate open starts neither service. Closing the tab leaves the
        archive record, and delete removes only that record.
        """
        self.caplog.set_level(logging.DEBUG)
        signature = inspect.signature(TabWidget.open_saved_service)
        self.assertEqual(list(signature.parameters), ["self", "identity", "label"])
        self.assertTrue(signature.parameters["label"].default is None)

        self.assertEqual(self.gui.tabs.count(), 1)
        self.assertTrue(self.gui.tabs.widget(0).mode is None)
        persistent_tabs = self._persistent_tabs()
        persistent_names = self._persistent_names()
        self.assertEqual(persistent_tabs, [])
        self.assertEqual(persistent_names, [])

        identity = _fixture_identity(mode)
        sibling = _sibling_identity()
        label = "w4-" + mode
        secrets = _secrets_of(identity, sibling)
        archive = SavedServices(self.gui.common, self.gui.common.settings)
        archive.add(sibling, "w4-sibling")
        stored = archive.add(identity, label)
        saved_at = stored["saved_at"]
        self.assertEqual(self._persistent_tabs(), persistent_tabs)
        self.assertEqual(self._persistent_names(), persistent_names)

        data_dir = self.gui.common.build_data_dir()
        archive_path = os.path.join(
            data_dir, "saved_services", identity["service_id"] + ".json"
        )
        sibling_path = os.path.join(
            data_dir, "saved_services", sibling["service_id"] + ".json"
        )
        self.assertTrue(os.path.isfile(archive_path))
        self.assertTrue(os.path.isfile(sibling_path))
        self.assertFalse(
            os.path.exists(
                os.path.join(data_dir, "persistent", identity["service_id"] + ".json")
            )
        )
        with open(sibling_path, "rb") as handle:
            sibling_bytes = handle.read()
        with open(archive_path, "r", encoding="utf-8") as handle:
            on_disk = json.load(handle)
        self.assertEqual(on_disk["label"], label)
        self.assertEqual(on_disk["mode"], mode)
        self.assertEqual(on_disk["saved_at"], saved_at)
        self.assertTrue("filenames" not in on_disk)
        self.assertTrue("data_dir" not in on_disk)
        self.assertTrue("persistent" not in on_disk)
        self.assertTrue("autostart_on_launch" not in on_disk)
        self.assertTrue(on_disk["private_key"] == identity["private_key"])

        self._log_messages = []
        original_log = self.gui.common.log

        def wrapped_log(module, func, msg=None):
            self._log_messages.append((module, func, msg))
            return original_log(module, func, msg)

        construction = []
        start_calls = []
        save_calls = []
        alerts = []
        dialogs = []

        real_init = Mode.__init__

        def wrapped_init(self, tab):
            construction.append(
                {
                    "enabled_false": tab.settings.get("persistent", "enabled") is False,
                    "autostart_false": tab.settings.get(
                        "persistent", "autostart_on_launch"
                    )
                    is False,
                    "timer_false": tab.settings.get("general", "autostart_timer")
                    is False,
                    "mode": tab.settings.get("persistent", "mode"),
                    "cls": type(self).__name__,
                }
            )
            return real_init(self, tab)

        def status_start(self, *args, **kwargs):
            start_calls.append("status")

        def mode_start(self, *args, **kwargs):
            start_calls.append("mode")

        def settings_save(self, *args, **kwargs):
            save_calls.append(self.id)

        real_alert_init = Alert.__init__

        def alert_init(box, common, message, *args, **kwargs):
            alerts.append(message)
            return real_alert_init(box, common, message, *args, **kwargs)

        def exec_answer(box, *args, **kwargs):
            yes = QtWidgets.QMessageBox.StandardButton.Yes
            if box.standardButtons() & yes:
                return yes
            return QtWidgets.QMessageBox.StandardButton.Ok

        def dialog_exec(dialog):
            dialog.show()
            dialogs.append(dialog)
            return QtWidgets.QDialog.DialogCode.Rejected

        self.gui.common.log = wrapped_log
        self.gui.common.gui.onion.connected_to_tor = True
        try:
            with mock.patch.object(ModeSettings, "save", settings_save), mock.patch.object(
                Mode, "__init__", wrapped_init
            ), mock.patch.object(
                ServerStatus, "start_server", status_start
            ), mock.patch.object(
                Mode, "start_server", mode_start
            ), mock.patch.object(
                Alert, "__init__", alert_init
            ), mock.patch.object(
                QtWidgets.QMessageBox, "exec", exec_answer
            ), mock.patch.object(
                SavedServicesDialog, "exec", dialog_exec
            ):
                self.gui.settings_button.click()
                self.gui.qtapp.processEvents()
                settings_tab = self._settings_tab()
                self.assertIsNotNone(settings_tab)
                self.assertTrue(settings_tab.saved_services_button.isVisible())
                self.assertFalse(settings_tab.saved_services_button.isHidden())
                self.assertEqual(
                    settings_tab.saved_services_button.text(),
                    strings._("gui_settings_saved_services_button"),
                )

                settings_tab.saved_services_button.click()
                self.gui.qtapp.processEvents()
                dialog = dialogs[-1]
                self._dialog = dialog
                self.assertFalse(dialog.disclosure_label.isHidden())
                self.assertTrue(dialog.disclosure_label.isVisible())
                disclosure = dialog.disclosure_label.text()
                self.assertTrue("unencrypted" in disclosure)
                self.assertTrue("this computer" in disclosure)
                self.assertEqual(dialog.table.rowCount(), 2)
                self.assertFalse(dialog.open_button.isEnabled())
                self.assertFalse(dialog.export_button.isEnabled())
                self.assertTrue(dialog.import_button.isEnabled())

                row = self._select(dialog, identity["service_id"])
                self.assertTrue(dialog.open_button.isEnabled())
                self.assertTrue(dialog.export_button.isEnabled())
                self.assertEqual(dialog.table.item(row, 0).text(), label)
                self.assertEqual(
                    dialog.table.item(row, 1).text(),
                    strings._("gui_tab_name_" + mode),
                )
                shown_id = dialog.table.item(row, 2).text()
                self.assertFalse(shown_id == identity["service_id"])
                self.assertTrue(shown_id.startswith(identity["service_id"][:8]))
                self.assertTrue(dialog.detail_onion.text() == identity["service_id"])
                self.assertEqual(dialog.table.item(row, 3).text(), saved_at)
                self.assertEqual(
                    dialog.table.item(row, 4).text(),
                    strings._("gui_saved_services_private"),
                )
                for column in range(dialog.table.columnCount()):
                    cell = dialog.table.item(row, column).text()
                    for secret in secrets:
                        self.assertFalse(secret in cell)

                count_before_open = self.gui.tabs.count()
                dialog.open_button.click()
                self.gui.qtapp.processEvents()

                self.assertEqual(len(construction), 1)
                opened_flags = construction[0]
                self.assertTrue(opened_flags["enabled_false"])
                self.assertTrue(opened_flags["autostart_false"])
                self.assertTrue(opened_flags["timer_false"])
                self.assertEqual(opened_flags["mode"], mode)
                self.assertEqual(opened_flags["cls"], _MODE_CLASS[mode])
                self.assertEqual(self.gui.tabs.count(), count_before_open + 1)
                opened_tabs = self._tabs_for_service(identity["service_id"])
                self.assertEqual(len(opened_tabs), 1)
                tab = opened_tabs[0]
                mode_obj = tab.get_mode()
                self.assertEqual(tab.mode, mode)
                self.assertEqual(mode_obj.get_type(), mode)
                self.assertTrue(tab.settings.get("persistent", "enabled") is False)
                self.assertTrue(
                    tab.settings.get("persistent", "autostart_on_launch") is False
                )
                self.assertTrue(tab.settings.get("general", "autostart_timer") is False)
                self.assertTrue(tab.settings.get("general", "public") is False)
                self.assertTrue(tab.settings.get("general", "title") is None)
                self.assertTrue(
                    tab.settings.get("onion", "private_key") == identity["private_key"]
                )
                self.assertTrue(
                    tab.settings.get("onion", "client_auth_priv_key")
                    == identity["client_auth_priv_key"]
                )
                self.assertTrue(
                    tab.settings.get("onion", "client_auth_pub_key")
                    == identity["client_auth_pub_key"]
                )
                widget = mode_obj.mode_settings_widget
                self.assertFalse(widget.persistent_checkbox.isChecked())
                self.assertFalse(
                    widget.persistent_autostart_on_launch_checkbox.isChecked()
                )
                self.assertFalse(widget.autostart_timer_checkbox.isChecked())
                self.assertEqual(
                    mode_obj.server_status.status, ServerStatus.STATUS_STOPPED
                )
                self.assertEqual(start_calls, [])
                self.assertEqual(save_calls, [])
                self.assertFalse(os.path.exists(tab.settings.filename))
                self.assertTrue(tab.settings.id not in self._persistent_tabs())
                self.assertEqual(self._persistent_tabs(), persistent_tabs)
                self.assertEqual(self._persistent_names(), persistent_names)

                mode_obj.tor_connection_started()
                self.gui.tabs.tor_is_connected()
                self.gui.qtapp.processEvents()
                self.assertEqual(
                    mode_obj.server_status.status, ServerStatus.STATUS_STOPPED
                )
                self.assertEqual(start_calls, [])
                self.assertEqual(save_calls, [])
                self.assertEqual(self._persistent_tabs(), persistent_tabs)
                self.assertEqual(self._persistent_names(), persistent_names)

                real_save_tabs = self.gui.tabs.save_persistent_tabs
                self.gui.tabs.save_persistent_tabs = lambda: None
                try:
                    tab.settings._settings["persistent"]["enabled"] = True
                    tab.settings._settings["persistent"]["autostart_on_launch"] = True
                    mode_obj.server_status.status = ServerStatus.STATUS_STARTED
                    count_at_duplicate = self.gui.tabs.count()
                    self._select(dialog, identity["service_id"])
                    dialog.open_button.click()
                    self.gui.qtapp.processEvents()
                    self.assertEqual(self.gui.tabs.count(), count_at_duplicate)
                    self.assertEqual(
                        len(self._tabs_for_service(identity["service_id"])), 1
                    )
                    self.assertEqual(len(construction), 1)
                    self.assertEqual(
                        mode_obj.server_status.status, ServerStatus.STATUS_STARTED
                    )
                    self.assertEqual(start_calls, [])
                    self.assertTrue(
                        strings._("gui_saved_services_duplicate") in alerts
                    )
                finally:
                    tab.settings._settings["persistent"]["enabled"] = False
                    tab.settings._settings["persistent"][
                        "autostart_on_launch"
                    ] = False
                    mode_obj.server_status.status = ServerStatus.STATUS_STOPPED
                    self.gui.tabs.save_persistent_tabs = real_save_tabs

                self.assertEqual(
                    mode_obj.server_status.status, ServerStatus.STATUS_STOPPED
                )
                self.assertTrue(tab.settings.get("persistent", "enabled") is False)
                self.assertTrue(
                    tab.settings.get("persistent", "autostart_on_launch") is False
                )
                self._close_service_tab(tab)
                self.gui.qtapp.processEvents()
                self.assertEqual(len(self._tabs_for_service(identity["service_id"])), 0)
                self.assertTrue(os.path.isfile(archive_path))
                reloaded = SavedServices(
                    self.gui.common, self.gui.common.settings
                ).get(identity["service_id"])
                self.assertEqual(reloaded["label"], label)
                self.assertEqual(reloaded["saved_at"], saved_at)
                self.assertTrue(reloaded["private_key"] == identity["private_key"])

                dialog.close()
                settings_tab.saved_services_button.click()
                self.gui.qtapp.processEvents()
                dialog = dialogs[-1]
                self._dialog = dialog
                self.assertTrue("unencrypted" in dialog.disclosure_label.text())
                self._select(dialog, identity["service_id"])
                dialog.open_button.click()
                self.gui.qtapp.processEvents()

                self.assertEqual(len(construction), 2)
                reopened_flags = construction[1]
                self.assertTrue(reopened_flags["enabled_false"])
                self.assertTrue(reopened_flags["autostart_false"])
                self.assertTrue(reopened_flags["timer_false"])
                self.assertEqual(reopened_flags["mode"], mode)
                self.assertEqual(reopened_flags["cls"], _MODE_CLASS[mode])
                reopened_tabs = self._tabs_for_service(identity["service_id"])
                self.assertEqual(len(reopened_tabs), 1)
                reopened = reopened_tabs[0]
                self.assertEqual(
                    reopened.get_mode().server_status.status,
                    ServerStatus.STATUS_STOPPED,
                )
                self.assertEqual(start_calls, [])
                self.assertEqual(save_calls, [])
                self.assertFalse(os.path.exists(reopened.settings.filename))
                self.assertEqual(self._persistent_tabs(), persistent_tabs)
                self.assertEqual(self._persistent_names(), persistent_names)

                renamed_label = "w4-renamed-" + mode
                with mock.patch.object(
                    QtWidgets.QInputDialog,
                    "getText",
                    return_value=(renamed_label, True),
                ):
                    self._select(dialog, identity["service_id"])
                    dialog.rename_button.click()
                self.gui.qtapp.processEvents()
                renamed = SavedServices(
                    self.gui.common, self.gui.common.settings
                ).get(identity["service_id"])
                self.assertEqual(renamed["label"], renamed_label)
                self.assertEqual(renamed["saved_at"], saved_at)
                self.assertEqual(renamed["mode"], mode)
                self.assertTrue(renamed["private_key"] == identity["private_key"])
                self.assertTrue(
                    renamed["client_auth_priv_key"] == identity["client_auth_priv_key"]
                )
                self.assertTrue(
                    renamed["client_auth_pub_key"] == identity["client_auth_pub_key"]
                )
                self.assertTrue(renamed["public"] is False)
                self.assertEqual(
                    reopened.get_mode().server_status.status,
                    ServerStatus.STATUS_STOPPED,
                )
                self.assertEqual(start_calls, [])
                with open(sibling_path, "rb") as handle:
                    self.assertTrue(handle.read() == sibling_bytes)

                self._select(dialog, identity["service_id"])
                dialog.delete_button.click()
                self.gui.qtapp.processEvents()
                self.assertFalse(os.path.exists(archive_path))
                self.assertTrue(os.path.isfile(sibling_path))
                with open(sibling_path, "rb") as handle:
                    self.assertTrue(handle.read() == sibling_bytes)
                saved_ids = list(self.gui.common.settings.get("saved_services"))
                self.assertTrue(identity["service_id"] not in saved_ids)
                self.assertTrue(sibling["service_id"] in saved_ids)
                self.assertTrue(
                    strings._("gui_saved_services_delete_confirm") in alerts
                )
                still_open = self._tabs_for_service(identity["service_id"])
                self.assertEqual(len(still_open), 1)
                self.assertEqual(
                    still_open[0].get_mode().server_status.status,
                    ServerStatus.STATUS_STOPPED,
                )
                self.assertEqual(start_calls, [])
                self.assertEqual(save_calls, [])
                self.assertEqual(self._persistent_tabs(), persistent_tabs)
                self.assertEqual(self._persistent_names(), persistent_names)
                self._assert_secrets_absent(secrets, alerts)
        finally:
            self.gui.common.log = original_log
            self.gui.common.gui.onion.connected_to_tor = False

    def run_symlinked_archive_list_error(self):
        identity = _sibling_identity()
        archive = SavedServices(self.gui.common, self.gui.common.settings)
        archive.add(identity, "w4-link")
        data_dir = self.gui.common.build_data_dir()
        directory = os.path.join(data_dir, "saved_services")
        record_name = identity["service_id"] + ".json"
        with open(os.path.join(directory, record_name), "rb") as handle:
            before = handle.read()
        holder = tempfile.TemporaryDirectory()
        target = os.path.join(holder.name, "archive-target")
        marker = os.path.join(target, "marker.txt")
        try:
            os.rename(directory, target)
            os.symlink(target, directory)
            with open(marker, "wb") as handle:
                handle.write(b"untouched")
            alerts = []
            real_exec = QtWidgets.QMessageBox.exec

            def record_exec(box, *args, **kwargs):
                alerts.append(box.text())
                return QtWidgets.QMessageBox.StandardButton.Ok

            with mock.patch.object(QtWidgets.QMessageBox, "exec", record_exec):
                dialog = SavedServicesDialog(self.gui.common, self.gui.tabs)
                self._dialog = dialog
            if strings._("gui_saved_services_list_error") not in alerts:
                raise AssertionError("manager did not show the list error")
            if dialog.table.rowCount() != 0:
                raise AssertionError("symlinked archive still filled the table")
            with open(os.path.join(target, record_name), "rb") as handle:
                if handle.read() != before:
                    raise AssertionError("symlink target record changed")
            with open(marker, "rb") as handle:
                if handle.read() != b"untouched":
                    raise AssertionError("symlink target marker changed")
        finally:
            if os.path.islink(directory):
                os.unlink(directory)
            holder.cleanup()

    def run_post_commit_oserror_reloads_table(self):
        first = _sibling_identity()
        second = _sibling_identity()
        archive = SavedServices(self.gui.common, self.gui.common.settings)
        archive.add(first, "w4-delete")
        archive.add(second, "w4-rename")
        alerts = []

        def record_exec(box, *args, **kwargs):
            alerts.append(box.text())
            yes = QtWidgets.QMessageBox.StandardButton.Yes
            if box.standardButtons() & yes:
                return yes
            return QtWidgets.QMessageBox.StandardButton.Ok

        def fail_fsync(_directory):
            raise OSError(errno.EIO, "w4-fsync-eio")

        with mock.patch.object(QtWidgets.QMessageBox, "exec", record_exec):
            dialog = SavedServicesDialog(self.gui.common, self.gui.tabs)
            self._dialog = dialog
            self._select(dialog, first["service_id"])
            from onionshare_cli import saved_services as saved_services_module

            with mock.patch.object(
                saved_services_module, "_fsync_directory", fail_fsync
            ):
                dialog.delete_selected()
            if strings._("gui_saved_services_delete_error") not in alerts:
                raise AssertionError("delete did not show the archive error")
            self._assert_table_matches_disk(dialog)

            alerts.clear()
            self._select(dialog, second["service_id"])
            with mock.patch.object(
                saved_services_module, "_fsync_directory", fail_fsync
            ), mock.patch.object(
                QtWidgets.QInputDialog,
                "getText",
                return_value=("w4-renamed", True),
            ):
                dialog.rename_selected()
            if strings._("gui_saved_services_rename_error") not in alerts:
                raise AssertionError("rename did not show the archive error")
            self._assert_table_matches_disk(dialog)
            renamed = False
            for row in range(dialog.table.rowCount()):
                item = dialog.table.item(row, 0)
                if item is not None and item.text() == "w4-renamed":
                    renamed = True
            if not renamed:
                raise AssertionError("reloaded table does not show the new label")
        captured = self.capsys.readouterr()
        blobs = self.caplog.text + captured.out + captured.err
        if "w4-fsync-eio" in blobs:
            raise AssertionError("fsync error text was logged")

    def run_damaged_record_can_be_deleted(self):
        """
        A truncated record and a symlink record are listed as damaged text
        rows. Only Delete is enabled. Delete unlinks the record id and does
        not follow a symlink.
        """
        good = _sibling_identity()
        damaged = _sibling_identity()
        linked = _sibling_identity()
        secrets = _secrets_of(good, damaged, linked)
        archive = SavedServices(self.gui.common, self.gui.common.settings)
        archive.add(good, "w6-good")
        archive.add(damaged, "w6-damaged")
        archive.add(linked, "w6-linked")
        data_dir = self.gui.common.build_data_dir()
        directory = os.path.join(data_dir, "saved_services")
        damaged_path = os.path.join(directory, damaged["service_id"] + ".json")
        link_path = os.path.join(directory, linked["service_id"] + ".json")
        good_path = os.path.join(directory, good["service_id"] + ".json")
        with open(damaged_path, "rb") as handle:
            raw = handle.read()
        key = damaged["private_key"].encode("ascii")
        marker = b'"private_key":"' + key + b'"'
        if marker not in raw:
            raise AssertionError("could not locate the key field to truncate")
        truncated = raw[: raw.find(marker) + len(marker)]
        with open(damaged_path, "wb") as handle:
            handle.write(truncated)
        with open(link_path, "rb") as handle:
            link_bytes = handle.read()
        holder = tempfile.TemporaryDirectory()
        outside = os.path.join(holder.name, "outside-target.json")
        try:
            with open(outside, "wb") as handle:
                handle.write(link_bytes)
            os.remove(link_path)
            os.symlink(outside, link_path)
            listed = [
                item["service_id"]
                for item in SavedServices(
                    self.gui.common, self.gui.common.settings
                ).list()
            ]
            if listed != [good["service_id"]]:
                raise AssertionError("list() changed which valid records it returns")

            answers = {"confirm": QtWidgets.QMessageBox.StandardButton.No}
            alerts = []

            def exec_answer(box, *args, **kwargs):
                alerts.append(box.text())
                yes = QtWidgets.QMessageBox.StandardButton.Yes
                if box.standardButtons() & yes:
                    return answers["confirm"]
                return QtWidgets.QMessageBox.StandardButton.Ok

            persistent_tabs = self._persistent_tabs()
            tabs_before = self.gui.tabs.count()
            with mock.patch.object(QtWidgets.QMessageBox, "exec", exec_answer):
                dialog = SavedServicesDialog(self.gui.common, self.gui.tabs)
                self._dialog = dialog
                if dialog.table.rowCount() != 3:
                    raise AssertionError(
                        "damaged records were omitted from the manager"
                    )
                if dialog.empty_label.isVisible():
                    raise AssertionError("damaged records showed the empty state")
                good_row = self._select(dialog, good["service_id"])
                if dialog.table.item(good_row, 0).text() != "w6-good":
                    raise AssertionError("valid row label changed")
                if not (
                    dialog.open_button.isEnabled()
                    and dialog.export_button.isEnabled()
                    and dialog.rename_button.isEnabled()
                    and dialog.delete_button.isEnabled()
                ):
                    raise AssertionError("valid row did not enable every action")

                damaged_row = self._select(dialog, damaged["service_id"])
                damaged_label = strings._("gui_saved_services_damaged_record")
                if dialog.table.item(damaged_row, 0).text() != damaged_label:
                    raise AssertionError("damaged row was not labeled in text")
                if damaged_label != "Damaged record":
                    raise AssertionError("damaged row label string changed")
                self._assert_no_secret_text(dialog, damaged_row, secrets)
                if not dialog.detail_label.text().startswith(damaged_label):
                    raise AssertionError("details did not name the damaged record")
                if (
                    strings._("gui_saved_services_damaged_details")
                    not in dialog.detail_label.text()
                ):
                    raise AssertionError("details did not explain the damaged record")
                if dialog.detail_onion.text() != damaged["service_id"]:
                    raise AssertionError("damaged details omitted the service id")
                for secret in secrets:
                    if secret and secret in dialog.detail_label.text():
                        raise AssertionError("damaged details included key material")
                    if secret and secret in dialog.detail_onion.text():
                        raise AssertionError("damaged details included key material")
                if dialog.open_button.isEnabled() or dialog.export_button.isEnabled():
                    raise AssertionError("damaged row enabled open or export")
                if dialog.rename_button.isEnabled() or not dialog.delete_button.isEnabled():
                    raise AssertionError("damaged row did not leave only delete enabled")
                dialog.open_selected()
                dialog.export_selected()
                dialog.rename_selected()
                self.gui.qtapp.processEvents()
                if self.gui.tabs.count() != tabs_before:
                    raise AssertionError("damaged open created a tab")
                if dialog.export_dialog is not None:
                    raise AssertionError("damaged export opened a backup dialog")
                with open(damaged_path, "rb") as handle:
                    if handle.read() != truncated:
                        raise AssertionError("disabled actions changed the damaged file")

                self._select(dialog, damaged["service_id"])
                dialog.delete_button.click()
                self.gui.qtapp.processEvents()
                if strings._("gui_saved_services_delete_confirm") not in alerts:
                    raise AssertionError("delete did not ask for confirmation")
                if not os.path.lexists(damaged_path):
                    raise AssertionError("cancelling delete removed the damaged file")

                answers["confirm"] = QtWidgets.QMessageBox.StandardButton.Yes
                self._select(dialog, damaged["service_id"])
                dialog.delete_button.click()
                self.gui.qtapp.processEvents()
                if os.path.lexists(damaged_path):
                    raise AssertionError("delete left the damaged file in place")
                self.gui.common.settings.load()
                saved_ids = list(self.gui.common.settings.get("saved_services"))
                if damaged["service_id"] in saved_ids:
                    raise AssertionError("delete left the damaged id in settings")
                if good["service_id"] not in saved_ids:
                    raise AssertionError("delete removed the valid saved service")
                if not os.path.islink(link_path):
                    raise AssertionError("delete followed or replaced the symlink")
                with open(outside, "rb") as handle:
                    if handle.read() != link_bytes:
                        raise AssertionError("symlink target changed")

                link_row = self._select(dialog, linked["service_id"])
                if dialog.table.item(link_row, 0).text() != damaged_label:
                    raise AssertionError("symlink record was not labeled as damaged")
                self._assert_no_secret_text(dialog, link_row, secrets)
                if dialog.open_button.isEnabled() or dialog.rename_button.isEnabled():
                    raise AssertionError("symlink row enabled open or rename")
                dialog.delete_button.click()
                self.gui.qtapp.processEvents()
                if os.path.lexists(link_path):
                    raise AssertionError("delete left the symlink record in place")
                if not os.path.isfile(outside):
                    raise AssertionError("delete removed the symlink target")
                with open(outside, "rb") as handle:
                    if handle.read() != link_bytes:
                        raise AssertionError("symlink target bytes changed")
                self.gui.common.settings.load()
                saved_ids = list(self.gui.common.settings.get("saved_services"))
                if linked["service_id"] in saved_ids:
                    raise AssertionError("delete left the symlink id in settings")
                if saved_ids != [good["service_id"]]:
                    raise AssertionError("settings ids were not left as the valid record")
                if not os.path.isfile(good_path):
                    raise AssertionError("delete removed the valid record file")
                reloaded = SavedServices(
                    self.gui.common, self.gui.common.settings
                ).get(good["service_id"])
                if reloaded["label"] != "w6-good":
                    raise AssertionError("valid record label changed")
                if reloaded["private_key"] != good["private_key"]:
                    raise AssertionError("valid record key changed")
                if self._persistent_tabs() != persistent_tabs:
                    raise AssertionError("delete changed persistent tabs")
                again = [
                    item["service_id"]
                    for item in SavedServices(
                        self.gui.common, self.gui.common.settings
                    ).list()
                ]
                if again != [good["service_id"]]:
                    raise AssertionError("list() no longer returns the valid record")
        finally:
            holder.cleanup()
            if os.path.islink(link_path):
                os.unlink(link_path)
            captured = self.capsys.readouterr()
            blob = self.caplog.text + captured.out + captured.err
            for secret in secrets:
                if secret and secret in blob:
                    raise AssertionError("private key appeared in test output")

    def _assert_no_secret_text(self, dialog, row, secrets):
        for column in range(dialog.table.columnCount()):
            cell = dialog.table.item(row, column)
            if cell is None:
                continue
            for secret in secrets:
                if secret and secret in cell.text():
                    raise AssertionError("record key text was shown in the manager")
                tooltip = cell._item.toolTip(column)
                if secret and tooltip and secret in tooltip:
                    raise AssertionError("record key text was shown in a tooltip")

    def run_empty_manager(self):
        dialog = SavedServicesDialog(self.gui.common, self.gui.tabs)
        self._dialog = dialog
        dialog.show()
        self.gui.qtapp.processEvents()
        self.assertEqual(dialog.windowTitle(), strings._("gui_saved_services_dialog_title"))
        self.assertEqual(dialog.windowTitle(), "Saved Services")
        self.assertTrue(dialog.empty_label.isVisible())
        self.assertTrue(dialog.empty_label.text().startswith("No saved services yet"))
        self.assertTrue(dialog.disclosure_label.isVisible())
        disclosure = dialog.disclosure_label.text().lower()
        self.assertTrue("unencrypted" in disclosure)
        self.assertTrue("not an encrypted backup" in disclosure)
        self.assertEqual(dialog.table.rowCount(), 0)
        self.assertFalse(dialog.table.isVisible())
        self.assertTrue(dialog.import_button.isEnabled())
        self.assertTrue(dialog.import_button.isDefault())
        self.assertFalse(dialog.open_button.isEnabled())
        self.assertFalse(dialog.export_button.isEnabled())
        self.assertFalse(dialog.rename_button.isEnabled())
        self.assertFalse(dialog.delete_button.isEnabled())

    def _assert_table_matches_disk(self, dialog):
        self.gui.common.settings.load()
        listed = []
        for row in range(dialog.table.rowCount()):
            item = dialog.table.item(row, 0)
            if item is None:
                continue
            service_id = item.data(QtCore.Qt.ItemDataRole.UserRole)
            listed.append(service_id)
        on_disk = list(self.gui.common.settings.get("saved_services"))
        if listed != on_disk:
            raise AssertionError("table does not match saved_services")
        directory = os.path.join(self.gui.common.build_data_dir(), "saved_services")
        names = []
        if os.path.isdir(directory) and not os.path.islink(directory):
            names = [
                name[: -len(".json")]
                for name in os.listdir(directory)
                if name.endswith(".json")
            ]
        if sorted(listed) != sorted(names):
            raise AssertionError("table does not match archive files")


@pytest.fixture(scope="module")
def saved_services_case():
    SavedServicesCase.setUpClass()
    yield SavedServicesCase
    SavedServicesCase.tearDownClass()


def test_symlinked_archive_directory_shows_list_error(
    saved_services_case, caplog, capsys
):
    case = saved_services_case("run_symlinked_archive_list_error")
    case.caplog = caplog
    case.capsys = capsys
    case.setUp()
    try:
        case.run_symlinked_archive_list_error()
    finally:
        case.tearDown()


def test_damaged_saved_service_row_can_be_deleted(
    saved_services_case, caplog, capsys
):
    case = saved_services_case("run_damaged_record_can_be_deleted")
    case.caplog = caplog
    case.capsys = capsys
    case.setUp()
    try:
        case.run_damaged_record_can_be_deleted()
    finally:
        case.tearDown()


def test_manager_empty_state_and_disabled_actions(saved_services_case, caplog, capsys):
    case = saved_services_case("run_empty_manager")
    case.caplog = caplog
    case.capsys = capsys
    case.setUp()
    try:
        case.run_empty_manager()
    finally:
        case.tearDown()


def test_post_commit_oserror_reloads_saved_services_table(
    saved_services_case, caplog, capsys
):
    case = saved_services_case("run_post_commit_oserror_reloads_table")
    case.caplog = caplog
    case.capsys = capsys
    case.setUp()
    try:
        case.run_post_commit_oserror_reloads_table()
    finally:
        case.tearDown()


@pytest.mark.parametrize("mode", ["share", "receive", "website", "chat"])
def test_open_saved_service_stays_stopped(saved_services_case, mode, caplog, capsys):
    case = saved_services_case("run_open_saved_service")
    case.caplog = caplog
    case.capsys = capsys
    case.setUp()
    try:
        case.run_open_saved_service(mode)
    finally:
        case.tearDown()
