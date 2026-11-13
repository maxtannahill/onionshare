# -*- coding: utf-8 -*-
"""
GUI tests for identity backup export.

Assertions that compare secrets use assertTrue/assertFalse so a failure does
not print passphrases, private keys, or decrypted identities.
"""

import errno
import gc
import inspect
import json
import logging
import os
import stat
import tempfile
import threading
import time
from unittest import mock

import pytest
from PySide6 import QtCore, QtGui, QtTest, QtWidgets
from shiboken6 import isValid

from onionshare_cli.identity_backup import IdentityBackupError, decrypt_identity
from onionshare_cli import saved_services as saved_services_module
from onionshare_cli.saved_services import SavedServices
from onionshare_cli.settings import Settings

from onionshare import identity_backup_dialog, strings
from onionshare.identity_backup_dialog import identity_for_open_tab
from onionshare.tab.server_status import ServerStatus
from onionshare.widgets import Alert, QRCodeDialog, qr_code_pixmap

from .gui_base_test import GuiBaseTest


def _fixture_identity():
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "cli",
        "tests",
        "persistent.json",
    )
    with open(path, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    return {
        "mode": document["persistent"]["mode"],
        "service_id": document["general"]["service_id"],
        "private_key": document["onion"]["private_key"],
        "client_auth_priv_key": document["onion"]["client_auth_priv_key"],
        "client_auth_pub_key": document["onion"]["client_auth_pub_key"],
        "public": document["general"]["public"],
    }


def _inject_keys_keep_mode_null(mode_settings, identity):
    """Copy the key fields and leave persistent.mode untouched."""
    mode_settings._settings["general"]["service_id"] = identity["service_id"]
    mode_settings._settings["general"]["public"] = identity["public"]
    mode_settings._settings["onion"]["private_key"] = identity["private_key"]
    mode_settings._settings["onion"]["client_auth_priv_key"] = identity[
        "client_auth_priv_key"
    ]
    mode_settings._settings["onion"]["client_auth_pub_key"] = identity[
        "client_auth_pub_key"
    ]


def _inject_identity(mode_settings, identity):
    """
    Put a fixture identity on a tab without ModeSettings.set.

    set() logs the value, and verbose tests would then print the private key.
    """
    mode_settings._settings["persistent"]["mode"] = identity["mode"]
    mode_settings._settings["general"]["service_id"] = identity["service_id"]
    mode_settings._settings["general"]["public"] = identity["public"]
    mode_settings._settings["onion"]["private_key"] = identity["private_key"]
    mode_settings._settings["onion"]["client_auth_priv_key"] = identity[
        "client_auth_priv_key"
    ]
    mode_settings._settings["onion"]["client_auth_pub_key"] = identity[
        "client_auth_pub_key"
    ]


def _secrets_of(identity, *passphrases):
    values = [
        identity["private_key"],
        identity["client_auth_priv_key"],
    ]
    for passphrase in passphrases:
        if passphrase:
            values.append(passphrase)
    return values


def _assert_secrets_absent(test, blobs, secrets):
    for blob in blobs:
        if blob is None:
            continue
        if isinstance(blob, bytes):
            for secret in secrets:
                test.assertFalse(secret.encode("utf-8") in blob)
        else:
            text = str(blob)
            for secret in secrets:
                test.assertFalse(secret in text)


def _image_bytes(pixmap):
    image = pixmap.toImage().convertToFormat(QtGui.QImage.Format.Format_ARGB32)
    bits = image.constBits()
    return bytes(bits)


class TestIdentityBackupGui(GuiBaseTest):
    @pytest.fixture(autouse=True)
    def _capture(self, caplog, capsys):
        self.caplog = caplog
        self.capsys = capsys

    def tearDown(self):
        dialog = getattr(self, "_dialog", None)
        self._dialog = None
        if dialog is not None and isValid(dialog):
            try:
                thread = dialog.encrypt_thread
                if (
                    thread is not None
                    and isValid(thread)
                    and thread.isRunning()
                ):
                    thread.wait(180000)
                dialog.close()
            except RuntimeError:
                pass
        self.close_all_tabs()

    def _wait_until(self, predicate, timeout=120):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.gui.qtapp.processEvents()
            if predicate():
                self.gui.qtapp.processEvents()
                return
            time.sleep(0.02)
        self.fail("timed out waiting for identity backup")

    def _open_export_dialog(self, tab):
        widget = tab.get_mode().mode_settings_widget
        with mock.patch.object(
            QtWidgets.QDialog,
            "exec",
            return_value=QtWidgets.QDialog.DialogCode.Accepted,
        ):
            widget.export_identity_backup_button.click()
        dialog = widget.identity_backup_dialog
        self._dialog = dialog
        self._wait_until(lambda: dialog.generation >= 1 and not dialog.is_busy)
        return dialog

    def _guard_start_server(self, mode):
        calls = []
        status = mode.server_status
        real_mode_start = mode.start_server
        real_status_start = status.start_server

        def mode_start(*args, **kwargs):
            calls.append("mode")
            return real_mode_start(*args, **kwargs)

        def status_start(*args, **kwargs):
            calls.append("status")
            return real_status_start(*args, **kwargs)

        try:
            status.server_started.disconnect(real_mode_start)
        except (RuntimeError, TypeError):
            pass
        mode.start_server = mode_start
        status.start_server = status_start
        status.server_started.connect(mode_start)
        return calls, real_mode_start, real_status_start

    def _restore_start_server(self, mode, real_mode_start, real_status_start):
        status = mode.server_status
        current = mode.start_server
        try:
            status.server_started.disconnect(current)
        except (RuntimeError, TypeError):
            pass
        mode.start_server = real_mode_start
        status.start_server = real_status_start
        status.server_started.connect(real_mode_start)

    def _capture_common_log(self):
        messages = []
        common = self.gui.common
        original = common.log

        def wrapped(module, func, msg=None):
            messages.append(msg)
            return original(module, func, msg)

        common.log = wrapped
        return messages, original

    def _restore_common_log(self, original):
        self.gui.common.log = original

    def _log_blobs(self, messages):
        captured = self.capsys.readouterr()
        blobs = [self.caplog.text, captured.out, captured.err]
        for message in messages:
            if message is not None:
                blobs.append(message)
        return blobs

    def test_export_button_disabled_without_private_key(self):
        """A never-started local-only tab cannot export; the server stays stopped."""
        tab = self.new_share_tab()
        tab.get_mode().server_status.file_selection.file_list.add_file(self.tmpfiles[0])
        mode = tab.get_mode()
        widget = mode.mode_settings_widget
        self.assertIsNone(tab.settings.get("onion", "private_key"))
        self.assertEqual(mode.server_status.status, ServerStatus.STATUS_STOPPED)
        self.assertTrue(widget.export_identity_backup_button.isVisible())
        self.assertFalse(widget.export_identity_backup_button.isHidden())
        self.assertFalse(widget.export_identity_backup_button.isEnabled())
        self.assertTrue(widget.save_to_saved_services_button.isVisible())
        self.assertFalse(widget.save_to_saved_services_button.isEnabled())
        widget.update_ui()
        self.assertFalse(widget.export_identity_backup_button.isEnabled())
        self.assertEqual(mode.server_status.status, ServerStatus.STATUS_STOPPED)

    def test_export_button_hidden_in_download_mode(self):
        tab = self.gui.tabs.widget(0)
        self.verify_new_tab(tab)
        tab.download_button.click()
        widget = tab.download_mode.mode_settings_widget
        self.assertTrue(widget.export_identity_backup_button.isHidden())
        self.assertFalse(widget.export_identity_backup_button.isVisible())
        self.assertTrue(widget.save_to_saved_services_button.isHidden())
        self.assertFalse(widget.save_to_saved_services_button.isVisible())
        self.assertEqual(
            tab.download_mode.server_status.status, ServerStatus.STATUS_STOPPED
        )

    def test_qr_code_dialog_constructor_unchanged(self):
        """
        URL and client-auth callers still construct QRCodeDialog(common, title, text)
        and that constructor still blocks on exec().
        """
        signature = inspect.signature(QRCodeDialog.__init__)
        self.assertEqual(
            list(signature.parameters),
            ["self", "common", "title", "text"],
        )
        source = inspect.getsource(QRCodeDialog.__init__)
        self.assertIn("self.exec()", source)
        self.assertIn("qr_code_pixmap(text)", source)
        url_source = inspect.getsource(ServerStatus.show_url_qr_code_button_clicked)
        auth_source = inspect.getsource(
            ServerStatus.show_client_auth_qr_code_button_clicked
        )
        self.assertIn("QRCodeDialog(", url_source)
        self.assertIn("QRCodeDialog(", auth_source)
        self.assertNotIn("ExportIdentityBackupDialog", url_source)
        self.assertNotIn("ExportIdentityBackupDialog", auth_source)

        tab = self.new_share_tab()
        status = tab.get_mode().server_status
        self.assertEqual(status.status, ServerStatus.STATUS_STOPPED)
        url = "http://example.onion/share"
        auth = "CLIENT-AUTH-EXAMPLE"
        with mock.patch.object(QRCodeDialog, "exec", return_value=0) as exec_mock:
            with mock.patch.object(status, "get_url", return_value=url):
                status.show_url_qr_code_button_clicked()
            url_dialog = status.qr_code_dialog
            status.app.auth_string = auth
            status.show_client_auth_qr_code_button_clicked()
            auth_dialog = status.qr_code_dialog
        self.assertEqual(exec_mock.call_count, 2)
        self.assertIsInstance(url_dialog, QRCodeDialog)
        self.assertIsInstance(auth_dialog, QRCodeDialog)
        self.assertIsNot(url_dialog, auth_dialog)
        self.assertEqual(
            url_dialog.qr_label_title.text(), strings._("gui_qr_label_url_title")
        )
        self.assertEqual(
            auth_dialog.qr_label_title.text(),
            strings._("gui_qr_label_auth_string_title"),
        )
        self.assertEqual(
            url_dialog.windowTitle(), strings._("gui_qr_code_dialog_title")
        )
        self.assertEqual(
            auth_dialog.windowTitle(), strings._("gui_qr_code_dialog_title")
        )
        self.assertTrue(
            _image_bytes(url_dialog.qr_label.pixmap())
            == _image_bytes(qr_code_pixmap(url))
        )
        self.assertTrue(
            _image_bytes(auth_dialog.qr_label.pixmap())
            == _image_bytes(qr_code_pixmap(auth))
        )
        self.assertEqual(status.status, ServerStatus.STATUS_STOPPED)

    def test_export_qr_text_equals_saved_bytes_and_round_trips(self):
        identity = _fixture_identity()
        tab = self.new_share_tab()
        tab.get_mode().server_status.file_selection.file_list.add_file(self.tmpfiles[0])
        mode = tab.get_mode()
        _inject_identity(tab.settings, identity)
        widget = mode.mode_settings_widget
        widget.update_ui()
        self.assertTrue(widget.export_identity_backup_button.isVisible())
        self.assertTrue(widget.export_identity_backup_button.isEnabled())
        self.assertEqual(mode.server_status.status, ServerStatus.STATUS_STOPPED)
        persistent_before = list(self.gui.common.settings.get("persistent_tabs"))
        persistent_filename = tab.settings.filename
        had_persistent_file = os.path.exists(persistent_filename)

        calls, real_mode_start, real_status_start = self._guard_start_server(mode)
        try:
            dialog = self._open_export_dialog(tab)
            self.assertFalse(dialog.encrypt_thread.worker_thread is None)
            main_thread = QtCore.QCoreApplication.instance().thread()
            self.assertFalse(dialog.encrypt_thread.worker_thread is main_thread)
            self.assertTrue(dialog.encrypt_thread.worker_thread is dialog.encrypt_thread)
            self.assertTrue(dialog.qr_text.encode("utf-8") == dialog.pending_bytes)
            self.assertFalse(dialog.pending_bytes.endswith(b"\n"))
            self.assertFalse(dialog.passphrase.encode("utf-8") in dialog.pending_bytes)
            _assert_secrets_absent(
                self,
                [dialog.pending_bytes, dialog.qr_text],
                _secrets_of(identity, dialog.passphrase),
            )
            restored = decrypt_identity(dialog.qr_text, dialog.passphrase)
            self.assertTrue(restored == identity)

            fd, path = tempfile.mkstemp(suffix=".json")
            os.close(fd)
            try:
                with mock.patch.object(
                    QtWidgets.QFileDialog,
                    "getSaveFileName",
                    return_value=(path, "json"),
                ):
                    dialog.save_button.click()
                with open(path, "rb") as handle:
                    file_bytes = handle.read()
            finally:
                os.remove(path)
            self.assertTrue(file_bytes == dialog.pending_bytes)
            self.assertTrue(dialog.qr_text.encode("utf-8") == file_bytes)
            self.assertFalse(dialog.passphrase.encode("utf-8") in file_bytes)
            from_file = decrypt_identity(file_bytes.decode("utf-8"), dialog.passphrase)
            self.assertTrue(from_file == identity)
        finally:
            self._restore_start_server(mode, real_mode_start, real_status_start)

        self.assertFalse(calls)
        self.assertEqual(mode.server_status.status, ServerStatus.STATUS_STOPPED)
        self.assertEqual(
            list(self.gui.common.settings.get("persistent_tabs")), persistent_before
        )
        self.assertTrue(os.path.exists(persistent_filename) == had_persistent_file)

    def test_regenerate_replaces_passphrase_salt_and_ciphertext(self):
        identity = _fixture_identity()
        tab = self.new_share_tab()
        mode = tab.get_mode()
        _inject_identity(tab.settings, identity)
        mode.mode_settings_widget.update_ui()
        calls, real_mode_start, real_status_start = self._guard_start_server(mode)
        try:
            dialog = self._open_export_dialog(tab)
            first_passphrase = dialog.passphrase
            first_qr = dialog.qr_text
            first_bytes = dialog.pending_bytes
            first_thread = dialog.encrypt_thread
            first_envelope = json.loads(first_qr)
            generation = dialog.generation

            dialog.regenerate_button.click()
            self._wait_until(
                lambda: dialog.generation > generation and not dialog.is_busy
            )

            second_envelope = json.loads(dialog.qr_text)
            self.assertFalse(dialog.passphrase == first_passphrase)
            self.assertFalse(second_envelope["salt"] == first_envelope["salt"])
            self.assertFalse(second_envelope["n"] == first_envelope["n"])
            self.assertFalse(second_envelope["ct"] == first_envelope["ct"])
            self.assertFalse(dialog.qr_text == first_qr)
            self.assertFalse(dialog.pending_bytes == first_bytes)
            self.assertTrue(dialog.qr_text.encode("utf-8") == dialog.pending_bytes)
            self.assertFalse(dialog.encrypt_thread is first_thread)
            main_thread = QtCore.QCoreApplication.instance().thread()
            self.assertFalse(dialog.encrypt_thread.worker_thread is main_thread)
            self.assertTrue(dialog.encrypt_thread.worker_thread is dialog.encrypt_thread)

            restored = decrypt_identity(dialog.qr_text, dialog.passphrase)
            self.assertTrue(restored == identity)
            old_failed = False
            try:
                decrypt_identity(dialog.qr_text, first_passphrase)
            except IdentityBackupError:
                old_failed = True
            self.assertTrue(old_failed)
            self.assertFalse(first_passphrase.encode("utf-8") in dialog.pending_bytes)
            self.assertFalse(dialog.passphrase.encode("utf-8") in dialog.pending_bytes)

            fd, path = tempfile.mkstemp(suffix=".json")
            os.close(fd)
            try:
                with mock.patch.object(
                    QtWidgets.QFileDialog,
                    "getSaveFileName",
                    return_value=(path, "json"),
                ):
                    dialog.save_button.click()
                with open(path, "rb") as handle:
                    file_bytes = handle.read()
            finally:
                os.remove(path)
            self.assertTrue(file_bytes == dialog.pending_bytes)
            self.assertFalse(file_bytes == first_bytes)
        finally:
            self._restore_start_server(mode, real_mode_start, real_status_start)
        self.assertFalse(calls)
        self.assertEqual(mode.server_status.status, ServerStatus.STATUS_STOPPED)

    def test_secrets_absent_from_bytes_and_logs(self):
        """Export, regenerate, and save must not log or write the passphrase or keys."""
        identity = _fixture_identity()
        tab = self.new_share_tab()
        mode = tab.get_mode()
        _inject_identity(tab.settings, identity)
        mode.mode_settings_widget.update_ui()
        # Drop logs from opening the tab before the operations under test.
        self.capsys.readouterr()
        self.caplog.clear()
        messages, original_log = self._capture_common_log()
        try:
            with self.caplog.at_level(logging.DEBUG):
                dialog = self._open_export_dialog(tab)
                first_passphrase = dialog.passphrase
                generation = dialog.generation
                dialog.regenerate_button.click()
                self._wait_until(
                    lambda: dialog.generation > generation and not dialog.is_busy
                )
                fd, path = tempfile.mkstemp(suffix=".json")
                os.close(fd)
                try:
                    with mock.patch.object(
                        QtWidgets.QFileDialog,
                        "getSaveFileName",
                        return_value=(path, "json"),
                    ):
                        dialog.save_button.click()
                    with open(path, "rb") as handle:
                        file_bytes = handle.read()
                finally:
                    os.remove(path)
                blobs = self._log_blobs(messages)
                blobs.extend([file_bytes, dialog.pending_bytes, dialog.qr_text])
                _assert_secrets_absent(
                    self,
                    blobs,
                    _secrets_of(identity, first_passphrase, dialog.passphrase),
                )
                self.assertTrue(file_bytes == dialog.pending_bytes)
                self.assertTrue(dialog.qr_text.encode("utf-8") == file_bytes)
        finally:
            self._restore_common_log(original_log)

    def test_save_to_saved_services_discloses_and_does_not_overwrite(self):
        identity = _fixture_identity()
        tab = self.new_share_tab()
        _inject_identity(tab.settings, identity)
        widget = tab.get_mode().mode_settings_widget
        widget.update_ui()
        self.assertTrue(widget.save_to_saved_services_button.isEnabled())
        persistent_before = list(self.gui.common.settings.get("persistent_tabs"))
        record_path = os.path.join(
            self.gui.common.build_data_dir(),
            "saved_services",
            identity["service_id"] + ".json",
        )

        ok = QtWidgets.QMessageBox.StandardButton.Ok
        no = QtWidgets.QMessageBox.StandardButton.No
        # disclosure, saved notice, disclosure, decline replace, unchanged notice
        answers = [ok, ok, ok, no, ok]
        order = []
        from onionshare.widgets import Alert

        real_alert_init = Alert.__init__

        def alert_init(box, common, message, *args, **kwargs):
            order.append(message)
            return real_alert_init(box, common, message, *args, **kwargs)

        def exec_side_effect(*args, **kwargs):
            order.append("dialog")
            return answers.pop(0)

        from onionshare_cli.saved_services import SavedServices

        real_add = SavedServices.add

        def add(archive, *args, **kwargs):
            order.append("add")
            return real_add(archive, *args, **kwargs)

        disclosure = strings._("gui_identity_backup_archive_disclosure")
        duplicate = strings._("gui_identity_backup_archive_duplicate")
        with mock.patch.object(Alert, "__init__", alert_init):
            with mock.patch.object(
                QtWidgets.QMessageBox, "exec", side_effect=exec_side_effect
            ):
                with mock.patch.object(
                    QtWidgets.QInputDialog,
                    "getText",
                    side_effect=[("First label", True), ("Second label", True)],
                ):
                    with mock.patch.object(SavedServices, "add", add):
                        widget.save_to_saved_services_button.click()
                        self.assertTrue(os.path.isfile(record_path))
                        with open(record_path, "rb") as handle:
                            first_bytes = handle.read()
                        first_label = json.loads(first_bytes.decode("utf-8"))["label"]
                        self.assertTrue(first_label == "First label")
                        self.assertTrue(disclosure in order)
                        self.assertTrue(order.index(disclosure) < order.index("add"))
                        self.assertTrue("unencrypted" in disclosure)
                        widget.save_to_saved_services_button.click()
                        with open(record_path, "rb") as handle:
                            second_bytes = handle.read()
                        self.assertTrue(second_bytes == first_bytes)
                        self.assertTrue(duplicate in order)
                        self.assertTrue(order.index(duplicate) > order.index("add"))
        self.assertFalse(answers)
        self.assertEqual(
            list(self.gui.common.settings.get("persistent_tabs")), persistent_before
        )
        self.assertEqual(
            tab.get_mode().server_status.status, ServerStatus.STATUS_STOPPED
        )
        _assert_secrets_absent(
            self,
            [str(message) for message in order],
            _secrets_of(identity),
        )

    def _prepare_share_with_identity(self):
        identity = _fixture_identity()
        tab = self.new_share_tab()
        _inject_identity(tab.settings, identity)
        tab.get_mode().mode_settings_widget.update_ui()
        return tab

    def _close_tab_now(self):
        self.gui.tabs.tabBar().tabButton(
            0, QtWidgets.QTabBar.ButtonPosition.RightSide
        ).click()

    def test_close_button_during_kdf_finishes_thread_without_alert_or_file(self):
        tab = self._prepare_share_with_identity()
        widget = tab.get_mode().mode_settings_widget
        started = threading.Event()
        alerts = []
        saves = []
        real_encrypt = identity_backup_dialog.encrypt_identity
        real_alert_init = Alert.__init__

        def slow(identity, passphrase):
            started.set()
            time.sleep(0.8)
            return real_encrypt(identity, passphrase)

        def alert_init(box, common, message, *args, **kwargs):
            alerts.append(message)
            return real_alert_init(box, common, message, *args, **kwargs)

        def record_save(*args, **kwargs):
            saves.append(True)
            return ("", "")

        with mock.patch.object(identity_backup_dialog, "encrypt_identity", slow):
            with mock.patch.object(Alert, "__init__", alert_init):
                with mock.patch.object(
                    QtWidgets.QFileDialog, "getSaveFileName", record_save
                ):
                    def close_when_started():
                        dialog = widget.identity_backup_dialog
                        if dialog is None or not started.is_set():
                            QtCore.QTimer.singleShot(10, close_when_started)
                            return
                        dialog.close_button.click()

                    QtCore.QTimer.singleShot(10, close_when_started)
                    widget.export_identity_backup_button.click()
                    dialog = widget.identity_backup_dialog
                    self._dialog = dialog
                    thread = dialog.encrypt_thread
        self.gui.qtapp.processEvents()
        self.assertFalse(thread.isRunning())
        self.assertTrue(thread.isFinished())
        self.assertFalse(dialog.isVisible())
        self.assertFalse(alerts)
        self.assertFalse(saves)
        self.assertEqual(
            tab.get_mode().server_status.status, ServerStatus.STATUS_STOPPED
        )

    def test_escape_during_kdf_finishes_thread_without_alert_or_file(self):
        tab = self._prepare_share_with_identity()
        widget = tab.get_mode().mode_settings_widget
        started = threading.Event()
        alerts = []
        saves = []
        real_encrypt = identity_backup_dialog.encrypt_identity
        real_alert_init = Alert.__init__

        def slow(identity, passphrase):
            started.set()
            time.sleep(0.8)
            return real_encrypt(identity, passphrase)

        def alert_init(box, common, message, *args, **kwargs):
            alerts.append(message)
            return real_alert_init(box, common, message, *args, **kwargs)

        def record_save(*args, **kwargs):
            saves.append(True)
            return ("", "")

        with mock.patch.object(identity_backup_dialog, "encrypt_identity", slow):
            with mock.patch.object(Alert, "__init__", alert_init):
                with mock.patch.object(
                    QtWidgets.QFileDialog, "getSaveFileName", record_save
                ):
                    def escape_when_started():
                        dialog = widget.identity_backup_dialog
                        if dialog is None or not started.is_set():
                            QtCore.QTimer.singleShot(10, escape_when_started)
                            return
                        QtTest.QTest.keyClick(dialog, QtCore.Qt.Key.Key_Escape)

                    QtCore.QTimer.singleShot(10, escape_when_started)
                    widget.export_identity_backup_button.click()
                    dialog = widget.identity_backup_dialog
                    self._dialog = dialog
                    thread = dialog.encrypt_thread
        self.gui.qtapp.processEvents()
        self.assertFalse(thread.isRunning())
        self.assertTrue(thread.isFinished())
        self.assertFalse(dialog.isVisible())
        self.assertFalse(alerts)
        self.assertFalse(saves)

    def test_tab_close_during_kdf_finishes_thread_without_alert_or_file(self):
        tab = self._prepare_share_with_identity()
        widget = tab.get_mode().mode_settings_widget
        started = threading.Event()
        alerts = []
        saves = []
        real_encrypt = identity_backup_dialog.encrypt_identity
        real_alert_init = Alert.__init__

        def slow(identity, passphrase):
            started.set()
            time.sleep(0.8)
            return real_encrypt(identity, passphrase)

        def alert_init(box, common, message, *args, **kwargs):
            alerts.append(message)
            return real_alert_init(box, common, message, *args, **kwargs)

        def record_save(*args, **kwargs):
            saves.append(True)
            return ("", "")

        with mock.patch.object(identity_backup_dialog, "encrypt_identity", slow):
            with mock.patch.object(Alert, "__init__", alert_init):
                with mock.patch.object(
                    QtWidgets.QFileDialog, "getSaveFileName", record_save
                ):
                    with mock.patch.object(
                        QtWidgets.QDialog,
                        "exec",
                        return_value=QtWidgets.QDialog.DialogCode.Accepted,
                    ):
                        widget.export_identity_backup_button.click()
                    dialog = widget.identity_backup_dialog
                    self._dialog = dialog
                    self._wait_until(started.is_set)
                    thread = dialog.encrypt_thread
                    self.assertTrue(thread.isRunning())
                    self._close_tab_now()
        self.gui.qtapp.processEvents()
        self.assertFalse(thread.isRunning())
        self.assertTrue(thread.isFinished())
        self.assertFalse(alerts)
        self.assertFalse(saves)
        self._dialog = None

    def test_actions_disabled_while_encryption_runs(self):
        tab = self._prepare_share_with_identity()
        widget = tab.get_mode().mode_settings_widget
        started = threading.Event()
        release = threading.Event()
        seen = {}
        real_encrypt = identity_backup_dialog.encrypt_identity

        def slow(identity, passphrase):
            started.set()
            release.wait(timeout=30)
            return real_encrypt(identity, passphrase)

        with mock.patch.object(identity_backup_dialog, "encrypt_identity", slow):
            def watch():
                dialog = widget.identity_backup_dialog
                if dialog is None or not started.is_set():
                    QtCore.QTimer.singleShot(10, watch)
                    return
                if "save" not in seen:
                    seen["save"] = dialog.save_button.isEnabled()
                    seen["regenerate"] = dialog.regenerate_button.isEnabled()
                    seen["archive"] = dialog.save_to_saved_services_button.isEnabled()
                    seen["busy"] = dialog.is_busy
                    release.set()
                if dialog.generation >= 1 and not dialog.is_busy:
                    dialog.accept()
                    return
                QtCore.QTimer.singleShot(20, watch)

            QtCore.QTimer.singleShot(10, watch)
            widget.export_identity_backup_button.click()
            dialog = widget.identity_backup_dialog
            self._dialog = dialog
        self.assertTrue(seen.get("busy") is True)
        self.assertTrue(seen.get("save") is False)
        self.assertTrue(seen.get("regenerate") is False)
        self.assertTrue(seen.get("archive") is False)
        self.assertFalse(dialog.encrypt_thread.isRunning())

    def test_null_persistent_mode_uses_open_tab_mode_without_mutation(self):
        identity = _fixture_identity()
        openers = (
            ("share", self.new_share_tab),
            ("receive", self.new_receive_tab),
            ("website", self.new_website_tab),
            ("chat", self.new_chat_tab),
        )
        for mode_name, opener in openers:
            tab = opener()
            _inject_keys_keep_mode_null(tab.settings, identity)
            self.assertTrue(tab.settings.get("persistent", "mode") is None)
            onion_before = tab.settings.get("onion", "private_key")
            result = identity_for_open_tab(tab.settings, tab.mode)
            self.assertTrue(result["mode"] == mode_name)
            self.assertTrue(result["service_id"] == identity["service_id"])
            self.assertTrue(result["public"] == identity["public"])
            self.assertTrue(tab.settings.get("persistent", "mode") is None)
            self.assertTrue(tab.settings.get("onion", "private_key") == onion_before)
            self.assertTrue(tab.mode == mode_name)
            self.close_all_tabs()

    def test_failed_save_preserves_existing_file_and_temp(self):
        tab = self._prepare_share_with_identity()
        dialog = self._open_export_dialog(tab)
        payload = dialog.pending_bytes
        original = b"pre-existing-backup-bytes"
        self.assertFalse(payload == original)

        def attempt(explode):
            directory = tempfile.mkdtemp()
            path = os.path.join(directory, "backup.json")
            with open(path, "wb") as handle:
                handle.write(original)
            with mock.patch.object(
                QtWidgets.QFileDialog, "getSaveFileName", return_value=(path, "json")
            ):
                with mock.patch.object(
                    QtWidgets.QMessageBox,
                    "exec",
                    return_value=QtWidgets.QMessageBox.StandardButton.Ok,
                ):
                    with explode:
                        dialog.save_button.click()
            with open(path, "rb") as handle:
                kept = handle.read()
            names = os.listdir(directory)
            self.assertTrue(kept == original)
            self.assertFalse(any(name.startswith(".tmp-") for name in names))

        attempt(
            mock.patch.object(
                identity_backup_dialog.os, "replace", side_effect=OSError("replace")
            )
        )
        attempt(
            mock.patch.object(
                identity_backup_dialog.os,
                "fdopen",
                side_effect=OSError("write"),
            )
        )
        self.assertTrue(dialog.qr_text.encode("utf-8") == dialog.pending_bytes)

    def test_invalid_label_shows_dedicated_message_and_writes_nothing(self):
        identity = _fixture_identity()
        tab = self.new_share_tab()
        _inject_identity(tab.settings, identity)
        widget = tab.get_mode().mode_settings_widget
        widget.update_ui()
        label = "bad\nlabel"
        record_path = os.path.join(
            self.gui.common.build_data_dir(),
            "saved_services",
            identity["service_id"] + ".json",
        )
        saved_before = list(self.gui.common.settings.get("saved_services"))
        existed = os.path.exists(record_path)
        before_bytes = None
        if existed:
            with open(record_path, "rb") as handle:
                before_bytes = handle.read()
        messages = []
        real_alert_init = Alert.__init__

        def alert_init(box, common, message, *args, **kwargs):
            messages.append(message)
            kwargs = dict(kwargs)
            kwargs["autostart"] = False
            return real_alert_init(box, common, message, *args, **kwargs)

        log_messages, original_log = self._capture_common_log()
        try:
            ok = QtWidgets.QMessageBox.StandardButton.Ok
            with mock.patch.object(Alert, "__init__", alert_init):
                with mock.patch.object(
                    QtWidgets.QMessageBox, "exec", return_value=ok
                ):
                    with mock.patch.object(
                        QtWidgets.QInputDialog,
                        "getText",
                        return_value=(label, True),
                    ):
                        widget.save_to_saved_services_button.click()
        finally:
            self._restore_common_log(original_log)

        dedicated = strings._("gui_identity_backup_invalid_label")
        self.assertTrue(dedicated in messages)
        self.assertTrue("100" in dedicated)
        self.assertTrue("control" in dedicated)
        if existed:
            with open(record_path, "rb") as handle:
                after_bytes = handle.read()
            self.assertTrue(after_bytes == before_bytes)
        else:
            self.assertFalse(os.path.exists(record_path))
        archive_dir = os.path.join(self.gui.common.build_data_dir(), "saved_services")
        if os.path.isdir(archive_dir):
            names = os.listdir(archive_dir)
            self.assertFalse(any(name.startswith(".tmp-") for name in names))
        self.assertEqual(
            list(self.gui.common.settings.get("saved_services")), saved_before
        )
        blobs = ["" if message is None else str(message) for message in log_messages]
        blobs.append("\n".join(str(message) for message in messages))
        _assert_secrets_absent(self, blobs, [label])
        for blob in blobs:
            self.assertFalse("invalid label" in blob)

    def test_archive_oserror_shows_fixed_message_and_writes_nothing(self):
        """A durable-write OSError on Save to Saved Services shows the archive alert.

        Covers a new record and a confirmed replace. Neither opens a tab.
        The temp file is removed. Settings bytes, the persistent directory,
        and the archive directory are unchanged by the failed write.
        """
        identity = _fixture_identity()
        tab = self.new_share_tab()
        _inject_identity(tab.settings, identity)
        widget = tab.get_mode().mode_settings_widget
        widget.update_ui()
        self.assertTrue(widget.save_to_saved_services_button.isEnabled())

        data_dir = self.gui.common.build_data_dir()
        settings_path = self.gui.common.settings.filename
        persistent_dir = os.path.join(data_dir, "persistent")
        archive_dir = os.path.join(data_dir, "saved_services")
        record_path = os.path.join(archive_dir, identity["service_id"] + ".json")
        os.makedirs(archive_dir, 0o700, exist_ok=True)
        archive = SavedServices(self.gui.common, self.gui.common.settings)
        if os.path.isfile(record_path) or identity["service_id"] in list(
            self.gui.common.settings.get("saved_services")
        ):
            archive.delete(identity["service_id"])

        def read_bytes(path):
            if not os.path.isfile(path):
                return None
            with open(path, "rb") as handle:
                return handle.read()

        def tree(path):
            if not os.path.isdir(path):
                return None
            found = {}
            for name in sorted(os.listdir(path)):
                full = os.path.join(path, name)
                if os.path.islink(full):
                    found[name] = "link"
                elif os.path.isfile(full):
                    with open(full, "rb") as handle:
                        found[name] = handle.read()
                else:
                    found[name] = "dir"
            return found

        def no_temp():
            names = os.listdir(archive_dir)
            self.assertFalse(any(name.startswith(".tmp-") for name in names))

        disclosure = strings._("gui_identity_backup_archive_disclosure")
        duplicate = strings._("gui_identity_backup_archive_duplicate")
        archive_error = strings._("gui_identity_backup_archive_error")
        saved = strings._("gui_identity_backup_archive_saved")
        self.assertEqual(archive_error, "Could not save this service.")
        disk_error = "disk-write-failed"
        tab_count = self.gui.tabs.count()
        log_messages, original_log = self._capture_common_log()

        def attempt(label):
            messages = []
            replace_calls = []

            def exec_box(box, *args, **kwargs):
                text = box.text()
                messages.append(text)
                if text == duplicate:
                    return QtWidgets.QMessageBox.StandardButton.Yes
                return QtWidgets.QMessageBox.StandardButton.Ok

            real_replace = saved_services_module.os.replace

            def explode(src, dst, *args, **kwargs):
                destination = dst if isinstance(dst, (str, bytes)) else ""
                if isinstance(destination, bytes):
                    destination = destination.decode("utf-8", "replace")
                if "saved_services" in destination and destination.endswith(".json"):
                    replace_calls.append(True)
                    raise OSError(disk_error)
                return real_replace(src, dst, *args, **kwargs)

            with mock.patch.object(QtWidgets.QMessageBox, "exec", exec_box):
                with mock.patch.object(
                    QtWidgets.QInputDialog, "getText", return_value=(label, True)
                ):
                    with mock.patch.object(
                        saved_services_module.os, "replace", explode
                    ):
                        widget.save_to_saved_services_button.click()
            return messages, replace_calls

        try:
            self.gui.common.settings.save()
            settings_before = read_bytes(settings_path)
            persistent_before = tree(persistent_dir)
            archive_before = tree(archive_dir)
            self.assertTrue(settings_before is not None)
            self.assertFalse(os.path.exists(record_path))

            messages, replace_calls = attempt("first-label")
            seen_messages = list(messages)
            self.assertEqual(messages, [disclosure, archive_error])
            self.assertEqual(
                [text for text in messages if text != disclosure], [archive_error]
            )
            for text in messages:
                self.assertFalse(disk_error in text)
            self.assertEqual(replace_calls, [True])
            self.assertFalse(os.path.exists(record_path))
            no_temp()
            self.assertTrue(read_bytes(settings_path) == settings_before)
            self.assertTrue(tree(persistent_dir) == persistent_before)
            self.assertTrue(tree(archive_dir) == archive_before)
            self.assertEqual(self.gui.tabs.count(), tab_count)
            self.assertEqual(
                tab.get_mode().server_status.status, ServerStatus.STATUS_STOPPED
            )

            archive.add(identity, "seed-label")
            self.assertTrue(os.path.isfile(record_path))
            record_before = read_bytes(record_path)
            settings_seed = read_bytes(settings_path)
            persistent_seed = tree(persistent_dir)
            archive_seed = tree(archive_dir)

            messages, replace_calls = attempt("second-label")
            seen_messages.extend(messages)
            self.assertEqual(messages, [disclosure, duplicate, archive_error])
            self.assertEqual(
                [text for text in messages if text not in (disclosure, duplicate)],
                [archive_error],
            )
            self.assertFalse(saved in messages)
            self.assertFalse(
                strings._("gui_identity_backup_invalid_label") in messages
            )
            self.assertEqual(replace_calls, [True])
            self.assertTrue(read_bytes(record_path) == record_before)
            no_temp()
            self.assertTrue(read_bytes(settings_path) == settings_seed)
            self.assertTrue(tree(persistent_dir) == persistent_seed)
            self.assertTrue(tree(archive_dir) == archive_seed)
            self.assertEqual(self.gui.tabs.count(), tab_count)
            self.assertEqual(
                tab.get_mode().server_status.status, ServerStatus.STATUS_STOPPED
            )
            for text in messages:
                self.assertFalse(disk_error in text)
        finally:
            self._restore_common_log(original_log)
            try:
                SavedServices(self.gui.common, self.gui.common.settings).delete(
                    identity["service_id"]
                )
            except Exception:
                pass

        blobs = self._log_blobs(log_messages)
        blobs.append("\n".join(seen_messages))
        _assert_secrets_absent(
            self,
            blobs,
            _secrets_of(identity) + [disk_error],
        )

    def test_cleanup_abandons_blocked_worker_without_applying_result(self):
        tab = self._prepare_share_with_identity()
        widget = tab.get_mode().mode_settings_widget
        started = threading.Event()
        release = threading.Event()
        tabs_before = self.gui.tabs.count()
        saved_before = list(self.gui.common.settings.get("saved_services"))

        def blocked(identity, passphrase):
            started.set()
            release.wait(timeout=30)
            return "{}"

        try:
            with mock.patch.object(
                identity_backup_dialog, "encrypt_identity", blocked
            ):
                with mock.patch.object(
                    QtWidgets.QDialog,
                    "exec",
                    return_value=QtWidgets.QDialog.DialogCode.Accepted,
                ):
                    widget.export_identity_backup_button.click()
                dialog = widget.identity_backup_dialog
                self._dialog = dialog
                self._wait_until(started.is_set)
                self.assertTrue(dialog.encrypt_thread.isRunning())
                with mock.patch.object(
                    identity_backup_dialog, "_ENCRYPT_THREAD_WAIT_MS", 80
                ):
                    tab.cleanup()
                if dialog._accepting_results:
                    raise AssertionError("quit re-armed the export worker")
                if dialog.pending_bytes is not None or dialog.envelope is not None:
                    raise AssertionError("envelope applied during cleanup")
                release.set()
                self._wait_until(lambda: not dialog.encrypt_thread.isRunning())
                for _ in range(20):
                    self.gui.qtapp.processEvents()
                if dialog.pending_bytes is not None or dialog.envelope is not None:
                    raise AssertionError("envelope applied after cleanup")
                if self.gui.tabs.count() != tabs_before:
                    raise AssertionError("cleanup opened a tab")
                if list(self.gui.common.settings.get("saved_services")) != saved_before:
                    raise AssertionError("cleanup wrote saved services")
        finally:
            release.set()

    def test_deleting_dialog_during_abandoned_export_does_not_abort(self):
        tab = self._prepare_share_with_identity()
        widget = tab.get_mode().mode_settings_widget
        started = threading.Event()
        release = threading.Event()

        def blocked(identity, passphrase):
            started.set()
            release.wait(timeout=30)
            return "{}"

        try:
            with mock.patch.object(
                identity_backup_dialog, "encrypt_identity", blocked
            ):
                with mock.patch.object(
                    QtWidgets.QDialog,
                    "exec",
                    return_value=QtWidgets.QDialog.DialogCode.Accepted,
                ):
                    widget.export_identity_backup_button.click()
                dialog = widget.identity_backup_dialog
                self._dialog = dialog
                self._wait_until(started.is_set)
                with mock.patch.object(
                    identity_backup_dialog, "_ENCRYPT_THREAD_WAIT_MS", 80
                ):
                    tab.cleanup()
                if dialog._accepting_results:
                    raise AssertionError("quit re-armed the export worker")
                keeper = identity_backup_dialog._abandoned_thread_keeper
                if keeper is None or not any(
                    thread.isRunning() for thread in keeper._threads
                ):
                    raise AssertionError("running worker was not retained")
                widget.identity_backup_dialog = None
                dialog.deleteLater()
                self._dialog = None
                del dialog
                gc.collect()
                for _ in range(10):
                    self.gui.qtapp.processEvents()
                if not any(thread.isRunning() for thread in list(keeper._threads)):
                    raise AssertionError("retained worker stopped before release")
                release.set()
                self._wait_until(
                    lambda: not any(
                        thread.isRunning() for thread in list(keeper._threads)
                    )
                )
        finally:
            release.set()

    def test_user_close_while_export_runs_refuses_then_accepts_result(self):
        tab = self._prepare_share_with_identity()
        widget = tab.get_mode().mode_settings_widget
        started = threading.Event()
        release = threading.Event()

        def blocked(identity, passphrase):
            started.set()
            release.wait(timeout=30)
            return "{}"

        try:
            with mock.patch.object(
                identity_backup_dialog, "encrypt_identity", blocked
            ):
                with mock.patch.object(
                    QtWidgets.QDialog,
                    "exec",
                    return_value=QtWidgets.QDialog.DialogCode.Accepted,
                ):
                    widget.export_identity_backup_button.click()
                dialog = widget.identity_backup_dialog
                self._dialog = dialog
                self._wait_until(started.is_set)
                dialog.show()
                self.gui.qtapp.processEvents()
                with mock.patch.object(
                    identity_backup_dialog, "_ENCRYPT_THREAD_WAIT_MS", 80
                ):
                    closed = dialog.close()
                if closed:
                    raise AssertionError("user close accepted while the worker ran")
                if not dialog.isVisible():
                    raise AssertionError("user close hid the dialog")
                if not dialog._accepting_results:
                    raise AssertionError("user close left the worker disconnected")
                release.set()
                self._wait_until(lambda: dialog.pending_bytes is not None)
                if dialog.envelope is None:
                    raise AssertionError("user close did not accept the result")
        finally:
            release.set()

    def test_reject_clears_export_identity_and_passphrase(self):
        def fast(identity, passphrase):
            return "{}"

        with mock.patch.object(identity_backup_dialog, "encrypt_identity", fast):
            dialog = identity_backup_dialog.ExportIdentityBackupDialog(
                self.gui.common,
                _fixture_identity(),
                "alpha-bravo-charlie-delta-echo-foxtrot",
            )
            self._dialog = dialog
            self._wait_until(
                lambda: (not dialog.is_busy) and dialog.passphrase_label.text() != ""
            )
        dialog.reject()
        if (
            dialog.identity is not None
            or dialog.passphrase is not None
            or dialog._next_passphrase is not None
        ):
            raise AssertionError("export dialog kept identity or passphrase")
        if dialog.passphrase_label.text() != "":
            raise AssertionError("passphrase label was not cleared")

    def _assert_clipboard_empty(self, clipboard):
        """Fail without echoing clipboard text. It may be the recovery phrase."""
        if clipboard.text() != "":
            raise AssertionError("clipboard was not empty")
        try:
            supports_selection = clipboard.supportsSelection()
        except Exception:
            supports_selection = False
        if supports_selection:
            selection = clipboard.text(QtGui.QClipboard.Mode.Selection)
            if selection != "":
                raise AssertionError("selection clipboard was not empty")

    def test_copied_passphrase_is_cleared_on_close_and_regenerate(self):
        """
        Copy must not leave the recovery phrase on the clipboard after the
        dialog closes, is destroyed, or regenerates. Unrelated clipboard
        text, including the envelope, stays put.
        """

        def fast(identity, passphrase):
            return "{}"

        clipboard = QtWidgets.QApplication.clipboard()
        clipboard.clear()
        self.gui.qtapp.processEvents()
        with mock.patch.object(identity_backup_dialog, "encrypt_identity", fast):
            dialog = identity_backup_dialog.ExportIdentityBackupDialog(
                self.gui.common,
                _fixture_identity(),
                "alpha-bravo-charlie-delta-echo-foxtrot",
            )
            self._dialog = dialog
            self._wait_until(
                lambda: (not dialog.is_busy) and dialog.passphrase_label.text() != ""
            )
            dialog.copy_passphrase_button.click()
            if clipboard.text() != dialog.passphrase:
                raise AssertionError("copy did not place the recovery phrase")
            dialog.reject()
            self._assert_clipboard_empty(clipboard)
            if (
                dialog.passphrase is not None
                or dialog.passphrase_label.text() != ""
            ):
                raise AssertionError("reject left the recovery phrase in the dialog")

            dialog = identity_backup_dialog.ExportIdentityBackupDialog(
                self.gui.common,
                _fixture_identity(),
                "alpha-bravo-charlie-delta-echo-foxtrot",
            )
            self._dialog = dialog
            self._wait_until(
                lambda: (not dialog.is_busy) and dialog.passphrase_label.text() != ""
            )
            dialog.copy_passphrase_button.click()
            previous = dialog.passphrase
            generation = dialog.generation
            dialog.regenerate_button.click()
            if clipboard.text() == previous or clipboard.text() != "":
                raise AssertionError(
                    "regenerate left the previous recovery phrase on the clipboard"
                )
            self._wait_until(
                lambda: dialog.generation > generation and not dialog.is_busy
            )
            if clipboard.text() == previous or clipboard.text() != "":
                raise AssertionError(
                    "clipboard held the previous recovery phrase after regenerate"
                )
            if dialog.passphrase == previous:
                raise AssertionError("regenerate did not replace the recovery phrase")
            dialog.reject()

            dialog = identity_backup_dialog.ExportIdentityBackupDialog(
                self.gui.common,
                _fixture_identity(),
                "alpha-bravo-charlie-delta-echo-foxtrot",
            )
            self._dialog = dialog
            self._wait_until(
                lambda: (not dialog.is_busy) and dialog.passphrase_label.text() != ""
            )
            clipboard.setText("unrelated-clipboard-text")
            dialog.reject()
            if clipboard.text() != "unrelated-clipboard-text":
                raise AssertionError("unrelated clipboard text was replaced")

            dialog = identity_backup_dialog.ExportIdentityBackupDialog(
                self.gui.common,
                _fixture_identity(),
                "alpha-bravo-charlie-delta-echo-foxtrot",
            )
            self._dialog = dialog
            self._wait_until(
                lambda: (not dialog.is_busy) and dialog.passphrase_label.text() != ""
            )
            dialog.copy_passphrase_button.click()
            dialog.copy_encrypted_button.click()
            if clipboard.text() != dialog.qr_text:
                raise AssertionError("copy encrypted text did not update the clipboard")
            dialog.close_button.click()
            if clipboard.text() != "{}":
                raise AssertionError("close cleared clipboard text that was not the phrase")

            dialog = identity_backup_dialog.ExportIdentityBackupDialog(
                self.gui.common,
                _fixture_identity(),
                "alpha-bravo-charlie-delta-echo-foxtrot",
            )
            self._dialog = dialog
            self._wait_until(
                lambda: (not dialog.is_busy) and dialog.passphrase_label.text() != ""
            )
            dialog.copy_passphrase_button.click()
            phrase = dialog.passphrase

            class _ClipboardDouble(object):
                def __init__(self):
                    self.values = {
                        QtGui.QClipboard.Mode.Clipboard: "unrelated-clipboard-text",
                        QtGui.QClipboard.Mode.Selection: phrase,
                    }

                def supportsSelection(self):
                    return True

                def text(self, mode=QtGui.QClipboard.Mode.Clipboard):
                    return self.values.get(mode, "")

                def clear(self, mode=QtGui.QClipboard.Mode.Clipboard):
                    self.values[mode] = ""

            double = _ClipboardDouble()
            with mock.patch.object(
                QtWidgets.QApplication, "clipboard", return_value=double
            ):
                dialog.deleteLater()
                QtCore.QCoreApplication.sendPostedEvents(
                    None, QtCore.QEvent.Type.DeferredDelete
                )
            if isValid(dialog):
                raise AssertionError("dialog was not destroyed")
            if double.text(QtGui.QClipboard.Mode.Selection) != "":
                raise AssertionError(
                    "destroy left the recovery phrase on the selection clipboard"
                )
            if double.text() != "unrelated-clipboard-text":
                raise AssertionError(
                    "destroy cleared clipboard text that was not the phrase"
                )
            self._dialog = None
            clipboard.clear()
            self.gui.qtapp.processEvents()

    def test_save_qr_image_is_created_mode_0600(self):
        """The QR PNG is mode 0600 from creation, including under umask 0."""

        def fast(identity, passphrase):
            return "{}"

        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "qr.png")
        old_umask = os.umask(0)
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o666)
            os.close(descriptor)
            with mock.patch.object(identity_backup_dialog, "encrypt_identity", fast):
                dialog = identity_backup_dialog.ExportIdentityBackupDialog(
                    self.gui.common,
                    _fixture_identity(),
                    "alpha-bravo-charlie-delta-echo-foxtrot",
                )
                self._dialog = dialog
                self._wait_until(
                    lambda: (not dialog.is_busy)
                    and dialog.pending_bytes is not None
                    and dialog._qr_source is not None
                )
                chmod_other_bits = []
                real_chmod = os.chmod

                def spy_chmod(filename, mode):
                    if os.path.abspath(filename) == os.path.abspath(path):
                        if os.path.lexists(filename):
                            chmod_other_bits.append(
                                os.lstat(filename).st_mode & 0o077
                            )
                    return real_chmod(filename, mode)

                with mock.patch.object(os, "chmod", spy_chmod):
                    with mock.patch.object(
                        QtWidgets.QFileDialog,
                        "getSaveFileName",
                        return_value=(path, "png"),
                    ):
                        dialog.save_qr_button.click()
            mode = stat.S_IMODE(os.lstat(path).st_mode)
            if mode != 0o600:
                raise AssertionError(
                    "QR png mode was {0}, expected 0600".format(oct(mode))
                )
            for bits in chmod_other_bits:
                if bits != 0:
                    raise AssertionError(
                        "QR png was group or world readable before chmod"
                    )
            buffer = QtCore.QBuffer()
            buffer.open(QtCore.QIODevice.OpenModeFlag.WriteOnly)
            if not dialog._qr_source.save(buffer, "PNG"):
                raise AssertionError("pixmap PNG encode failed")
            with open(path, "rb") as handle:
                file_bytes = handle.read()
            if file_bytes != bytes(buffer.data()):
                raise AssertionError("QR png bytes differed from the pixmap")
            if not file_bytes.startswith(b"\x89PNG"):
                raise AssertionError("saved QR image was not a PNG")
            names = sorted(os.listdir(directory))
            if names != ["qr.png"]:
                raise AssertionError("QR save left a temporary file behind")
        finally:
            os.umask(old_umask)
            for name in os.listdir(directory):
                try:
                    os.remove(os.path.join(directory, name))
                except OSError:
                    pass
            os.rmdir(directory)

    def test_save_qr_image_writes_png_on_windows_without_fchmod(self):
        """
        Windows has no os.fchmod and st_mode can report 0666.

        Save QR still writes the PNG through the temp file and os.replace.
        """

        def fast(identity, passphrase):
            return "{}"

        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "qr.png")
        module_os = identity_backup_dialog.os
        real_name = module_os.name
        real_fstat = module_os.fstat
        real_fchmod = getattr(module_os, "fchmod", None)
        removed_fchmod = False

        def windows_fstat(fd):
            info = real_fstat(fd)
            values = list(info)
            values[0] = (values[0] & ~0o777) | 0o666
            return os.stat_result(values)

        try:
            with mock.patch.object(identity_backup_dialog, "encrypt_identity", fast):
                dialog = identity_backup_dialog.ExportIdentityBackupDialog(
                    self.gui.common,
                    _fixture_identity(),
                    "alpha-bravo-charlie-delta-echo-foxtrot",
                )
                self._dialog = dialog
                self._wait_until(
                    lambda: (not dialog.is_busy)
                    and dialog.pending_bytes is not None
                    and dialog._qr_source is not None
                )
                module_os.name = "nt"
                if hasattr(module_os, "fchmod"):
                    del module_os.fchmod
                    removed_fchmod = True
                module_os.fstat = windows_fstat
                with mock.patch.object(
                    QtWidgets.QMessageBox,
                    "exec",
                    return_value=QtWidgets.QMessageBox.StandardButton.Ok,
                ):
                    with mock.patch.object(
                        QtWidgets.QFileDialog,
                        "getSaveFileName",
                        return_value=(path, "png"),
                    ):
                        dialog.save_qr_button.click()
            if not os.path.isfile(path):
                raise AssertionError("Windows QR save did not write a file")
            with open(path, "rb") as handle:
                file_bytes = handle.read()
            if not file_bytes.startswith(b"\x89PNG"):
                raise AssertionError("Windows QR save was not a PNG")
            buffer = QtCore.QBuffer()
            buffer.open(QtCore.QIODevice.OpenModeFlag.WriteOnly)
            if not dialog._qr_source.save(buffer, "PNG"):
                raise AssertionError("pixmap PNG encode failed")
            if file_bytes != bytes(buffer.data()):
                raise AssertionError("Windows QR png bytes differed from the pixmap")
            names = sorted(os.listdir(directory))
            if names != ["qr.png"]:
                raise AssertionError("Windows QR save left a temporary file behind")
        finally:
            module_os.name = real_name
            module_os.fstat = real_fstat
            if removed_fchmod and real_fchmod is not None:
                module_os.fchmod = real_fchmod
            for name in os.listdir(directory):
                try:
                    os.remove(os.path.join(directory, name))
                except OSError:
                    pass
            os.rmdir(directory)

    def test_export_dialog_presentation(self):
        """Titles, sections, actions, collapsed Advanced, and crisp QR."""
        envelope = (
            '{"ct":"YQ==","kdf":"argon2id","m":67108864,"n":"YQ==",'
            '"p":1,"salt":"YQ==","t":2,"v":1}'
        )
        modes = []
        real_scaled = QtGui.QPixmap.scaled

        def spy_scaled(pixmap, *args, **kwargs):
            if len(args) >= 4:
                modes.append(args[3])
            return real_scaled(pixmap, *args, **kwargs)

        def fast(identity, passphrase):
            return envelope

        with mock.patch.object(QtGui.QPixmap, "scaled", spy_scaled):
            with mock.patch.object(identity_backup_dialog, "encrypt_identity", fast):
                dialog = identity_backup_dialog.ExportIdentityBackupDialog(
                    self.gui.common,
                    _fixture_identity(),
                    "alpha-bravo-charlie-delta-echo-foxtrot",
                )
                self._dialog = dialog
                self._wait_until(
                    lambda: (not dialog.is_busy) and dialog.pending_bytes is not None
                )
        dialog.show()
        self.gui.qtapp.processEvents()
        self.assertEqual(
            dialog.windowTitle(), strings._("gui_identity_backup_dialog_title")
        )
        self.assertEqual(dialog.windowTitle(), "Back up onion service")
        self.assertTrue("files" in dialog.instructions.text().lower())
        self.assertTrue("nothing is uploaded" in dialog.local_encryption_label.text().lower())
        self.assertEqual(dialog.recovery_group.title(), "Recovery phrase")
        self.assertEqual(dialog.encrypted_group.title(), "Encrypted backup")
        self.assertTrue(
            "cannot be recovered later" in dialog.passphrase_warning.text().lower()
        )
        self.assertFalse(dialog.advanced_widget.isVisible())
        self.assertEqual(dialog.advanced_toggle.text(), "Advanced")
        self.assertTrue(dialog.save_button.isEnabled())
        self.assertTrue(dialog.save_button.isDefault())
        self.assertTrue(dialog.save_qr_button.isEnabled())
        self.assertTrue(dialog.copy_encrypted_button.isEnabled())
        self.assertTrue(dialog.copy_passphrase_button.isEnabled())
        self.assertTrue(dialog.regenerate_button.isEnabled())
        self.assertFalse(dialog.regenerate_button.isDefault())
        self.assertFalse(dialog.save_qr_button.isDefault())
        self.assertFalse(dialog.copy_encrypted_button.isDefault())
        self.assertFalse(dialog.qr_label.hasScaledContents())
        self.assertTrue(
            QtCore.Qt.TransformationMode.FastTransformation in modes
        )
        self.assertFalse(
            QtCore.Qt.TransformationMode.SmoothTransformation in modes
        )
        image = dialog.qr_label.pixmap().toImage()
        corner = image.pixelColor(0, 0)
        self.assertEqual(corner.red(), 255)
        self.assertEqual(corner.green(), 255)
        self.assertEqual(corner.blue(), 255)
        black = False
        step_x = max(1, image.width() // 16)
        step_y = max(1, image.height() // 16)
        for y in range(0, image.height(), step_y):
            for x in range(0, image.width(), step_x):
                color = image.pixelColor(x, y)
                if color.red() < 16 and color.green() < 16 and color.blue() < 16:
                    black = True
                    break
            if black:
                break
        self.assertTrue(black)
        self.assertTrue(dialog.qr_text.encode("utf-8") == dialog.pending_bytes)
        dialog.advanced_toggle.click()
        self.gui.qtapp.processEvents()
        self.assertTrue(dialog.advanced_widget.isVisible())
        shown = dialog.advanced_text.toPlainText()
        self.assertTrue(dialog.qr_text in shown)
        self.assertTrue("argon2id" in shown)
        clipboard = QtWidgets.QApplication.clipboard()
        dialog.copy_passphrase_button.click()
        self.assertTrue(clipboard.text() == dialog.passphrase)
        dialog.copy_encrypted_button.click()
        self.assertTrue(clipboard.text() == dialog.qr_text)
        clipboard.clear()

    def test_quit_cleanup_does_not_block_on_export_worker(self):
        tab = self._prepare_share_with_identity()
        widget = tab.get_mode().mode_settings_widget
        started = threading.Event()
        release = threading.Event()

        def blocked(identity, passphrase):
            started.set()
            release.wait(timeout=30)
            return "{}"

        try:
            with mock.patch.object(
                identity_backup_dialog, "encrypt_identity", blocked
            ):
                with mock.patch.object(
                    QtWidgets.QDialog,
                    "exec",
                    return_value=QtWidgets.QDialog.DialogCode.Accepted,
                ):
                    widget.export_identity_backup_button.click()
                dialog = widget.identity_backup_dialog
                self._dialog = dialog
                self._wait_until(started.is_set)
                self.assertTrue(dialog.encrypt_thread.isRunning())
                started_at = time.monotonic()
                tab.cleanup()
                elapsed = time.monotonic() - started_at
                if elapsed >= 2.0:
                    raise AssertionError("quit cleanup waited on the export worker")
                if dialog._accepting_results:
                    raise AssertionError("quit re-armed the export worker")
                keeper = identity_backup_dialog._abandoned_thread_keeper
                running = []
                if keeper is not None:
                    running = [
                        thread
                        for thread in list(keeper._threads)
                        if thread.isRunning()
                    ]
                if not running:
                    raise AssertionError("running worker was not retained")
                release.set()
                self._wait_until(lambda: not any(thread.isRunning() for thread in running))
        finally:
            release.set()

    def _click_save_archive(self, widget, label):
        messages = []

        def exec_box(box, *args, **kwargs):
            messages.append(box.text())
            return QtWidgets.QMessageBox.StandardButton.Ok

        with mock.patch.object(QtWidgets.QMessageBox, "exec", exec_box):
            with mock.patch.object(
                QtWidgets.QInputDialog, "getText", return_value=(label, True)
            ):
                widget.save_to_saved_services_button.click()
        return messages

    def test_post_commit_chmod_reports_saved_not_failure(self):
        identity = _fixture_identity()
        tab = self.new_share_tab()
        _inject_identity(tab.settings, identity)
        widget = tab.get_mode().mode_settings_widget
        widget.update_ui()
        record_path = os.path.join(
            self.gui.common.build_data_dir(),
            "saved_services",
            identity["service_id"] + ".json",
        )
        archive = SavedServices(self.gui.common, self.gui.common.settings)
        if os.path.isfile(record_path) or identity["service_id"] in list(
            self.gui.common.settings.get("saved_services")
        ):
            archive.delete(identity["service_id"])
        real_chmod = os.chmod

        def fail_json_chmod(path, mode):
            if str(path).endswith(".json"):
                raise OSError(errno.EPERM, "chmod-failed")
            return real_chmod(path, mode)

        def fail_fsync(_directory):
            raise OSError(errno.EIO, "fsync-failed")

        log_messages, original_log = self._capture_common_log()
        try:
            with mock.patch.object(saved_services_module.os, "chmod", fail_json_chmod):
                with mock.patch.object(
                    saved_services_module, "_fsync_directory", fail_fsync
                ):
                    messages = self._click_save_archive(widget, "kept-label")
        finally:
            self._restore_common_log(original_log)

        saved = strings._("gui_identity_backup_archive_saved")
        warning = strings._("gui_identity_backup_archive_saved_warning")
        error = strings._("gui_identity_backup_archive_error")
        self.assertTrue(saved in messages)
        self.assertTrue(warning in messages)
        self.assertFalse(error in messages)
        self.assertTrue(os.path.isfile(record_path))
        archive_dir = os.path.dirname(record_path)
        self.assertFalse(
            any(name.startswith(".tmp-") for name in os.listdir(archive_dir))
        )
        self.gui.common.settings.load()
        self.assertTrue(
            identity["service_id"] in self.gui.common.settings.get("saved_services")
        )
        blobs = self._log_blobs(log_messages)
        blobs.append("\n".join(messages))
        for blob in blobs:
            self.assertFalse("chmod-failed" in str(blob))
            self.assertFalse("fsync-failed" in str(blob))
        try:
            SavedServices(self.gui.common, self.gui.common.settings).delete(
                identity["service_id"]
            )
        except Exception:
            pass

    def test_settings_save_failure_after_commit_reports_saved(self):
        identity = _fixture_identity()
        tab = self.new_share_tab()
        _inject_identity(tab.settings, identity)
        widget = tab.get_mode().mode_settings_widget
        widget.update_ui()
        record_path = os.path.join(
            self.gui.common.build_data_dir(),
            "saved_services",
            identity["service_id"] + ".json",
        )
        archive = SavedServices(self.gui.common, self.gui.common.settings)
        if os.path.isfile(record_path) or identity["service_id"] in list(
            self.gui.common.settings.get("saved_services")
        ):
            archive.delete(identity["service_id"])
        calls = {"n": 0}
        real_save = Settings.save

        def flaky(settings):
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError(errno.EIO, "settings-save-eio")
            return real_save(settings)

        log_messages, original_log = self._capture_common_log()
        try:
            with mock.patch.object(Settings, "save", flaky):
                messages = self._click_save_archive(widget, "kept-label")
        finally:
            self._restore_common_log(original_log)

        saved = strings._("gui_identity_backup_archive_saved")
        error = strings._("gui_identity_backup_archive_error")
        self.assertTrue(saved in messages)
        self.assertFalse(error in messages)
        self.assertTrue(calls["n"] >= 2)
        self.assertTrue(os.path.isfile(record_path))
        fresh = Settings(self.gui.common)
        fresh.load()
        self.assertTrue(identity["service_id"] in fresh.get("saved_services"))
        blobs = self._log_blobs(log_messages)
        blobs.append("\n".join(messages))
        for blob in blobs:
            self.assertFalse("settings-save-eio" in str(blob))
        try:
            SavedServices(self.gui.common, self.gui.common.settings).delete(
                identity["service_id"]
            )
        except Exception:
            pass
