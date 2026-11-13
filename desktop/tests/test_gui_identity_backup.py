# -*- coding: utf-8 -*-
"""
GUI tests for identity backup export.

Assertions that compare secrets use assertTrue/assertFalse so a failure does
not print passphrases, private keys, or decrypted identities.
"""

import inspect
import json
import logging
import os
import tempfile
import time
from unittest import mock

import pytest
from PySide6 import QtCore, QtGui, QtWidgets

from onionshare_cli.identity_backup import IdentityBackupError, decrypt_identity

from onionshare import strings
from onionshare.tab.server_status import ServerStatus
from onionshare.widgets import QRCodeDialog, qr_code_pixmap

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
        if dialog is not None:
            thread = dialog.encrypt_thread
            if thread is not None and thread.isRunning():
                thread.wait(180000)
            dialog.close()
            self._dialog = None
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
