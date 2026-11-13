# -*- coding: utf-8 -*-
"""
GUI tests for identity backup import.

File and pasted-text import both decrypt off the GUI thread, write a Saved
Services record only after the plaintext-archive disclosure, and open the
tab through TabWidget.open_saved_service. A failed import leaves no tab,
no archive record, and no settings change. Assertions that compare secrets
use assertTrue/assertFalse so a failure does not print them.
"""

import ast
import base64
import hashlib
import inspect
import json
import os
import tempfile
import threading
import time
from unittest import mock

import nacl.bindings
import nacl.public
import nacl.signing
import pytest
from PySide6 import QtCore, QtTest, QtWidgets

from onionshare_cli.identity_backup import IdentityBackupError, encrypt_identity
from onionshare_cli import saved_services as saved_services_module
from onionshare_cli.saved_services import SavedServices

from onionshare import identity_import_dialog, strings
from onionshare.identity_import_dialog import read_envelope_file
from onionshare.settings_parent_tab import SettingsParentTab
from onionshare.tab.mode import Mode
from onionshare.tab.server_status import ServerStatus
from onionshare.tab.tab import Tab
from onionshare.tab_widget import TabWidget
from onionshare.widgets import Alert

from .gui_base_test import GuiBaseTest


# Outer spaces are part of what the line edit holds. decrypt_identity strips
# them. "t-shirt" is one wordlist token, so the field must not be split.
PASSPHRASE_STRIPPED = "alpha-t-shirt-bravo-charlie-delta-echo"
PASSPHRASE_TYPED = "  " + PASSPHRASE_STRIPPED + "  "
GENERIC = "wrong passphrase or damaged backup"
_MODES = ("share", "receive", "website", "chat")
_FORBIDDEN = ("QtMultimedia", "cv2", "pyzbar", "zbar", "QCamera")
_FORBIDDEN_MODULES = (
    "cv2",
    "pyzbar",
    "zbar",
    "PySide6.QtMultimedia",
    "PySide6.QtMultimediaWidgets",
)


def _b32_key(raw):
    encoded = base64.b32encode(raw)
    if not encoded.endswith(b"===="):
        raise AssertionError("client auth key was not canonical base32")
    return encoded[:-4].decode("ascii")


def _onion_address(public_key):
    checksum = hashlib.sha3_256(b".onion checksum" + public_key + b"\x03").digest()[:2]
    encoded = base64.b32encode(public_key + checksum + b"\x03").decode("ascii")
    return encoded.lower()


def _tor_ed25519():
    """Disposable Tor ED25519-V3 blob and its service id. Not a real onion."""
    signing_key = nacl.signing.SigningKey.generate()
    expanded = bytearray(hashlib.sha512(bytes(signing_key)).digest())
    expanded[0] &= 248
    expanded[31] &= 127
    expanded[31] |= 64
    scalar = bytes(expanded[:32])
    public = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(scalar)
    if public != bytes(signing_key.verify_key):
        raise AssertionError("generated ed25519 public key did not match")
    private_key = base64.b64encode(bytes(expanded)).decode("ascii")
    return private_key, _onion_address(public)


def _identity(mode, public=False, client_auth=True):
    private_key, service_id = _tor_ed25519()
    if client_auth:
        private = nacl.public.PrivateKey.generate()
        priv = _b32_key(bytes(private))
        pub = _b32_key(bytes(private.public_key))
    else:
        priv = pub = None
    return {
        "mode": mode,
        "service_id": service_id,
        "private_key": private_key,
        "client_auth_priv_key": priv,
        "client_auth_pub_key": pub,
        "public": public,
    }


def _secrets_of(identity, envelope, passphrase):
    values = [passphrase, envelope, identity["private_key"]]
    for key in ("client_auth_priv_key", "client_auth_pub_key"):
        if identity[key]:
            values.append(identity[key])
    return values


def _imported_names(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.append(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return names


@pytest.fixture(scope="module")
def envelopes():
    """Fixture envelopes from encrypt_identity. Built once; tests only decrypt."""
    built = {}
    for mode in _MODES:
        identity = _identity(mode, public=False, client_auth=True)
        built[mode] = {
            "identity": identity,
            "envelope": encrypt_identity(identity, PASSPHRASE_STRIPPED),
        }
    public_identity = _identity("share", public=True, client_auth=False)
    built["public"] = {
        "identity": public_identity,
        "envelope": encrypt_identity(public_identity, PASSPHRASE_STRIPPED),
    }
    return built


class IdentityImportCase(GuiBaseTest):
    """
    Window lifecycle is GuiBaseTest's. Pytest functions below own the cases.
    This class has no test methods, because a unittest method would not
    expand pytest.mark.parametrize.
    """

    def setUp(self):
        self.gui.common.gui.onion.connected_to_tor = False
        self._log_messages = []
        self._original_log = self.gui.common.log

        def wrapped_log(module, func, msg=None):
            self._log_messages.append((module, func, msg))
            return self._original_log(module, func, msg)

        self.gui.common.log = wrapped_log
        self._temp_paths = []
        self._temp_dirs = []
        self._timed_out = False
        self._quiesce_tabs()
        self.gui.tabs.close_settings_tab()
        self._close_feature_tabs()
        self._leave_one_chooser()
        self._clear_archive()
        self.gui.qtapp.processEvents()

    def tearDown(self):
        self.gui.common.gui.onion.connected_to_tor = False
        original = getattr(self, "_original_log", None)
        if original is not None:
            self.gui.common.log = original
        dialog = getattr(self, "_import_dialog", None)
        self._import_dialog = None
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
        for path in getattr(self, "_temp_paths", []):
            try:
                os.chmod(path, 0o644)
            except OSError:
                pass
            try:
                os.remove(path)
            except OSError:
                pass
        for path in getattr(self, "_temp_dirs", []):
            try:
                os.rmdir(path)
            except OSError:
                pass

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
            except Exception:
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

    def _settings_tab(self):
        for tab in self.gui.tabs.tabs.values():
            if type(tab) is SettingsParentTab:
                return tab.widget(0)
        return None

    def _open_settings(self):
        self.gui.tabs.open_settings_tab()
        self.gui.qtapp.processEvents()
        settings = self._settings_tab()
        if settings is None:
            self.fail("settings tab did not open")
        return settings

    def _close_settings_tab(self):
        tabs = self.gui.tabs
        for index in range(tabs.count()):
            if type(tabs.widget(index)) is SettingsParentTab:
                button = tabs.tabBar().tabButton(
                    index, QtWidgets.QTabBar.ButtonPosition.RightSide
                )
                button.click()
                return
        self.fail("settings tab was not open")

    def _wait_until(self, predicate, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            self.gui.qtapp.processEvents()
            if predicate():
                return
            time.sleep(0.01)
        self.fail("timed out")

    def _data_dir(self):
        return self.gui.common.build_data_dir()

    def _record_path(self, service_id):
        return os.path.join(self._data_dir(), "saved_services", service_id + ".json")

    def _settings_path(self):
        return self.gui.common.settings.filename

    def _read_bytes(self, path):
        if not os.path.isfile(path):
            return None
        with open(path, "rb") as handle:
            return handle.read()

    def _tree(self, path):
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

    def _capture(self):
        data = self._data_dir()
        return {
            "settings": self._read_bytes(self._settings_path()),
            "persistent_tabs": list(self.gui.common.settings.get("persistent_tabs")),
            "saved_services": list(self.gui.common.settings.get("saved_services")),
            "persistent": self._tree(os.path.join(data, "persistent")),
            "archive": self._tree(os.path.join(data, "saved_services")),
            "service_ids": self._open_service_ids(),
        }

    def _assert_unchanged(self, before):
        after = self._capture()
        self.assertTrue(after["settings"] == before["settings"])
        self.assertEqual(after["persistent_tabs"], before["persistent_tabs"])
        self.assertEqual(after["saved_services"], before["saved_services"])
        self.assertTrue(after["persistent"] == before["persistent"])
        self.assertTrue(after["archive"] == before["archive"])
        self.assertEqual(after["service_ids"], before["service_ids"])

    def _open_service_ids(self):
        found = []
        for tab in self.gui.tabs.tabs.values():
            if not isinstance(tab, Tab):
                continue
            settings = getattr(tab, "settings", None)
            if settings is None:
                continue
            try:
                found.append(settings.get("general", "service_id"))
            except Exception:
                continue
        return found

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

    def _write_temp(self, payload):
        descriptor, path = tempfile.mkstemp(prefix="os-import-", suffix=".json")
        try:
            os.write(descriptor, payload)
        finally:
            os.close(descriptor)
        self._temp_paths.append(path)
        return path

    def _assert_secrets_absent(self, secrets):
        captured = self.capsys.readouterr() if getattr(self, "capsys", None) else None
        blobs = []
        caplog = getattr(self, "caplog", None)
        if caplog is not None:
            blobs.append(caplog.text)
        if captured is not None:
            blobs.append(captured.out)
            blobs.append(captured.err)
        for module, func, msg in self._log_messages:
            blobs.append(module)
            blobs.append(func)
            if msg is not None:
                blobs.append(msg)
        for blob in blobs:
            text = "" if blob is None else str(blob)
            for secret in secrets:
                if secret:
                    self.assertFalse(secret in text)

    def _drive(self, prepare, close_when_idle=True, deadline_s=45):
        """Open Saved Services, then Import backup, through the real buttons."""
        settings = self._open_settings()
        state = {"alive": True, "timed_out": False, "dialog": None}
        deadline = time.time() + deadline_s

        def still_running(dialog):
            thread = dialog.decrypt_thread
            if thread is None:
                return False
            try:
                return thread.isRunning()
            except RuntimeError:
                return False

        def finish(dialog):
            if not state["alive"]:
                return
            self.gui.qtapp.processEvents()
            if time.time() > deadline:
                state["timed_out"] = True
                state["alive"] = False
                try:
                    dialog.close()
                except RuntimeError:
                    pass
                return
            if dialog.is_busy or still_running(dialog):
                QtCore.QTimer.singleShot(20, lambda: finish(dialog))
                return
            dialog.close_button.click()

        def when_import_visible():
            if not state["alive"]:
                return
            manager = getattr(settings, "saved_services_dialog", None)
            dialog = None if manager is None else manager.import_dialog
            if (
                manager is None
                or not manager.isVisible()
                or dialog is None
                or not dialog.isVisible()
            ):
                if time.time() > deadline:
                    state["timed_out"] = True
                    state["alive"] = False
                    if manager is not None:
                        try:
                            manager.close()
                        except RuntimeError:
                            pass
                    return
                QtCore.QTimer.singleShot(15, when_import_visible)
                return
            state["dialog"] = dialog
            prepare(dialog)
            if close_when_idle:
                QtCore.QTimer.singleShot(20, lambda: finish(dialog))

        def open_import():
            if not state["alive"]:
                return
            manager = getattr(settings, "saved_services_dialog", None)
            if manager is None or not manager.isVisible():
                if time.time() > deadline:
                    state["timed_out"] = True
                    state["alive"] = False
                    return
                QtCore.QTimer.singleShot(15, open_import)
                return
            QtCore.QTimer.singleShot(15, when_import_visible)
            manager.import_button.click()
            if state["alive"] and manager.isVisible():
                manager.close_button.click()

        QtCore.QTimer.singleShot(15, open_import)
        settings.saved_services_button.click()
        state["alive"] = False
        self._timed_out = state["timed_out"]
        self._import_dialog = state["dialog"]
        self.gui.qtapp.processEvents()
        return state["dialog"]

    def _mode_label(self, mode):
        return strings._(
            {
                "share": "gui_tab_name_share",
                "receive": "gui_tab_name_receive",
                "website": "gui_tab_name_website",
                "chat": "gui_tab_name_chat",
            }[mode]
        )

    def run_import(self, envelopes, mode, source):
        """Import one mode from a file or from pasted text. The tab stays stopped."""
        signature = inspect.signature(TabWidget.open_saved_service)
        self.assertEqual(list(signature.parameters), ["self", "identity", "label"])
        self.assertTrue(signature.parameters["label"].default is None)
        self.assertEqual(
            strings._("gui_saved_services_import_button"), "Import backup…"
        )
        self.assertEqual(strings._("gui_identity_import_error"), GENERIC)

        packed = envelopes[mode]
        identity = packed["identity"]
        envelope = packed["envelope"]
        label = "label-" + mode
        record_path = self._record_path(identity["service_id"])
        file_path = None
        if source == "file":
            file_path = self._write_temp(envelope.encode("utf-8"))

        disclosure = strings._("gui_identity_backup_archive_disclosure")
        self.assertTrue("unencrypted" in disclosure)
        self.assertTrue("this computer" in disclosure)
        messages = []
        defaults = []
        existed_at_disclosure = []
        existed_at_label = []
        calls = []
        start_calls = []
        decrypt_calls = []
        files_at_open = []
        captured = {}

        def exec_box(box, *args, **kwargs):
            text = box.text()
            messages.append(text)
            if text == disclosure:
                existed_at_disclosure.append(os.path.exists(record_path))
            return QtWidgets.QMessageBox.StandardButton.Ok

        def get_text(*args, **kwargs):
            if "text" in kwargs:
                defaults.append(kwargs["text"])
            elif len(args) > 4:
                defaults.append(args[4])
            existed_at_label.append(os.path.exists(record_path))
            return (label, True)

        def get_open(*args, **kwargs):
            return (file_path or "", "")

        real_open = TabWidget.open_saved_service
        real_decrypt = identity_import_dialog.decrypt_identity

        def spy(self, opened_identity, opened_label=None):
            files_at_open.append(os.path.isfile(record_path))
            calls.append((opened_identity, opened_label))
            return real_open(self, opened_identity, opened_label)

        def wrapped_decrypt(text, passphrase):
            decrypt_calls.append(
                (threading.get_ident(), passphrase, QtCore.QThread.currentThread())
            )
            return real_decrypt(text, passphrase)

        def status_start(self, *args, **kwargs):
            start_calls.append("status")

        def mode_start(self, *args, **kwargs):
            start_calls.append("mode")

        def prepare(dialog):
            self.assertEqual(len(dialog.findChildren(QtWidgets.QLineEdit)), 1)
            self.assertTrue(isinstance(dialog.passphrase_edit, QtWidgets.QLineEdit))
            dialog.passphrase_edit.setText(PASSPHRASE_TYPED)
            captured["widget_passphrase"] = dialog.passphrase_edit.text()
            captured["before"] = self._capture()
            if source == "file":
                dialog.envelope_edit.setPlainText("not-the-envelope")
                dialog.file_radio.setChecked(True)
                self.assertTrue(dialog.choose_file_button.isEnabled())
                dialog.choose_file_button.click()
            else:
                dialog.paste_radio.setChecked(True)
                dialog.envelope_edit.setPlainText(envelope)
            dialog.import_button.click()

        self.gui.common.gui.onion.connected_to_tor = True
        try:
            with mock.patch.object(TabWidget, "open_saved_service", spy):
                with mock.patch.object(ServerStatus, "start_server", status_start):
                    with mock.patch.object(Mode, "start_server", mode_start):
                        with mock.patch.object(QtWidgets.QMessageBox, "exec", exec_box):
                            with mock.patch.object(
                                QtWidgets.QInputDialog, "getText", get_text
                            ):
                                with mock.patch.object(
                                    QtWidgets.QFileDialog,
                                    "getOpenFileName",
                                    get_open,
                                ):
                                    with mock.patch.object(
                                        identity_import_dialog,
                                        "decrypt_identity",
                                        wrapped_decrypt,
                                    ):
                                        dialog = self._drive(prepare)
        finally:
            self.gui.common.gui.onion.connected_to_tor = False

        self.assertFalse(self._timed_out)
        self.assertEqual(len(decrypt_calls), 1)
        gui_thread = QtWidgets.QApplication.instance().thread()
        worker_ident, seen_passphrase, worker_qthread = decrypt_calls[0]
        self.assertTrue(worker_ident != threading.get_ident())
        self.assertTrue(worker_qthread is not gui_thread)
        self.assertTrue(dialog.decrypt_thread.worker_thread is worker_qthread)
        self.assertTrue(seen_passphrase == captured["widget_passphrase"])
        self.assertTrue("t-shirt" in seen_passphrase)
        self.assertTrue(seen_passphrase == PASSPHRASE_TYPED)
        self.assertEqual(defaults, [self._mode_label(mode)])
        self.assertEqual(existed_at_disclosure, [False])
        self.assertEqual(existed_at_label, [False])
        self.assertTrue(disclosure in messages)
        self.assertFalse(GENERIC in messages)
        self.assertEqual(len(calls), 1)
        self.assertTrue(files_at_open == [True])
        opened_identity, opened_label = calls[0]
        self.assertTrue(opened_label == label)
        for key in (
            "mode",
            "service_id",
            "private_key",
            "client_auth_priv_key",
            "client_auth_pub_key",
            "public",
        ):
            self.assertTrue(opened_identity[key] == identity[key])

        tabs = self._tabs_for_service(identity["service_id"])
        self.assertEqual(len(tabs), 1)
        tab = tabs[0]
        self.assertTrue(tab.mode == mode)
        self.assertTrue(
            tab.get_mode().server_status.status == ServerStatus.STATUS_STOPPED
        )
        self.assertTrue(tab.settings.get("persistent", "enabled") is False)
        self.assertTrue(tab.settings.get("persistent", "autostart_on_launch") is False)
        self.assertTrue(tab.settings.get("general", "autostart_timer") is False)
        self.assertTrue(tab.settings.get("general", "public") is identity["public"])
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
        persistent_file = os.path.join(
            self._data_dir(), "persistent", tab.settings.id + ".json"
        )
        self.assertFalse(os.path.exists(persistent_file))
        tab.get_mode().tor_connection_started()
        self.gui.tabs.tor_is_connected()
        self.assertEqual(start_calls, [])
        self.assertTrue(
            tab.get_mode().server_status.status == ServerStatus.STATUS_STOPPED
        )

        self.assertTrue(os.path.isfile(record_path))
        with open(record_path, "r", encoding="utf-8") as handle:
            stored = json.load(handle)
        self.assertEqual(stored["label"], label)
        self.assertEqual(stored["mode"], mode)
        self.assertTrue(stored["saved_at"].endswith("Z"))
        self.assertTrue("filenames" not in stored)
        self.assertTrue("data_dir" not in stored)
        self.assertFalse(PASSPHRASE_STRIPPED in json.dumps(stored))
        before = captured["before"]
        after_raw = self._read_bytes(self._settings_path())
        self.assertTrue(after_raw is not None)
        after_settings = json.loads(after_raw)
        self.assertEqual(after_settings["persistent_tabs"], before["persistent_tabs"])
        self.assertEqual(
            after_settings["saved_services"],
            list(before["saved_services"]) + [identity["service_id"]],
        )
        if before["settings"] is not None:
            before_settings = json.loads(before["settings"])
            for key, value in before_settings.items():
                if key == "saved_services":
                    continue
                self.assertEqual(after_settings[key], value)
        self.assertTrue(
            self._tree(os.path.join(self._data_dir(), "persistent"))
            == before["persistent"]
        )
        self._assert_secrets_absent(
            _secrets_of(identity, envelope, PASSPHRASE_TYPED) + [PASSPHRASE_STRIPPED]
        )

    def run_public_import(self, envelopes):
        """A public identity with null client-auth keys imports and stays stopped."""
        packed = envelopes["public"]
        identity = packed["identity"]
        self.assertTrue(identity["public"] is True)
        self.assertTrue(identity["client_auth_priv_key"] is None)
        self.assertTrue(identity["client_auth_pub_key"] is None)
        path = self._write_temp(packed["envelope"].encode("utf-8"))
        calls = []
        start_calls = []
        real_open = TabWidget.open_saved_service

        def spy(self, opened_identity, opened_label=None):
            calls.append((opened_identity, opened_label))
            return real_open(self, opened_identity, opened_label)

        def status_start(self, *args, **kwargs):
            start_calls.append("status")

        def mode_start(self, *args, **kwargs):
            start_calls.append("mode")

        def prepare(dialog):
            dialog.file_radio.setChecked(True)
            dialog.passphrase_edit.setText(PASSPHRASE_TYPED)
            dialog.choose_file_button.click()
            dialog.import_button.click()

        self.gui.common.gui.onion.connected_to_tor = True
        try:
            with mock.patch.object(TabWidget, "open_saved_service", spy):
                with mock.patch.object(ServerStatus, "start_server", status_start):
                    with mock.patch.object(Mode, "start_server", mode_start):
                        with mock.patch.object(
                            QtWidgets.QMessageBox,
                            "exec",
                            return_value=QtWidgets.QMessageBox.StandardButton.Ok,
                        ):
                            with mock.patch.object(
                                QtWidgets.QInputDialog,
                                "getText",
                                return_value=("public-label", True),
                            ):
                                with mock.patch.object(
                                    QtWidgets.QFileDialog,
                                    "getOpenFileName",
                                    return_value=(path, ""),
                                ):
                                    self._drive(prepare)
        finally:
            self.gui.common.gui.onion.connected_to_tor = False

        self.assertFalse(self._timed_out)
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][0]["public"] is True)
        self.assertTrue(calls[0][0]["client_auth_priv_key"] is None)
        tabs = self._tabs_for_service(identity["service_id"])
        self.assertEqual(len(tabs), 1)
        tab = tabs[0]
        self.assertTrue(tab.mode == "share")
        self.assertTrue(tab.settings.get("general", "public") is True)
        self.assertTrue(tab.settings.get("onion", "client_auth_priv_key") is None)
        self.assertTrue(tab.settings.get("onion", "client_auth_pub_key") is None)
        self.assertTrue(
            tab.get_mode().server_status.status == ServerStatus.STATUS_STOPPED
        )
        self.assertTrue(tab.settings.get("persistent", "enabled") is False)
        self.assertTrue(tab.settings.get("persistent", "autostart_on_launch") is False)
        tab.get_mode().tor_connection_started()
        self.assertEqual(start_calls, [])
        self.assertTrue(
            tab.get_mode().server_status.status == ServerStatus.STATUS_STOPPED
        )
        self._assert_secrets_absent(
            _secrets_of(identity, packed["envelope"], PASSPHRASE_TYPED)
        )

    def run_failure(self, envelopes, kind):
        """A damaged import shows one generic message and changes nothing."""
        identity = envelopes["share"]["identity"]
        envelope = envelopes["share"]["envelope"]
        generic = strings._("gui_identity_import_error")
        self.assertTrue(generic == GENERIC)
        messages = []
        decrypt_calls = []
        calls = []
        real_decrypt = identity_import_dialog.decrypt_identity
        real_open = TabWidget.open_saved_service
        file_path = None

        def exec_box(box, *args, **kwargs):
            messages.append(box.text())
            return QtWidgets.QMessageBox.StandardButton.Ok

        def spy(self, opened_identity, opened_label=None):
            calls.append(True)
            return real_open(self, opened_identity, opened_label)

        def wrapped_decrypt(text, passphrase):
            decrypt_calls.append(threading.get_ident())
            return real_decrypt(text, passphrase)

        if kind == "wrong_passphrase":
            pasted = envelope
            typed = "wrong-passphrase-value"
        elif kind == "truncated":
            pasted = envelope[:-20]
            typed = PASSPHRASE_TYPED
        elif kind == "extra_key":
            payload = json.loads(envelope)
            payload["extra"] = "nope"
            pasted = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            typed = PASSPHRASE_TYPED
        elif kind == "oversize":
            file_path = self._write_temp(b"\xff" * 8193)
            pasted = None
            typed = PASSPHRASE_TYPED
        elif kind == "non_utf8":
            file_path = self._write_temp(b"\xff\xfe" + b"\x80\x81")
            pasted = None
            typed = PASSPHRASE_TYPED
        elif kind == "empty":
            pasted = ""
            typed = PASSPHRASE_TYPED
        elif kind == "empty_file":
            file_path = self._write_temp(b"")
            pasted = None
            typed = PASSPHRASE_TYPED
        elif kind == "bad_params":
            payload = json.loads(envelope)
            original_m = payload["m"]
            payload["m"] = original_m + 1
            pasted = json.dumps(
                payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            )
            self.assertTrue(payload["m"] != original_m)
            self.assertTrue(len(pasted) <= 8192)
            self.assertTrue(len(pasted.encode("utf-8")) <= 8192)
            typed = PASSPHRASE_TYPED
        elif kind == "permission":
            file_path = self._write_temp(b"backup")
            os.chmod(file_path, 0)
            denied = False
            try:
                with open(file_path, "rb") as handle:
                    handle.read()
            except PermissionError:
                denied = True
            self.assertTrue(denied)
            pasted = None
            typed = PASSPHRASE_TYPED
        elif kind == "directory":
            file_path = tempfile.mkdtemp(prefix="os-import-dir-")
            self._temp_dirs.append(file_path)
            self.assertTrue(os.path.isdir(file_path))
            pasted = None
            typed = PASSPHRASE_TYPED
        elif kind == "vanished":
            folder = tempfile.mkdtemp(prefix="os-import-dir-")
            self._temp_dirs.append(folder)
            file_path = os.path.join(folder, "gone.json")
            self.assertFalse(os.path.exists(file_path))
            pasted = None
            typed = PASSPHRASE_TYPED
        elif kind == "oversize_paste":
            pasted = "a" * 8193
            self.assertTrue(len(pasted) == 8193)
            self.assertTrue(pasted.isascii())
            typed = PASSPHRASE_TYPED
        elif kind == "oversize_ascii":
            file_path = self._write_temp(b"a" * 8193)
            raw = self._read_bytes(file_path)
            self.assertTrue(raw == b"a" * 8193)
            self.assertTrue(raw.decode("utf-8") == "a" * 8193)
            pasted = None
            typed = PASSPHRASE_TYPED
        else:
            self.fail("unknown failure kind")

        captured = {}

        def prepare(dialog):
            captured["before"] = self._capture()
            dialog.passphrase_edit.setText(typed)
            if file_path is None:
                dialog.paste_radio.setChecked(True)
                dialog.envelope_edit.setPlainText(pasted)
            else:
                dialog.file_radio.setChecked(True)
                dialog.choose_file_button.click()
            dialog.import_button.click()

        with mock.patch.object(TabWidget, "open_saved_service", spy):
            with mock.patch.object(QtWidgets.QMessageBox, "exec", exec_box):
                with mock.patch.object(
                    QtWidgets.QInputDialog, "getText", return_value=("nope", True)
                ):
                    with mock.patch.object(
                        QtWidgets.QFileDialog,
                        "getOpenFileName",
                        return_value=(file_path or "", ""),
                    ):
                        with mock.patch.object(
                            identity_import_dialog, "decrypt_identity", wrapped_decrypt
                        ):
                            dialog = self._drive(prepare)

        self.assertFalse(self._timed_out)
        self.assertEqual(messages, [generic])
        self.assertEqual(calls, [])
        self.assertEqual(self._tabs_for_service(identity["service_id"]), [])
        self.assertFalse(os.path.exists(self._record_path(identity["service_id"])))
        self._assert_unchanged(captured["before"])
        # Decodable oversize bytes never reach decrypt, so the file cap is
        # not only a Unicode rejection.
        pre_decrypt = (
            "oversize",
            "non_utf8",
            "oversize_paste",
            "oversize_ascii",
            "permission",
            "directory",
            "vanished",
        )
        if kind in pre_decrypt:
            self.assertEqual(decrypt_calls, [])
            self.assertTrue(dialog.decrypt_thread is None)
        else:
            self.assertEqual(len(decrypt_calls), 1)
            self.assertTrue(decrypt_calls[0] != threading.get_ident())
            self.assertTrue(
                dialog.decrypt_thread.worker_thread
                is not QtWidgets.QApplication.instance().thread()
            )
        secrets = [typed, PASSPHRASE_STRIPPED, identity["private_key"]]
        if pasted:
            secrets.append(pasted)
        secrets.append(envelope)
        self._assert_secrets_absent(secrets)

    def run_archive_write_error(self, envelopes):
        """An OSError from the durable write shows the archive alert only.

        The tab is not opened, the temp file is removed, and the settings
        file bytes plus both directories stay as they were.
        """
        identity = envelopes["share"]["identity"]
        envelope = envelopes["share"]["envelope"]
        archive_error = strings._("gui_identity_backup_archive_error")
        disclosure = strings._("gui_identity_backup_archive_disclosure")
        self.assertEqual(archive_error, "Could not save this service.")
        disk_error = "disk-write-failed"
        messages = []
        calls = []
        replace_calls = []
        label_calls = []
        real_open = TabWidget.open_saved_service
        archive_dir = os.path.join(self._data_dir(), "saved_services")
        os.makedirs(archive_dir, 0o700, exist_ok=True)

        def exec_box(box, *args, **kwargs):
            messages.append(box.text())
            return QtWidgets.QMessageBox.StandardButton.Ok

        def spy(self, opened_identity, opened_label=None):
            calls.append(True)
            return real_open(self, opened_identity, opened_label)

        real_replace = saved_services_module.os.replace

        def explode(src, dst, *args, **kwargs):
            destination = dst if isinstance(dst, (str, bytes)) else ""
            if isinstance(destination, bytes):
                destination = destination.decode("utf-8", "replace")
            if "saved_services" in destination and destination.endswith(".json"):
                replace_calls.append(True)
                raise OSError(disk_error)
            return real_replace(src, dst, *args, **kwargs)

        def get_text(*args, **kwargs):
            label_calls.append(True)
            return ("archive-label", True)

        captured = {}

        def prepare(dialog):
            self.gui.common.settings.save()
            captured["before"] = self._capture()
            dialog.paste_radio.setChecked(True)
            dialog.envelope_edit.setPlainText(envelope)
            dialog.passphrase_edit.setText(PASSPHRASE_TYPED)
            dialog.import_button.click()

        with mock.patch.object(saved_services_module.os, "replace", explode):
            with mock.patch.object(TabWidget, "open_saved_service", spy):
                with mock.patch.object(QtWidgets.QMessageBox, "exec", exec_box):
                    with mock.patch.object(QtWidgets.QInputDialog, "getText", get_text):
                        self._drive(prepare)

        self.assertFalse(self._timed_out)
        self.assertTrue(captured["before"]["settings"] is not None)
        self.assertEqual(messages, [disclosure, archive_error])
        self.assertEqual(
            [text for text in messages if text != disclosure], [archive_error]
        )
        self.assertFalse(GENERIC in messages)
        self.assertFalse(strings._("gui_identity_backup_invalid_label") in messages)
        for text in messages:
            self.assertFalse(disk_error in text)
        self.assertEqual(label_calls, [True])
        self.assertEqual(replace_calls, [True])
        self.assertEqual(calls, [])
        self.assertEqual(self._tabs_for_service(identity["service_id"]), [])
        self.assertFalse(os.path.exists(self._record_path(identity["service_id"])))
        names = os.listdir(archive_dir)
        self.assertFalse(any(name.startswith(".tmp-") for name in names))
        self._assert_unchanged(captured["before"])
        self._assert_secrets_absent(
            _secrets_of(identity, envelope, PASSPHRASE_TYPED)
            + [PASSPHRASE_STRIPPED, disk_error]
        )

    def run_decline_existing(self, envelopes):
        """Declining a replace writes nothing and opens nothing."""
        identity = envelopes["share"]["identity"]
        other = dict(identity)
        other["mode"] = "receive"
        SavedServices(self.gui.common, self.gui.common.settings).add(other, "kept")
        record_path = self._record_path(identity["service_id"])
        with open(record_path, "rb") as handle:
            before_record = handle.read()
        before = self._capture()
        messages = []
        calls = []
        question = strings._("gui_identity_backup_archive_duplicate")
        left = strings._("gui_identity_backup_archive_not_replaced")

        def exec_box(box, *args, **kwargs):
            text = box.text()
            messages.append(text)
            if text == question:
                return QtWidgets.QMessageBox.StandardButton.No
            return QtWidgets.QMessageBox.StandardButton.Ok

        def spy(self, opened_identity, opened_label=None):
            calls.append(True)
            return None

        def prepare(dialog):
            dialog.paste_radio.setChecked(True)
            dialog.envelope_edit.setPlainText(envelopes["share"]["envelope"])
            dialog.passphrase_edit.setText(PASSPHRASE_TYPED)
            dialog.import_button.click()

        with mock.patch.object(TabWidget, "open_saved_service", spy):
            with mock.patch.object(QtWidgets.QMessageBox, "exec", exec_box):
                with mock.patch.object(
                    QtWidgets.QInputDialog, "getText", return_value=("new-label", True)
                ):
                    self._drive(prepare)

        self.assertFalse(self._timed_out)
        self.assertTrue(question in messages)
        self.assertTrue(left in messages)
        self.assertFalse(GENERIC in messages)
        self.assertEqual(calls, [])
        with open(record_path, "rb") as handle:
            after_record = handle.read()
        self.assertTrue(after_record == before_record)
        self._assert_unchanged(before)
        self._assert_secrets_absent(
            _secrets_of(identity, envelopes["share"]["envelope"], PASSPHRASE_TYPED)
        )

    def run_identical_opens_without_rewrite(self, envelopes):
        """Identical archived keys are opened and the record bytes stay put."""
        identity = envelopes["website"]["identity"]
        archive = SavedServices(self.gui.common, self.gui.common.settings)
        archive.add(identity, "kept")
        record_path = self._record_path(identity["service_id"])
        with open(record_path, "rb") as handle:
            before_record = handle.read()
        messages = []
        calls = []
        start_calls = []
        question = strings._("gui_identity_backup_archive_duplicate")
        real_open = TabWidget.open_saved_service

        def exec_box(box, *args, **kwargs):
            messages.append(box.text())
            return QtWidgets.QMessageBox.StandardButton.Ok

        def spy(self, opened_identity, opened_label=None):
            calls.append(opened_label)
            return real_open(self, opened_identity, opened_label)

        def status_start(self, *args, **kwargs):
            start_calls.append("status")

        def mode_start(self, *args, **kwargs):
            start_calls.append("mode")

        def prepare(dialog):
            dialog.paste_radio.setChecked(True)
            dialog.envelope_edit.setPlainText(envelopes["website"]["envelope"])
            dialog.passphrase_edit.setText(PASSPHRASE_TYPED)
            dialog.import_button.click()

        self.gui.common.gui.onion.connected_to_tor = True
        try:
            with mock.patch.object(TabWidget, "open_saved_service", spy):
                with mock.patch.object(ServerStatus, "start_server", status_start):
                    with mock.patch.object(Mode, "start_server", mode_start):
                        with mock.patch.object(QtWidgets.QMessageBox, "exec", exec_box):
                            with mock.patch.object(
                                QtWidgets.QInputDialog,
                                "getText",
                                return_value=("other-label", True),
                            ):
                                self._drive(prepare)
        finally:
            self.gui.common.gui.onion.connected_to_tor = False

        self.assertFalse(self._timed_out)
        self.assertFalse(question in messages)
        self.assertEqual(calls, ["other-label"])
        with open(record_path, "rb") as handle:
            after_record = handle.read()
        self.assertTrue(after_record == before_record)
        tabs = self._tabs_for_service(identity["service_id"])
        self.assertEqual(len(tabs), 1)
        self.assertTrue(
            tabs[0].get_mode().server_status.status == ServerStatus.STATUS_STOPPED
        )
        self.assertEqual(start_calls, [])
        self.assertTrue(tabs[0].settings.get("persistent", "enabled") is False)

    def run_duplicate_open(self, envelopes):
        """A second import of an open service warns and starts neither tab."""
        identity = envelopes["chat"]["identity"]
        envelope = envelopes["chat"]["envelope"]
        start_calls = []
        calls = []
        real_open = TabWidget.open_saved_service
        duplicate = strings._("gui_saved_services_duplicate")

        def spy(self, opened_identity, opened_label=None):
            calls.append(opened_label)
            return real_open(self, opened_identity, opened_label)

        def status_start(self, *args, **kwargs):
            start_calls.append("status")

        def mode_start(self, *args, **kwargs):
            start_calls.append("mode")

        def prepare(dialog):
            dialog.paste_radio.setChecked(True)
            dialog.envelope_edit.setPlainText(envelope)
            dialog.passphrase_edit.setText(PASSPHRASE_TYPED)
            dialog.import_button.click()

        messages = []

        def exec_box(box, *args, **kwargs):
            messages.append(box.text())
            return QtWidgets.QMessageBox.StandardButton.Ok

        self.gui.common.gui.onion.connected_to_tor = True
        try:
            with mock.patch.object(TabWidget, "open_saved_service", spy):
                with mock.patch.object(ServerStatus, "start_server", status_start):
                    with mock.patch.object(Mode, "start_server", mode_start):
                        with mock.patch.object(QtWidgets.QMessageBox, "exec", exec_box):
                            with mock.patch.object(
                                QtWidgets.QInputDialog,
                                "getText",
                                return_value=("chat-label", True),
                            ):
                                self._drive(prepare)
                                record_path = self._record_path(identity["service_id"])
                                with open(record_path, "rb") as handle:
                                    first_bytes = handle.read()
                                self._drive(prepare)
                                with open(record_path, "rb") as handle:
                                    second_bytes = handle.read()
        finally:
            self.gui.common.gui.onion.connected_to_tor = False

        self.assertFalse(self._timed_out)
        self.assertTrue(first_bytes == second_bytes)
        self.assertEqual(calls, ["chat-label", "chat-label"])
        self.assertTrue(duplicate in messages)
        self.assertEqual(len(self._tabs_for_service(identity["service_id"])), 1)
        tab = self._tabs_for_service(identity["service_id"])[0]
        self.assertTrue(
            tab.get_mode().server_status.status == ServerStatus.STATUS_STOPPED
        )
        self.assertEqual(start_calls, [])
        self.assertTrue(tab.settings.get("persistent", "enabled") is False)

    def run_cancel_before_write(self, envelopes, stage):
        """Canceling disclosure or the label writes nothing and opens nothing."""
        identity = envelopes["receive"]["identity"]
        before = None
        messages = []
        calls = []
        get_text_calls = []
        disclosure = strings._("gui_identity_backup_archive_disclosure")

        def exec_box(box, *args, **kwargs):
            messages.append(box.text())
            if stage == "disclosure":
                return QtWidgets.QMessageBox.StandardButton.Cancel
            return QtWidgets.QMessageBox.StandardButton.Ok

        def get_text(*args, **kwargs):
            get_text_calls.append(True)
            if stage == "label":
                return ("label", False)
            return ("label", True)

        def spy(self, opened_identity, opened_label=None):
            calls.append(True)
            return None

        def prepare(dialog):
            nonlocal before
            before = self._capture()
            dialog.paste_radio.setChecked(True)
            dialog.envelope_edit.setPlainText(envelopes["receive"]["envelope"])
            dialog.passphrase_edit.setText(PASSPHRASE_TYPED)
            dialog.import_button.click()

        with mock.patch.object(TabWidget, "open_saved_service", spy):
            with mock.patch.object(QtWidgets.QMessageBox, "exec", exec_box):
                with mock.patch.object(QtWidgets.QInputDialog, "getText", get_text):
                    self._drive(prepare)

        self.assertFalse(self._timed_out)
        self.assertTrue(disclosure in messages)
        self.assertEqual(calls, [])
        self._assert_unchanged(before)
        if stage == "disclosure":
            self.assertEqual(get_text_calls, [])
        else:
            self.assertEqual(get_text_calls, [True])

    def run_invalid_label(self, envelopes):
        """A control character in the label writes nothing and opens nothing."""
        identity = envelopes["share"]["identity"]
        before = None
        messages = []
        calls = []
        dedicated = strings._("gui_identity_backup_invalid_label")

        def exec_box(box, *args, **kwargs):
            messages.append(box.text())
            return QtWidgets.QMessageBox.StandardButton.Ok

        def spy(self, opened_identity, opened_label=None):
            calls.append(True)
            return None

        def prepare(dialog):
            nonlocal before
            before = self._capture()
            dialog.paste_radio.setChecked(True)
            dialog.envelope_edit.setPlainText(envelopes["share"]["envelope"])
            dialog.passphrase_edit.setText(PASSPHRASE_TYPED)
            dialog.import_button.click()

        with mock.patch.object(TabWidget, "open_saved_service", spy):
            with mock.patch.object(QtWidgets.QMessageBox, "exec", exec_box):
                with mock.patch.object(
                    QtWidgets.QInputDialog, "getText", return_value=("bad\nlabel", True)
                ):
                    self._drive(prepare)

        self.assertFalse(self._timed_out)
        self.assertTrue(dedicated in messages)
        self.assertFalse(GENERIC in messages)
        self.assertEqual(calls, [])
        self._assert_unchanged(before)
        self._assert_secrets_absent(["bad\nlabel"])

    def _slow_decrypt(self, started):
        real = identity_import_dialog.decrypt_identity

        def slow(text, passphrase):
            started.set()
            time.sleep(0.5)
            return real(text, passphrase)

        return slow

    def run_close_during_kdf(self, envelopes, how):
        """Close or Escape during decrypt finishes the thread with no late tab."""
        identity = envelopes["share"]["identity"]
        envelope = envelopes["share"]["envelope"]
        started = threading.Event()
        alerts = []
        calls = []
        before = self._capture()

        def exec_box(box, *args, **kwargs):
            alerts.append(box.text())
            return QtWidgets.QMessageBox.StandardButton.Cancel

        def spy(self, opened_identity, opened_label=None):
            calls.append(True)
            return None

        def prepare(dialog):
            dialog.paste_radio.setChecked(True)
            dialog.envelope_edit.setPlainText(envelope)
            dialog.passphrase_edit.setText(PASSPHRASE_TYPED)

            def punch():
                if not started.is_set():
                    QtCore.QTimer.singleShot(10, punch)
                    return
                if how == "escape":
                    QtTest.QTest.keyClick(dialog, QtCore.Qt.Key.Key_Escape)
                else:
                    dialog.close_button.click()

            QtCore.QTimer.singleShot(10, punch)
            dialog.import_button.click()

        with mock.patch.object(TabWidget, "open_saved_service", spy):
            with mock.patch.object(QtWidgets.QMessageBox, "exec", exec_box):
                with mock.patch.object(
                    QtWidgets.QInputDialog, "getText", return_value=("x", True)
                ):
                    with mock.patch.object(
                        identity_import_dialog,
                        "decrypt_identity",
                        self._slow_decrypt(started),
                    ):
                        dialog = self._drive(prepare, close_when_idle=False)

        self.gui.qtapp.processEvents()
        self.assertFalse(self._timed_out)
        thread = dialog.decrypt_thread
        self.assertFalse(thread.isRunning())
        self.assertTrue(thread.isFinished())
        self.assertFalse(dialog.isVisible())
        self.assertEqual(alerts, [])
        self.assertEqual(calls, [])
        self._assert_unchanged(before)
        self.assertEqual(self._tabs_for_service(identity["service_id"]), [])
        self._assert_secrets_absent(_secrets_of(identity, envelope, PASSPHRASE_TYPED))

    def run_tab_close_during_kdf(self, envelopes):
        """Closing the settings tab during decrypt does not open a tab later."""
        identity = envelopes["share"]["identity"]
        envelope = envelopes["share"]["envelope"]
        started = threading.Event()
        alerts = []
        calls = []
        before = self._capture()
        settings = self._open_settings()
        accepted = QtWidgets.QDialog.DialogCode.Accepted

        def exec_box(box, *args, **kwargs):
            alerts.append(box.text())
            return QtWidgets.QMessageBox.StandardButton.Cancel

        def alert_init(box, common, message, *args, **kwargs):
            alerts.append(message)
            kwargs = dict(kwargs)
            kwargs["autostart"] = False
            return real_alert_init(box, common, message, *args, **kwargs)

        def spy(self, opened_identity, opened_label=None):
            calls.append(True)
            return None

        real_alert_init = Alert.__init__
        with mock.patch.object(TabWidget, "open_saved_service", spy):
            with mock.patch.object(QtWidgets.QMessageBox, "exec", exec_box):
                with mock.patch.object(Alert, "__init__", alert_init):
                    with mock.patch.object(
                        QtWidgets.QInputDialog, "getText", return_value=("x", True)
                    ):
                        with mock.patch.object(
                            QtWidgets.QDialog, "exec", return_value=accepted
                        ):
                            settings.saved_services_button.click()
                            manager = settings.saved_services_dialog
                            manager.import_button.click()
                        dialog = manager.import_dialog
                        self._import_dialog = dialog
                        dialog.paste_radio.setChecked(True)
                        dialog.envelope_edit.setPlainText(envelope)
                        dialog.passphrase_edit.setText(PASSPHRASE_TYPED)
                        with mock.patch.object(
                            identity_import_dialog,
                            "decrypt_identity",
                            self._slow_decrypt(started),
                        ):
                            dialog.import_button.click()
                            self._wait_until(started.is_set)
                            thread = dialog.decrypt_thread
                            self.assertTrue(thread.isRunning())
                            self._close_settings_tab()

        self.gui.qtapp.processEvents()
        self.assertFalse(thread.isRunning())
        self.assertTrue(thread.isFinished())
        self.assertEqual(alerts, [])
        self.assertEqual(calls, [])
        self._assert_unchanged(before)
        self.assertEqual(self._tabs_for_service(identity["service_id"]), [])

    def run_inputs_disabled_while_decrypting(self):
        """Import inputs stay disabled for the whole KDF, and Close stays enabled."""
        started = threading.Event()
        release = threading.Event()
        seen = {}

        def slow(text, passphrase):
            started.set()
            release.wait(timeout=30)
            raise IdentityBackupError()

        def prepare(dialog):
            dialog.paste_radio.setChecked(True)
            dialog.envelope_edit.setPlainText("{")
            dialog.passphrase_edit.setText(PASSPHRASE_TYPED)
            dialog.import_button.click()

            def sample():
                if not started.is_set():
                    QtCore.QTimer.singleShot(10, sample)
                    return
                seen["import"] = dialog.import_button.isEnabled()
                seen["passphrase"] = dialog.passphrase_edit.isEnabled()
                seen["paste"] = dialog.envelope_edit.isEnabled()
                seen["choose"] = dialog.choose_file_button.isEnabled()
                seen["paste_radio"] = dialog.paste_radio.isEnabled()
                seen["file_radio"] = dialog.file_radio.isEnabled()
                seen["close"] = dialog.close_button.isEnabled()
                seen["busy"] = dialog.is_busy
                release.set()

            QtCore.QTimer.singleShot(10, sample)

        with mock.patch.object(
            QtWidgets.QMessageBox,
            "exec",
            return_value=QtWidgets.QMessageBox.StandardButton.Ok,
        ):
            with mock.patch.object(
                identity_import_dialog, "decrypt_identity", slow
            ):
                dialog = self._drive(prepare)

        self.assertFalse(self._timed_out)
        self.assertTrue(seen.get("busy") is True)
        self.assertTrue(seen.get("import") is False)
        self.assertTrue(seen.get("passphrase") is False)
        self.assertTrue(seen.get("paste") is False)
        self.assertTrue(seen.get("choose") is False)
        self.assertTrue(seen.get("paste_radio") is False)
        self.assertTrue(seen.get("file_radio") is False)
        self.assertTrue(seen.get("close") is True)
        self.assertFalse(dialog.decrypt_thread.isRunning())
        self._assert_secrets_absent([PASSPHRASE_TYPED, PASSPHRASE_STRIPPED])

    def run_no_camera_or_qr_decode(self, envelopes):
        """The import modules do not import or load a camera or QR decoder."""
        root = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "onionshare",
        )
        paths = [
            os.path.join(root, "identity_import_dialog.py"),
            os.path.join(root, "saved_services_dialog.py"),
        ]
        for path in paths:
            source = open(path, encoding="utf-8").read()
            for name in _FORBIDDEN:
                self.assertFalse(name in source)
            self.assertFalse(".start_server(" in source)
            for imported in _imported_names(__import__("pathlib").Path(path)):
                for name in _FORBIDDEN:
                    self.assertFalse(imported == name or imported.startswith(name + "."))
        self.assertTrue("open_saved_service" in open(paths[0], encoding="utf-8").read())
        reader = inspect.getsource(read_envelope_file)
        self.assertTrue(reader.index("_MAX_ENVELOPE_BYTES") < reader.index(".decode("))
        self.assertTrue("read(_MAX_ENVELOPE_BYTES + 1)" in reader)

        def prepare(dialog):
            dialog.paste_radio.setChecked(True)
            dialog.envelope_edit.setPlainText("{")
            dialog.passphrase_edit.setText(PASSPHRASE_TYPED)
            dialog.import_button.click()

        with mock.patch.object(
            QtWidgets.QMessageBox,
            "exec",
            return_value=QtWidgets.QMessageBox.StandardButton.Ok,
        ):
            self._drive(prepare)

        self.assertFalse(self._timed_out)
        for name in _FORBIDDEN_MODULES:
            self.assertFalse(name in __import__("sys").modules)


@pytest.fixture(scope="module")
def identity_import_case():
    IdentityImportCase.setUpClass()
    yield IdentityImportCase
    IdentityImportCase.tearDownClass()


def _bind(case_cls, name, caplog, capsys):
    case = case_cls(name)
    case.caplog = caplog
    case.capsys = capsys
    case.setUp()
    return case


@pytest.mark.parametrize("mode", list(_MODES))
@pytest.mark.parametrize("source", ["file", "paste"])
def test_import_backup_opens_stopped_tab(
    identity_import_case, envelopes, mode, source, caplog, capsys
):
    case = _bind(identity_import_case, "run_import", caplog, capsys)
    try:
        case.run_import(envelopes, mode, source)
    finally:
        case.tearDown()


def test_import_public_identity_opens_stopped(
    identity_import_case, envelopes, caplog, capsys
):
    case = _bind(identity_import_case, "run_public_import", caplog, capsys)
    try:
        case.run_public_import(envelopes)
    finally:
        case.tearDown()


@pytest.mark.parametrize(
    "kind",
    [
        "wrong_passphrase",
        "truncated",
        "oversize",
        "non_utf8",
        "extra_key",
        "empty",
        "empty_file",
        "bad_params",
        "permission",
        "directory",
        "vanished",
        "oversize_paste",
        "oversize_ascii",
    ],
)
def test_failed_import_has_no_side_effects(
    identity_import_case, envelopes, kind, caplog, capsys
):
    case = _bind(identity_import_case, "run_failure", caplog, capsys)
    try:
        case.run_failure(envelopes, kind)
    finally:
        case.tearDown()


def test_archive_write_error_opens_nothing(
    identity_import_case, envelopes, caplog, capsys
):
    case = _bind(identity_import_case, "run_archive_write_error", caplog, capsys)
    try:
        case.run_archive_write_error(envelopes)
    finally:
        case.tearDown()


def test_existing_record_decline_writes_nothing(
    identity_import_case, envelopes, caplog, capsys
):
    case = _bind(identity_import_case, "run_decline_existing", caplog, capsys)
    try:
        case.run_decline_existing(envelopes)
    finally:
        case.tearDown()


def test_identical_keys_open_without_rewrite(
    identity_import_case, envelopes, caplog, capsys
):
    case = _bind(identity_import_case, "run_identical_opens_without_rewrite", caplog, capsys)
    try:
        case.run_identical_opens_without_rewrite(envelopes)
    finally:
        case.tearDown()


def test_duplicate_open_starts_neither_service(
    identity_import_case, envelopes, caplog, capsys
):
    case = _bind(identity_import_case, "run_duplicate_open", caplog, capsys)
    try:
        case.run_duplicate_open(envelopes)
    finally:
        case.tearDown()


@pytest.mark.parametrize("stage", ["disclosure", "label"])
def test_cancel_before_archive_writes_nothing(
    identity_import_case, envelopes, stage, caplog, capsys
):
    case = _bind(identity_import_case, "run_cancel_before_write", caplog, capsys)
    try:
        case.run_cancel_before_write(envelopes, stage)
    finally:
        case.tearDown()


def test_invalid_label_writes_nothing(identity_import_case, envelopes, caplog, capsys):
    case = _bind(identity_import_case, "run_invalid_label", caplog, capsys)
    try:
        case.run_invalid_label(envelopes)
    finally:
        case.tearDown()


@pytest.mark.parametrize("how", ["close", "escape"])
def test_close_or_escape_during_kdf_has_no_late_tab(
    identity_import_case, envelopes, how, caplog, capsys
):
    case = _bind(identity_import_case, "run_close_during_kdf", caplog, capsys)
    try:
        case.run_close_during_kdf(envelopes, how)
    finally:
        case.tearDown()


def test_settings_tab_close_during_kdf_has_no_late_tab(
    identity_import_case, envelopes, caplog, capsys
):
    case = _bind(identity_import_case, "run_tab_close_during_kdf", caplog, capsys)
    try:
        case.run_tab_close_during_kdf(envelopes)
    finally:
        case.tearDown()


def test_inputs_disabled_while_decrypt_runs(identity_import_case, caplog, capsys):
    case = _bind(identity_import_case, "run_inputs_disabled_while_decrypting", caplog, capsys)
    try:
        case.run_inputs_disabled_while_decrypting()
    finally:
        case.tearDown()


def test_import_has_no_camera_or_qr_decode_path(
    identity_import_case, envelopes, caplog, capsys
):
    case = _bind(identity_import_case, "run_no_camera_or_qr_decode", caplog, capsys)
    try:
        case.run_no_camera_or_qr_decode(envelopes)
    finally:
        case.tearDown()
