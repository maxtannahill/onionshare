# -*- coding: utf-8 -*-
"""Import check for the PyNaCl modules used by identity backups.

cx_Freeze is not part of the test run. Importing these modules here fails
the suite if Argon2id or SecretBox is missing from the installed package.
"""

import nacl.pwhash.argon2id as argon2id
import nacl.secret


def test_nacl_argon2id_and_secretbox_import():
    assert callable(argon2id.kdf)
    assert argon2id.OPSLIMIT_INTERACTIVE == 2
    assert argon2id.MEMLIMIT_INTERACTIVE == 67108864
    assert nacl.secret.SecretBox is not None
