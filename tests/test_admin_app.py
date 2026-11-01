import unittest
from unittest.mock import Mock, patch

from fido2 import cbor

from nitrokey.trussed.admin_app import AdminApp, AdminCommand, ConfigFieldType


class TestConfigFieldType(unittest.TestCase):
    def test_from_int(self) -> None:
        self.assertEqual(ConfigFieldType.from_int(0), ConfigFieldType.BOOL)
        self.assertEqual(ConfigFieldType.from_int(1), ConfigFieldType.U8)
        self.assertEqual(ConfigFieldType.from_int(2), ConfigFieldType.STRING)
        self.assertIsNone(ConfigFieldType.from_int(3))

    def test_str(self) -> None:
        self.assertEqual(str(ConfigFieldType.BOOL), "Bool")
        self.assertEqual(str(ConfigFieldType.U8), "u8")
        self.assertEqual(str(ConfigFieldType.STRING), "String")

    def test_is_valid_string(self) -> None:
        ty = ConfigFieldType.STRING
        self.assertTrue(ty.is_valid(""))
        self.assertTrue(ty.is_valid("my key"))
        self.assertTrue(ty.is_valid("ĉ日本🔑"))
        self.assertTrue(ty.is_valid("\n"))
        self.assertTrue(ty.is_valid("\x1b[2J"))
        self.assertTrue(ty.is_valid("\u202e"))
        self.assertTrue(ty.is_valid("\u2028"))
        self.assertFalse(ty.is_valid("\ud800"))


class TestListAvailableFields(unittest.TestCase):
    def test_string_field(self) -> None:
        fields = [
            {"n": "fido.disable_skip_up_timeout", "c": False, "r": False, "d": False, "t": 0},
            {"n": "admin.label", "c": False, "r": False, "d": False, "t": 2},
        ]

        app = AdminApp(Mock())
        with patch.object(AdminApp, "_call", return_value=cbor.encode(fields)) as call:
            result = app.list_available_fields()
        call.assert_called_once_with(AdminCommand.LIST_AVAILABLE_FIELDS)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].name, "fido.disable_skip_up_timeout")
        self.assertEqual(result[0].ty, ConfigFieldType.BOOL)
        self.assertEqual(result[1].name, "admin.label")
        self.assertEqual(result[1].ty, ConfigFieldType.STRING)
