import unittest
from types import ModuleType


class TestBasic(unittest.TestCase):
    def test_import(self) -> None:
        import nitrokey
        import nitrokey.nk3
        import nitrokey.nkpk
        import nitrokey.trussed
        import nitrokey.updates

        self.assertIsInstance(nitrokey, ModuleType)

    def test_list_nk3(self) -> None:
        from nitrokey.nk3 import list

        list()

    def test_list_nkpk(self) -> None:
        from nitrokey.nkpk import list

        list()


class TestNk3Updates(unittest.TestCase):
    def test_update_path_default(self) -> None:
        from nitrokey.trussed import Model, Variant, Version
        from nitrokey.trussed.updates import _Migration

        self.assertEqual(
            _Migration.get(Model.NK3, Variant.NRF52, Version(1, 0, 0), Version(1, 1, 0)),
            frozenset(),
        )
        self.assertEqual(
            _Migration.get(Model.NK3, Variant.NRF52, Version(1, 8, 2), Version(1, 9, 0)),
            frozenset(),
        )
        self.assertEqual(
            _Migration.get(Model.NK3, Variant.LPC55, Version(1, 2, 2), Version(1, 3, 0)),
            frozenset(),
        )

    def test_update_path_nrf(self) -> None:
        from nitrokey.trussed import Model, Variant, Version
        from nitrokey.trussed.updates import _Migration

        migrations = frozenset([_Migration.NRF_IFS_MIGRATION])

        self.assertEqual(
            _Migration.get(Model.NK3, Variant.NRF52, Version(1, 2, 2), Version(1, 3, 0)), migrations
        )
        self.assertEqual(
            _Migration.get(Model.NK3, Variant.NRF52, Version(1, 0, 0), Version(1, 3, 0)), migrations
        )
        self.assertEqual(
            _Migration.get(Model.NK3, Variant.NRF52, None, Version(1, 3, 0)), migrations
        )

    def test_update_path_ifs_v2(self) -> None:
        from nitrokey.trussed import Model, Variant, Version
        from nitrokey.trussed.updates import _Migration

        migrations = frozenset([_Migration.IFS_MIGRATION_V2])

        self.assertEqual(
            _Migration.get(Model.NK3, Variant.NRF52, Version(1, 5, 0), Version(1, 8, 2)), migrations
        )
        self.assertEqual(
            _Migration.get(Model.NK3, Variant.LPC55, Version(1, 1, 0), Version(1, 8, 2)), migrations
        )
        self.assertEqual(
            _Migration.get(Model.NK3, Variant.LPC55, Version(1, 8, 0), Version(1, 8, 2)), migrations
        )

    def test_update_path_multi(self) -> None:
        from nitrokey.trussed import Model, Variant, Version
        from nitrokey.trussed.updates import _Migration

        migrations = frozenset([_Migration.NRF_IFS_MIGRATION, _Migration.IFS_MIGRATION_V2])

        self.assertEqual(
            _Migration.get(Model.NK3, Variant.NRF52, Version(1, 2, 2), Version(1, 8, 2)), migrations
        )


class TestConfigFieldType(unittest.TestCase):
    def test_is_valid_bool(self) -> None:
        from nitrokey.trussed.admin_app import ConfigFieldType

        t = ConfigFieldType.BOOL

        self.assertTrue(t.is_valid("true"))
        self.assertTrue(t.is_valid("false"))

        self.assertFalse(t.is_valid(""))
        self.assertFalse(t.is_valid("True"))
        self.assertFalse(t.is_valid("False"))
        self.assertFalse(t.is_valid("0"))
        self.assertFalse(t.is_valid("1"))
        self.assertFalse(t.is_valid("something else"))

    def test_is_valid_u8(self) -> None:
        from nitrokey.trussed.admin_app import ConfigFieldType

        t = ConfigFieldType.U8

        self.assertTrue(t.is_valid("0"))
        self.assertTrue(t.is_valid("1"))
        self.assertTrue(t.is_valid("42"))
        self.assertTrue(t.is_valid("255"))

        self.assertFalse(t.is_valid(""))
        self.assertFalse(t.is_valid("-1"))
        self.assertFalse(t.is_valid("256"))
        self.assertFalse(t.is_valid("4242"))
        self.assertFalse(t.is_valid("something else"))
        self.assertFalse(t.is_valid("True"))
