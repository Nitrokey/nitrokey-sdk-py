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
        from nitrokey.nk3.updates import _Migration
        from nitrokey.trussed import Variant, Version

        self.assertEqual(
            _Migration.get(Variant.NRF52, Version(1, 0, 0), Version(1, 1, 0)),
            frozenset(),
        )
        self.assertEqual(
            _Migration.get(Variant.NRF52, Version(1, 8, 2), Version(1, 9, 0)),
            frozenset(),
        )
        self.assertEqual(
            _Migration.get(Variant.LPC55, Version(1, 2, 2), Version(1, 3, 0)),
            frozenset(),
        )

    def test_update_path_nrf(self) -> None:
        from nitrokey.nk3.updates import _Migration
        from nitrokey.trussed import Variant, Version

        migrations = frozenset([_Migration.NRF_IFS_MIGRATION])

        self.assertEqual(
            _Migration.get(Variant.NRF52, Version(1, 2, 2), Version(1, 3, 0)),
            migrations,
        )
        self.assertEqual(
            _Migration.get(Variant.NRF52, Version(1, 0, 0), Version(1, 3, 0)),
            migrations,
        )
        self.assertEqual(
            _Migration.get(Variant.NRF52, None, Version(1, 3, 0)),
            migrations,
        )

    def test_update_path_ifs_v2(self) -> None:
        from nitrokey.nk3.updates import _Migration
        from nitrokey.trussed import Variant, Version

        migrations = frozenset([_Migration.IFS_MIGRATION_V2])

        self.assertEqual(
            _Migration.get(Variant.NRF52, Version(1, 5, 0), Version(1, 8, 2)),
            migrations,
        )
        self.assertEqual(
            _Migration.get(Variant.LPC55, Version(1, 1, 0), Version(1, 8, 2)),
            migrations,
        )
        self.assertEqual(
            _Migration.get(Variant.LPC55, Version(1, 8, 0), Version(1, 8, 2)),
            migrations,
        )

    def test_update_path_multi(self) -> None:
        from nitrokey.nk3.updates import _Migration
        from nitrokey.trussed import Variant, Version

        migrations = frozenset(
            [_Migration.NRF_IFS_MIGRATION, _Migration.IFS_MIGRATION_V2]
        )

        self.assertEqual(
            _Migration.get(Variant.NRF52, Version(1, 2, 2), Version(1, 8, 2)),
            migrations,
        )
