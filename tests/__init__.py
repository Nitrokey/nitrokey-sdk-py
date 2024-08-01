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
        from nitrokey.nk3.updates import UpdatePath
        from nitrokey.trussed import Variant, Version

        self.assertEqual(
            UpdatePath.create(Variant.NRF52, Version(1, 0, 0), Version(1, 1, 0)),
            UpdatePath.default,
        )

    def test_update_path_match(self) -> None:
        from nitrokey.nk3.updates import UpdatePath
        from nitrokey.trussed import Variant, Version

        self.assertEqual(
            UpdatePath.create(Variant.NRF52, Version(1, 2, 2), Version(1, 3, 0)),
            UpdatePath.nRF_IFS_Migration_v1_3,
        )
        self.assertEqual(
            UpdatePath.create(Variant.NRF52, Version(1, 0, 0), Version(1, 3, 0)),
            UpdatePath.nRF_IFS_Migration_v1_3,
        )
        self.assertEqual(
            UpdatePath.create(Variant.NRF52, None, Version(1, 3, 0)),
            UpdatePath.nRF_IFS_Migration_v1_3,
        )
