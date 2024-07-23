import unittest
from types import ModuleType


class TestBasic(unittest.TestCase):
    def test_import(self):
        import nitrokey
        import nitrokey.nk3
        import nitrokey.nkpk
        import nitrokey.trussed
        import nitrokey.updates

        self.assertIsInstance(nitrokey, ModuleType)

    def test_list_nk3(self):
        from nitrokey.nk3 import list

        list()

    def test_list_nkpk(self):
        from nitrokey.nkpk import list

        list()


class TestNk3Updates(unittest.TestCase):
    def test_update_path_default(self):
        from nitrokey.nk3.updates import UpdatePath
        from nitrokey.trussed.bootloader import Variant
        from nitrokey.trussed.utils import Version

        self.assertEquals(
            UpdatePath.create(Variant.NRF52, Version(1, 0, 0), Version(1, 1, 0)),
            UpdatePath.default,
        )

    def test_update_path_match(self):
        from nitrokey.nk3.updates import UpdatePath
        from nitrokey.trussed.bootloader import Variant
        from nitrokey.trussed.utils import Version

        self.assertEquals(
            UpdatePath.create(Variant.NRF52, Version(1, 2, 2), Version(1, 3, 0)),
            UpdatePath.nRF_IFS_Migration_v1_3,
        )
        self.assertEquals(
            UpdatePath.create(Variant.NRF52, Version(1, 0, 0), Version(1, 3, 0)),
            UpdatePath.nRF_IFS_Migration_v1_3,
        )
        self.assertEquals(
            UpdatePath.create(Variant.NRF52, None, Version(1, 3, 0)),
            UpdatePath.nRF_IFS_Migration_v1_3,
        )


if __name__ == "__main__":
    unittest.main()
