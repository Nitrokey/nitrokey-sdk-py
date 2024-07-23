import unittest
from types import ModuleType


class TestBasic(unittest.TestCase):
    def test_import(self):
        import nitrokey
        import nitrokey.helpers
        import nitrokey.nk3
        import nitrokey.nkpk
        import nitrokey.trussed
        import nitrokey.updates

        self.assertIsInstance(nitrokey, ModuleType)


if __name__ == "__main__":
    unittest.main()
