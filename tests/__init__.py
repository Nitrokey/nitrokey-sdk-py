import unittest
from types import ModuleType


class TestBasic(unittest.TestCase):
    def test_import(self):
        import nitrokey

        self.assertIsInstance(nitrokey, ModuleType)


if __name__ == "__main__":
    unittest.main()
