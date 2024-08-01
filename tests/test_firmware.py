import unittest

from nitrokey.trussed import FirmwareContainer, Model, Variant, parse_firmware_image


class TestFirmwareContainer(unittest.TestCase):
    def test_parse_nk3(self) -> None:
        self._test(Model.NK3, "v1.7.2", [Variant.LPC55, Variant.NRF52])

    def test_parse_nkpk(self) -> None:
        self._test(Model.NKPK, "v1.0.0", [Variant.NRF52])

    def _test(self, model: Model, version: str, variants: list[Variant]) -> None:
        path = f"./tests/data/firmware-{model.name.lower()}-{version}.zip"
        container = FirmwareContainer.parse(path, model)
        self.assertEqual(str(container.version), version)
        self.assertEqual(str(container.pynitrokey), "v0.4.35")
        self.assertEqual(set(variants), set(container.images))

        for variant, data in container.images.items():
            metadata = parse_firmware_image(variant, data, model)
            self.assertEqual(str(metadata.version), version)
            self.assertEqual(metadata.signed_by, "Nitrokey")
            self.assertTrue(metadata.signed_by_nitrokey)
