import unittest
from pathlib import Path

from nitrokey.checksum import FirmwareChecksum
from nitrokey.trussed import FirmwareContainer, Model, Variant, parse_firmware_image


class TestFirmwareContainer(unittest.TestCase):
    def test_parse_nk3(self) -> None:
        self._test(
            Model.NK3,
            "v1.7.2",
            [Variant.LPC55, Variant.NRF52],
            {
                Variant.LPC55: "51b76ef121d3e44270a65d8fe09165b133ecbdf85601e5dfb9d1cab19a988758",
                Variant.NRF52: "57315be2e84ff6184171c96a09861441047e21b73abdc63a4a9f19fe2ccac3ff",
            },
        )

    def test_parse_nkpk(self) -> None:
        self._test(
            Model.NKPK,
            "v1.0.0",
            [Variant.NRF52],
            {Variant.NRF52: "d4f4dbe7a49e60d6f41b16fb62e8a4430580c2884d09626cb72c47498146f2a1"},
        )

    def _test(
        self, model: Model, version: str, variants: list[Variant], checksum: dict[Variant, str]
    ) -> None:
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
            self.assertEqual(
                metadata.inner_checksum.hex() if metadata.inner_checksum else "", checksum[variant]
            )

    def test_ihex_checksum(self) -> None:
        data_dir = Path("./tests/data")
        container_file = data_dir / "firmware-nk3-v1.7.2.zip"
        ihex_file = data_dir / "firmware-nk3am-nrf52-v1.7.2.ihex"

        container = FirmwareContainer.parse(str(container_file), Model.NK3)
        assert Variant.NRF52 in container.images
        metadata = parse_firmware_image(Variant.NRF52, container.images[Variant.NRF52], Model.NK3)

        checksum = FirmwareChecksum(ihex_file.name, ihex_file.read_bytes()).calculate_checksum()

        self.assertEqual(metadata.inner_checksum, checksum)
