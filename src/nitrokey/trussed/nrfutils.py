from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from nitrokey.trussed._bootloader.nrf52_upload.dfu.dfu import Dfu
from nitrokey.trussed._bootloader.nrf52_upload.dfu.dfu_transport_serial import DfuTransportSerial
from nitrokey.trussed._bootloader.nrf52_upload.dfu.package import Package
from nitrokey.trussed._bootloader.nrf52_upload.dfu.signing import Signing
from nitrokey.trussed._bootloader.nrf52_upload.exceptions import NordicSemiException


def _int_as_text_to_int(value: str) -> int:
    try:
        if value[:2].lower() == "0x":
            return int(value[2:], 16)
        elif value[:1] == "0":
            return int(value, 8)
        return int(value, 10)
    except ValueError as err:
        raise NordicSemiException("%s is not a valid integer" % value) from err


def keygen(key_file: str) -> None:
    signer = Signing()
    signer.gen_key(key_file)


def pubview(format: str, priv_file: EllipticCurvePrivateKey, out_file: str) -> None:
    signer = Signing(priv_file)
    kstr = signer.get_vk(format, False)
    with open(out_file, "w") as outfile:
        outfile.write(kstr)


def usb_serial(package: str, port: str) -> None:
    flow_control = DfuTransportSerial.DEFAULT_FLOW_CONTROL
    packet_receipt_notification = DfuTransportSerial.DEFAULT_PRN
    baud_rate = DfuTransportSerial.DEFAULT_BAUD_RATE
    ping = False
    timeout = DfuTransportSerial.DEFAULT_TIMEOUT
    serial_backend = DfuTransportSerial(
        com_port=str(port),
        baud_rate=baud_rate,
        flow_control=flow_control,
        prn=packet_receipt_notification,
        do_ping=ping,
        timeout=timeout,
    )
    dfu = Dfu(zip_file_path=package, dfu_transport=serial_backend)
    dfu.dfu_send_images()


def pkg_gen(
    hw_version: int,
    sd_req: str,
    key_file: EllipticCurvePrivateKey,
    out_path: str,
    app_version: Optional[int] = None,
    bootloader_version: Optional[int] = None,
    application: Optional[str] = None,
    bootloader: Optional[str] = None,
    ecdsa_validation: bool = False,
) -> None:
    application_version_internal = app_version if app_version else None
    sd_req_list = []
    try:
        sd_req_list_temp = sd_req.split(",")
        sd_req_list = list(map(_int_as_text_to_int, sd_req_list_temp))
    except ValueError as err:
        raise NordicSemiException(
            "Could not parse value for --sd-req. Hex values should be prefixed with 0x."
        ) from err

    signer = Signing(key_file)
    app_boot_validation = "VALIDATE_ECDSA_P256_SHA256" if ecdsa_validation else None
    package = Package(
        False,
        hw_version,
        application_version_internal,
        bootloader_version,
        sd_req_list,
        [],
        application,
        bootloader,
        None,
        None,
        app_boot_validation,
        signer,
        False,
        False,
        None,
        None,
        None,
        None,
        None,
    )
    package.generate_package(out_path)
