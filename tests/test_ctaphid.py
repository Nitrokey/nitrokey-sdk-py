import unittest
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, Tuple
from unittest import mock

from nitrokey import _VID_NITROKEY
from nitrokey.nk3 import _PID_NK3_DEVICE, NK3
from nitrokey.nkpk import NKPK
from nitrokey.trussed._connection import ctaphid

PATH = "/dev/hidraw0"

_VID_FOREIGN = 0x1050
_PID_FOREIGN = 0x0407


@dataclass
class FakeDescriptor:
    path: str
    vid: int
    pid: int


@contextmanager
def fake_device(vid: int, pid: int) -> Iterator[Tuple[mock.Mock, mock.Mock]]:
    """Pretends that there is a CTAPHID device with the given VID and PID."""
    descriptor = FakeDescriptor(path=PATH, vid=vid, pid=pid)
    with (
        mock.patch.object(ctaphid, "get_descriptor", return_value=descriptor) as get_descriptor,
        mock.patch.object(ctaphid, "open_connection") as open_connection,
        mock.patch.object(ctaphid, "CtapHidDevice") as ctap_hid_device,
    ):
        ctap_hid_device.return_value.descriptor = descriptor
        yield (get_descriptor, open_connection)


class TestOpenCtaphid(unittest.TestCase):
    def test_matching_vid_pid(self) -> None:
        with fake_device(_VID_NITROKEY, _PID_NK3_DEVICE) as (_, open_connection):
            connection = ctaphid.open_ctaphid(PATH, vid=_VID_NITROKEY, pid=_PID_NK3_DEVICE)

            self.assertIsNotNone(connection)
            open_connection.assert_called_once()

    def test_wrong_vid_pid_is_not_opened(self) -> None:
        with fake_device(_VID_FOREIGN, _PID_FOREIGN) as (get_descriptor, open_connection):
            connection = ctaphid.open_ctaphid(PATH, vid=_VID_NITROKEY, pid=_PID_NK3_DEVICE)

            self.assertIsNone(connection)
            get_descriptor.assert_called_once()
            open_connection.assert_not_called()

    def test_path_roundtrip(self) -> None:
        with mock.patch("platform.system", return_value="Windows"):
            for raw in [rb"\\?\hid#vid_20a0&pid_42b2#7&1234&0&0000", b"\\\\?\\hid#caf\xe9"]:
                self.assertEqual(ctaphid._str_to_device_path(ctaphid._device_path_to_str(raw)), raw)


class TestTrussedDeviceOpen(unittest.TestCase):
    def test_open_foreign_device(self) -> None:
        with fake_device(_VID_FOREIGN, _PID_FOREIGN) as (_, open_connection):
            self.assertIsNone(NK3.open(PATH))
            open_connection.assert_not_called()

    def test_open_other_model(self) -> None:
        with fake_device(_VID_NITROKEY, _PID_NK3_DEVICE) as (_, open_connection):
            self.assertIsNone(NKPK.open(PATH))
            open_connection.assert_not_called()

    def test_missing_model_is_not_swallowed(self) -> None:
        with mock.patch.object(NK3, "model", None):
            with self.assertRaises(AttributeError):
                NK3.open(PATH)
