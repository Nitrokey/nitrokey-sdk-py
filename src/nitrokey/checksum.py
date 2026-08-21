import hashlib
import io
from enum import Enum


class _FileEndings(str, Enum):
    IHEX = ".ihex"
    BIN = ".bin"


class FirmwareChecksum:
    def __init__(self, name: str, content: bytes) -> None:
        self.name = name.lower()
        self.content = content

    def _hash_ihex(self, ihex_content: bytes) -> bytes:
        segments = []  # list of (address, bytes)
        base_addr = 0

        with io.StringIO(ihex_content.decode()) as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                if line[0] != ":":
                    raise ValueError(f"Line {lineno}: missing ':' start code")

                raw = bytes.fromhex(line[1:])
                byte_count = raw[0]
                addr = int.from_bytes(raw[1:3], "big")
                rec_type = raw[3]
                data = raw[4 : 4 + byte_count]
                checksum = raw[4 + byte_count]

                calc = (-(sum(raw[: 4 + byte_count]))) & 0xFF
                if calc != checksum:
                    raise ValueError(
                        f"Line {lineno}: bad checksum (got {checksum:02X}, expected {calc:02X})"
                    )

                if rec_type == 0x00:  # data
                    segments.append((base_addr + addr, data))
                elif rec_type == 0x01:  # EOF
                    break
                elif rec_type == 0x02:  # EAS
                    seg_val = int.from_bytes(data, "big")
                    base_addr = seg_val << 4
                else:
                    raise ValueError(f"Line {lineno}: unknown record type {rec_type:02X}")

        if not segments:
            return hashlib.sha256(b"").digest()

        min_addr = min(addr for addr, _ in segments)
        max_addr = max(addr + len(d) for addr, d in segments)

        out = bytearray(b"\xff" * (max_addr - min_addr))
        for addr, d in segments:
            start = addr - min_addr
            out[start : start + len(d)] = d

        return self._hash_bin(out)

    def _hash_bin(self, bin_content: bytes | bytearray) -> bytes:
        return hashlib.sha256(bin_content).digest()

    def calculate_checksum(self) -> bytes:
        """.bin firmwares are using with the NRF52 chipsets while .ihex is used with LPC55.
        For NRF52 firmware, the checksum is made by a direct cryptographic hash over the file.
        For LPC55 firmware, the metadata and certificate block is ignored during checksum calculation"""
        if self.name.endswith(_FileEndings.IHEX):
            return self._hash_ihex(self.content)
        elif self.name.endswith(_FileEndings.BIN):
            return self._hash_bin(self.content)

        raise ValueError("Invalid file ending for firmware")
