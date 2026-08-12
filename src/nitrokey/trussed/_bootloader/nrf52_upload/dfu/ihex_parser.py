import io
from typing import BinaryIO


class IhexParser:
    def __init__(self, content: bytes = b"", filename: str = "") -> None:
        self._buf = bytearray(content)
        self.filename = filename

    def loadfile(self, source: str, file_format: str) -> None:
        assert file_format == "hex"
        with open(source, "rb") as fob:
            hexcontent = fob.read()
        self._buf = self._convert_ihex(hexcontent)

    def writebinfile(self, fobj: BinaryIO) -> None:
        fobj.write(self._buf)

    def _convert_ihex(self, ihex_content: bytes) -> bytearray:
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
            return bytearray(b"")

        min_addr = min(addr for addr, _ in segments)
        max_addr = max(addr + len(d) for addr, d in segments)

        out = bytearray(b"\xff" * (max_addr - min_addr))
        for addr, d in segments:
            start = addr - min_addr
            out[start : start + len(d)] = d

        return out
