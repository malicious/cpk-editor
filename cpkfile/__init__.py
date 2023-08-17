"""
Modeled on the patterns in Python3's `zipfile`.
"""
import struct
from dataclasses import dataclass
from typing import Iterable, List


class CpkInfo:
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return f"CpkInfo(name={self.name})"


class FileHeader:
    def __init__(self, header_bytes: bytes):
        self.header_bytes = header_bytes

        (magic, unknown_0xff, packet_size) = struct.unpack('<4sIQ', header_bytes)
        if magic != b'CPK ':
            raise ValueError(f"CPK file header magic invalid: {repr(header_bytes[0:4])}")
        if unknown_0xff != 0x000000ff:
            raise ValueError(f"CPK file header padding 1 invalid: {header_bytes[4:8].hex()}")

        print(f"[INFO] FileHeader.packet_size: {packet_size}")

    def __repr__(self):
        return repr(self.header_bytes)


def _check_table_header(header_bytes: bytes):
    (magic, table_size) = struct.unpack('>4sI', header_bytes)
    if magic != b'@UTF':
        # TODO: Try decryption, too
        raise ValueError(f"CPK table header magic invalid: {repr(header_bytes[0:4])}")

    print(f"[INFO] Table header .table_size: {table_size}")


@dataclass
class TableInfo:
    rows_offset: int
    strings_offset: int
    data_offset: int
    table_name_ptr: int
    num_columns: int
    row_length: int
    num_rows: int

    @staticmethod
    def from_bytes(b: bytes):
        (rows_offset, strings_offset, data_offset, table_name_ptr, num_columns, row_length, num_rows) \
            = struct.unpack('>IIIIHHI', b)
        return TableInfo(rows_offset, strings_offset, data_offset, table_name_ptr, num_columns, row_length, num_rows)

class ColumnInfo:
    pass


class CpkFile:
    def __init__(self, name):
        self.name = name

    @classmethod
    def fromLocalPath(cls, filename):
        with open(filename, "rb") as fp:
            # Seek to the end of the file to figure out the file size
            fp.seek(0, 2)
            filesize = fp.tell()
            print(f"CPK file size: {filesize}")

            fp.seek(0)
            FileHeader(fp.read(16))
            _check_table_header(fp.read(8))
            ti = TableInfo.from_bytes(fp.read(24))
            print(ti)

        return cls(filename)

    def infolist(self) -> Iterable[CpkInfo]:
        return [
            CpkInfo(self.name),
        ]

    def _infolist_str(self, indent=2) -> str:
        info_str = "[\n"
        for cpk_info in self.infolist():
            info_str += " " * indent + str(cpk_info) + ",\n"
        info_str += "]\n"

        return info_str

    def __str__(self):
        info_str = f"CpkFile({self.name})\n"
        info_str += self._infolist_str()

        return info_str
