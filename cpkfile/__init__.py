"""
Modeled on the patterns in Python3's `zipfile`.
"""
import io
import struct
from dataclasses import dataclass
from pprint import pprint
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

    return table_size


class Table:
    BIG_TABLE_THRESHOLD = 1024

    def __init__(self, fpin, starting_offset):
        self.table_size = _check_table_header(fpin.read(8))
        if self.table_size > Table.BIG_TABLE_THRESHOLD:
            print(f"[INFO] Parsing large table header: {self.table_size} bytes")

        # Save the table into a local copy, so we depend less on the file handle
        self.table_bytes = fpin.read(self.table_size)
        table_buffer = io.BytesIO(self.table_bytes)

        # Parse the table header + column schema
        self.info = Table.Info.from_bytes(table_buffer.read(24))

        def read_string(starting_offset):
            start = self.info.strings_offset + starting_offset
            end = start + self.table_bytes[start:].find(b'\x00')
            return self.table_bytes[start:end].decode('ascii')

        def read_data(starting_offset, length):
            start = self.info.data_offset + starting_offset
            end = start + length
            return self.table_bytes[start:end]

        self.column_schemas = list()
        for n in range(self.info.num_columns):
            cs = Table.ColumnSchema.from_bytes(table_buffer.read(5))
            cs.name = read_string(cs.name_ptr)
            cs.maybe_read_constant(table_buffer, read_string, read_data)

            self.column_schemas.append(cs)

        # Parse the table content (row data)
        if table_buffer.tell() != self.info.rows_offset:
            print(f"[WARN] offset for row data differs: expected {self.info.rows_offset}, current position {table_buffer.tell()}")
            table_buffer.seek(self.info.rows_offset)

        self.rows = list()
        for n in range(self.info.num_rows):
            row = Table.Row.from_(self.column_schemas, table_buffer)

    @dataclass
    class Info:
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
            return Table.Info(rows_offset, strings_offset, data_offset, table_name_ptr, num_columns, row_length,
                              num_rows)

    class ColumnSchema:
        @staticmethod
        def from_bytes(b: bytes):
            cs = Table.ColumnSchema()
            (cs.flags, cs.name_ptr) = struct.unpack('>sI', b)

            return cs

        def maybe_read_constant(self, buffer, read_string, read_data):
            is_zero_constant = int.from_bytes(self.flags) & 0xF0 == 0x10
            is_data_constant = int.from_bytes(self.flags) & 0xF0 == 0x30
            is_per_row       = int.from_bytes(self.flags) & 0xF0 == 0x50

            if is_zero_constant:
                self.constant = 0
            elif is_data_constant:
                result = self.read_data_from(buffer)
                self.constant = result[0]

                # 0x0A: uint32 string pointer
                if int.from_bytes(self.flags) & 0x0F == 0x0A:
                    self.constant = read_string(result[0])
                # 0x0B: two uint32's, data pointer + data length
                elif int.from_bytes(self.flags) & 0x0F == 0x0B:
                    self.constant = read_data(result[0], result[1])
            elif is_per_row:
                return
            else:
                raise ValueError(f"Unidentified type_flag: {self.flags:02x}")

        def _as_struct_format(self) -> str:
            type_flag = int.from_bytes(self.flags) & 0x0F
            if type_flag == 0x00 or type_flag == 0x01:
                return '>B'
            elif type_flag == 0x02 or type_flag == 0x03:
                return '>H'
            elif type_flag == 0x04 or type_flag == 0x05:
                return '>L'
            elif type_flag == 0x06 or type_flag == 0x07:
                return '>Q'
            elif type_flag == 0x08:
                return '>f'
            elif type_flag == 0x0A:
                return '>L'
            elif type_flag == 0x0B:
                return '>LL'
            else:
                raise ValueError(f"Unidentified type_flag: {self.flags:02x}")

        def read_data_from(self, buffer):
            if hasattr(self, "constant"):
                return self.constant

            b = buffer.read(struct.calcsize(self._as_struct_format()))
            return struct.unpack(self._as_struct_format(), b)

        def __str__(self):
            info_str = f"Flags: {self.flags:02x}\n"
            if hasattr(self, 'name'):
                info_str += f"Name: {self.name}\n"
            else:
                info_str += f"Name Offset: {self.name_ptr}\n"
            if hasattr(self, "constant"):
                info_str += f"Value: {self.constant}\n"

    class Row:
        @staticmethod
        def from_(column_schemas: Iterable, buffer):
            row = Table.Row()
            row.entries = {}

            for cs in column_schemas:
                cell_data = cs.read_data_from(buffer)
                row.entries[cs.name] = cell_data

            # TODO: Remove references to pprint, to keep translation size small
            pprint(row.entries)
            return row


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
            t = Table(fp, fp.tell())
            print(t)

            fp.seek(16)
            table_size = _check_table_header(fp.read(8))
            print(f"[INFO] Table header .table_size: {table_size}")

            ti = Table.Info.from_bytes(fp.read(24))
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
