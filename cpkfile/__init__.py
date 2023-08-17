"""
Modeled on the patterns in Python3's `zipfile`.
"""
import io
import struct
from dataclasses import dataclass
from typing import Iterable


class CpkInfo:
    def __init__(self, toc_data):
        self.toc_data = toc_data

    def get(self, s):
        return self.toc_data[s]


def _check_file_header(header_bytes: bytes):
    (magic, unknown_0xff, packet_size) = struct.unpack('<4sIQ', header_bytes)
    if magic != b'CPK ':
        raise ValueError(f"CPK file header magic invalid: {repr(header_bytes[0:4])}")
    if unknown_0xff != 0x000000ff:
        raise ValueError(f"CPK file header padding 1 invalid: {header_bytes[4:8].hex()}")

    return packet_size


def _check_file_header_close_marker(fp, end_of_table_offset):
    # Done reading; check our offsets by reading table size aligned to 2 KB boundary
    aligned_offset = 2048 * int((end_of_table_offset + 2048) / 2048)
    assert aligned_offset >= end_of_table_offset

    fp.seek(aligned_offset - 6)
    termination_bytes = fp.read(6)
    if termination_bytes != b'(c)CRI':
        print(f"[WARN] End of CPK header looks corrupt: {termination_bytes}")


def _check_toc_header(header_bytes: bytes):
    (magic, unknown_0xff, packet_size) = struct.unpack('<4sIQ', header_bytes)
    if magic != b'TOC ':
        raise ValueError(f"TOC table header magic invalid: {repr(header_bytes[0:4])}")
    if unknown_0xff != 0x000000ff:
        raise ValueError(f"TOC table header padding 1 invalid: {header_bytes[4:8].hex()}")

    return packet_size


def _check_table_header(header_bytes: bytes):
    (magic, table_size) = struct.unpack('>4sI', header_bytes)
    if magic != b'@UTF':
        # TODO: Try decryption, too
        raise ValueError(f"CPK table header magic invalid: {repr(header_bytes[0:4])}")

    return table_size


class Table:
    BIG_TABLE_THRESHOLD = 2048

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
            cs.read_data = read_data
            cs.read_string = read_string

            cs.maybe_read_constant(table_buffer)
            cs.name = read_string(cs.name_ptr)

            self.column_schemas.append(cs)

        # Parse the table content (row data)
        if table_buffer.tell() != self.info.rows_offset:
            print(
                f"[WARN] offset for row data differs: expected {self.info.rows_offset}, current position {table_buffer.tell()}")
            table_buffer.seek(self.info.rows_offset)

        self.infos = list()
        self.rows = self.infos  # TODO: Make these different for CPK header vs TOC table

        for n in range(self.info.num_rows):
            toc_row_data = {}
            for cs in self.column_schemas:
                cell_data = cs.get_cell(table_buffer)
                toc_row_data[cs.name] = cell_data

            info = CpkInfo(toc_row_data)
            self.infos.append(info)

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
        """
        Unpack the column schema

        Sources:

        - https://gist.github.com/unknownbrackets/78c4631a4091044d381432ffb7f1bae4
        """

        @staticmethod
        def from_bytes(b: bytes):
            (flags, name_ptr) = struct.unpack('>sI', b)
            return Table.ColumnSchema(flags, name_ptr)

        def __init__(self, flags, name_ptr):
            self.flags = flags
            self.name_ptr = name_ptr

            def fake_read_data(offset, length):
                return f"[placeholder for fake data, offset: {offset} + length: {length}]"

            def fake_read_string(offset):
                return f"[placeholder for null-terminated string, offset: {offset}]"

            self.read_data = fake_read_data
            self.read_string = fake_read_string

        def maybe_read_constant(self, buffer):
            is_zero_constant = int.from_bytes(self.flags) & 0xF0 == 0x10
            is_data_constant = int.from_bytes(self.flags) & 0xF0 == 0x30
            is_per_row = int.from_bytes(self.flags) & 0xF0 == 0x50

            if is_zero_constant:
                self.constant = 0
            elif is_data_constant:
                self.constant = self._read_data_from(buffer)
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

        def _read_data_from(self, buffer):
            b = buffer.read(struct.calcsize(self._as_struct_format()))
            result = struct.unpack(self._as_struct_format(), b)

            # 0x0A: uint32 string pointer
            if int.from_bytes(self.flags) & 0x0F == 0x0A:
                return self.read_string(result[0])
            # 0x0B: two uint32's, data pointer + data length
            elif int.from_bytes(self.flags) & 0x0F == 0x0B:
                return self.read_data(result[0], result[1])
            else:
                # in normal times, just unpack the one-element tuple
                return result[0]

        def get_cell(self, row_data):
            if hasattr(self, "constant"):
                return self.constant

            return self._read_data_from(row_data)

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
        def from_(column_schemas: Iterable, row_data):
            row = Table.Row()
            row.entries = {}

            for cs in column_schemas:
                cell_data = cs.get_cell(row_data)
                row.entries[cs.name] = cell_data

            # TODO: Remove references to pprint, to keep translation size small
            # pprint(row.entries)
            return row


class CpkFile:
    def __init__(self, name, infos):
        self.name = name
        self.infos = infos

    @classmethod
    def fromLocalPath(cls, filename):
        with open(filename, "rb") as fp:
            # Seek to the end of the file to figure out the file size
            fp.seek(0, 2)
            filesize = fp.tell()
            print(f"CPK file size: {filesize}")

            # Read the file header + CPK table
            fp.seek(0)
            _check_file_header(fp.read(16))

            file_header_table = Table(fp, fp.tell())
            if len(file_header_table.rows) != 1:
                raise ValueError(f"Somehow found multiple rows ({len(file_header_table.rows)}) in CPK file header")

            _check_file_header_close_marker(fp, 16 + file_header_table.table_size)

            # Read later tables, starting with TOC
            fp.seek(file_header_table.rows[0].get('TocOffset'))
            _check_toc_header(fp.read(16))

            toc_table = Table(fp, file_header_table.rows[0].get('TocOffset'))
            if file_header_table.rows[0].get('Files') != len(toc_table.rows):
                raise ValueError(
                    f"[ERROR] number of files doesn't match: found {len(toc_table.rows)} / expected {file_header_table.rows[0].entries['Files']}")

            return cls(filename, toc_table.infos)

    def infolist(self) -> Iterable[CpkInfo]:
        return self.infos

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
