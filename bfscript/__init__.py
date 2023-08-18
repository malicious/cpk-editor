"""
Disassemble logic from Atlus scripts, for the sake of diff'ing.

- https://amicitia.miraheze.org/wiki/BF
- https://github.com/KeykKal/Haven-IDE/blob/master/AtlusScriptLibrary/FlowScriptLanguage/BinaryModel/Structs.cs#L6
"""

import struct
from dataclasses import dataclass
from pprint import pprint


@dataclass
class Header:
    file_type: int
    compression_flag: int
    user_id: int
    file_size: int
    magic: bytes
    runtime_size: int
    sections_count: int
    local_int_variable_count: int
    local_float_variable_count: int
    endianness: int
    unknown_field: int
    padding: bytes

    @staticmethod
    def from_bytes(header_bytes: bytes):
        (file_type, compression_flag, user_id, file_size, magic, runtime_size, sections_count, local_int_variable_count,
         local_float_variable_count, endianness, unknown_field, padding) = struct.unpack(
            '>BBHI4sLLHHHH4s',
            header_bytes)

        if file_type != 0:
            print(f"[WARN] Unidentified file type {file_type:02x}, expected 0 for BF")
        if compression_flag:
            raise ValueError(f"Unexpected compression_flag {compression_flag:02x}")
        if user_id != 0:
            print(f"[WARN] Expected User ID to be 0, got {user_id} instead")
        if magic != b'FLW0':
            raise ValueError(f"Unexpected magic number, got {magic}")
        if sections_count != 5:
            print(f"[DEBUG] Expected 5 type tables per file, got {sections_count}")

        return Header(file_type, compression_flag, user_id, file_size, magic, runtime_size, sections_count,
                      local_int_variable_count, local_float_variable_count, endianness, unknown_field, padding)

    def to_bytes(self) -> bytes:
        return struct.pack('>BBHI4sLLHHHH4s',
                           self.file_type, self.compression_flag, self.user_id, self.file_size, self.magic,
                           self.runtime_size, self.sections_count, self.local_int_variable_count,
                           self.local_float_variable_count, self.endianness, self.unknown_field, self.padding)


@dataclass
class SectionHeader:
    section_type: int
    element_size: int
    element_count: int
    first_element_address: int

    @staticmethod
    def from_bytes(header_bytes):
        (section_type, element_size, element_count, first_element_address) = struct.unpack('>LLLL', header_bytes)

        if first_element_address == 0:
            raise ValueError(f"Section start location is invalid")

        return SectionHeader(section_type, element_size, element_count, first_element_address)

    def to_bytes(self) -> bytes:
        return struct.pack('>LLLL', self.section_type, self.element_size, self.element_count,
                           self.first_element_address)

    def __str__(self):
        def section_type_to_str(st):
            if st == 0:
                return "0: Procedure entries"
            elif st == 1:
                return "1: Label entries"
            elif st == 2:
                return "2: Instruction data"
            elif st == 3:
                return "3: Message script data"
            elif st == 4:
                return "4: String data"
            else:
                return f"{st}: [unrecognized section type]"

        info_str = "Section(\n" \
                   f"  section_type {section_type_to_str(self.section_type)}\n" \
                   f"  elements:         {self.element_count} count, {self.element_size} bytes each\n" \
                   f"  first_element at: 0x{self.first_element_address:04x})"
        return info_str


class LabelSection:
    @dataclass
    class Label:
        name: str
        instruction_index: int

    def __init__(self, header: SectionHeader):
        self.header = header
        self.labels = []

    def read_labels(self, fp, is_little_endian):
        name_len = self.header.element_size - 8

        fp.seek(self.header.first_element_address)
        for n in range(self.header.element_count):
            b = fp.read(self.header.element_size)
            if is_little_endian:
                (name_bytes, instruction_index, reserved) = struct.unpack(f'<{name_len}sLL', b)
            else:
                (name_bytes, instruction_index, reserved) = struct.unpack(f'>{name_len}sLL', b)

            if reserved != 0:
                raise ValueError(f"Found unexpected value for \"reserved\": {reserved}")

            name_end = name_bytes.find(b'\x00')
            name = name_bytes[:name_end].decode('ascii')

            l = LabelSection.Label(name, instruction_index)
            self.labels.append(l)


class BinaryFile:
    def __init__(self, filename):
        with open(filename, "rb") as fp:
            fp.seek(0, 2)
            filesize = fp.tell()
            print(f"BF file size: {filesize}")

            fp.seek(0)
            self.file_header = Header.from_bytes(fp.read(32))

            self.section_headers = []
            for n in range(self.file_header.sections_count):
                sh = SectionHeader.from_bytes(fp.read(16))
                self.section_headers.append(sh)

            # Finally, parse each section, now that we know what the header(s) say
            for sh in self.section_headers:
                if sh.section_type == 0 or sh.section_type == 1:
                    s0 = LabelSection(sh)
                    s0.read_labels(fp, is_little_endian=self.file_header.endianness)
                    pprint(s0.labels)
                else:
                    print(f"TODO: Unimplemented section type {sh.section_type}")
