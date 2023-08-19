"""
Disassemble logic from Atlus scripts, for the sake of diff'ing.

- https://amicitia.miraheze.org/wiki/BF
"""
import json
import struct
from dataclasses import dataclass
from typing import Dict

import jsonpickle

from bfscript.sections import LabelSection, InstructionDataSection


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

    @staticmethod
    def from_json_ish(j):
        return jsonpickle.unpickler.Unpickler().restore(j)

    def to_json_ish(self):
        return jsonpickle.pickler.Pickler().flatten(self)


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

    @staticmethod
    def from_json_ish(j_in):
        del j_in["section_type_str"]
        return jsonpickle.unpickler.Unpickler().restore(j_in)

    def to_json_ish(self):
        j_out = jsonpickle.pickler.Pickler().flatten(self)
        j_out["section_type_str"] = SectionHeader._section_type_to_str(self.section_type)
        return j_out

    @staticmethod
    def _section_type_to_str(st):
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

    def __str__(self):
        info_str = "Section(\n" \
                   f"  section_type {SectionHeader._section_type_to_str(self.section_type)}\n" \
                   f"  elements:         {self.element_count} count, {self.element_size} bytes each\n" \
                   f"  first_element at: 0x{self.first_element_address:04x})"
        return info_str


class DefaultSection:
    def __init__(self):
        self.elements = []

    @staticmethod
    def from_bytes(fpin, section_header):
        s0 = DefaultSection()
        for n in range(section_header.element_count):
            b = fpin.read(section_header.element_size)
            s0.elements.append(b)

        return s0

    def to_bytes(self) -> bytes:
        return b''.join(self.elements)

    @staticmethod
    def from_json_ish(j: Dict):
        s0 = DefaultSection()
        for element in j:
            b = bytes.fromhex(element)
            s0.elements.append(b)

        return s0

    def to_json_ish(self):
        return [element.hex() for element in self.elements]


class BinaryFile:
    @staticmethod
    def from_binary(filename):
        with open(filename, "rb") as fp:
            bf = BinaryFile()

            bf.file_header = Header.from_bytes(fp.read(32))

            bf.section_headers = []
            for n in range(bf.file_header.sections_count):
                sh = SectionHeader.from_bytes(fp.read(16))
                bf.section_headers.append(sh)

            # Finally, parse each section, now that we know what the header(s) say
            bf.sections = []
            for sh in bf.section_headers:
                if sh.section_type == 0 or sh.section_type == 1:
                    s0 = LabelSection.from_binary(fp, sh, is_little_endian=bf.file_header.endianness)
                    bf.sections.append(s0)
                elif sh.section_type == 2:
                    s0 = InstructionDataSection.from_binary(fp, sh)
                    bf.sections.append(s0)
                else:
                    s0 = DefaultSection.from_bytes(fp, sh)
                    bf.sections.append(s0)

            return bf

    def to_binary(self, filename):
        with open(filename, "wb") as fpout:
            fpout.write(self.file_header.to_bytes())

            for sh in self.section_headers:
                fpout.write(sh.to_bytes())

            for s0 in self.sections:
                fpout.write(s0.to_bytes())

    @staticmethod
    def from_json(filename):
        with open(filename, "r") as fpin:
            fpin_j = json.load(fpin)
            bf = BinaryFile()

            bf.file_header = Header.from_json_ish(fpin_j['header'])

            bf.section_headers = []
            bf.sections = []

            for n in range(bf.file_header.sections_count):
                sh = SectionHeader.from_json_ish(fpin_j['section_headers'][n])
                bf.section_headers.append(sh)

                if sh.section_type == 0 or sh.section_type == 1:
                    s0 = LabelSection.from_json_ish(fpin_j['sections'][n])
                    bf.sections.append(s0)
                elif sh.section_type == 2:
                    s0 = InstructionDataSection.from_json_ish(fpin_j['sections'][n])
                    bf.sections.append(s0)
                else:
                    s0 = DefaultSection.from_json_ish(fpin_j['sections'][n])
                    bf.sections.append(s0)

            return bf

    def to_json(self, filename):
        with open(filename, "w") as fpout:
            json_output = {}
            json_output['header'] = self.file_header.to_json_ish()
            json_output['section_headers'] = [sh.to_json_ish() for sh in self.section_headers]
            json_output['sections'] = [s0.to_json_ish() for s0 in self.sections]

            json.dump(json_output, fpout)
