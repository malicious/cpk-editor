"""
Special handling for sections we're trying to understand

- https://github.com/KeykKal/Haven-IDE/blob/master/AtlusScriptLibrary/FlowScriptLanguage/BinaryModel/Structs.cs#L6
"""
import struct
from dataclasses import dataclass

from bfscript import SectionHeader


def section_header_to_string(self):
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


SectionHeader.__str__ = section_header_to_string


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


class Opcodes:
    PUSHI = 0
    PUSHF = 1

    @staticmethod
    def _lookup_opcode(opcode: int) -> str:
        opcodes_dict = {
            0: 'PUSHI  ',  # Push integer value to the stack
            1: 'PUSHF  ',  # Push float value to the stack
            2: 'PUSHIX ',  # Push the value of a global indexed integer to the stack.
            3: 'PUSHIF ',  # Push the value of a global indexed float to the stack.
            4: 'PUSHREG',  # Push result of a native function onto the stack /
            # Push the value of the register to the stack. Used to store COMM return values.
            5: 'POPIX  ',  # Pop a value off the stack and assign it to a global indexed integer.
            6: 'POPFX  ',  # Pop a value off the stack and assign it to a global indexed float.
            7: 'PROC   ',  # Start of procedure.
            8: 'COMM   ',  # Communicate with game through calling a native registered function.
            9: 'END    ',  # Jumps to the return address.
            10: 'JUMP   ',  # Jump to a procedure by index.
            11: 'CALL   ',  # Call into a procedure by index.
            12: 'RUN    ',  # Run script. Not supported by any game.
            13: 'GOTO   ',  # Jump to a label by index.
            14: 'ADD    ',  # Add 2 values by popping them off the stack and pushing the return value to the stack.
            15: 'SUB    ',  # Subtract 2 values by popping them off the stack and pushing the return value to the stack.
            16: 'MUL    ',  # Multiply 2 values by popping them off the stack and pushing the return value to the stack.
            17: 'DIV    ',  # Divide 2 values by popping them off the stack and pushing the return value to the stack.
            18: 'MINUS  ',  # Negate one value by popping it off the stack and pushing the return value to the stack.
            19: 'NOT    ',
            # Logical NOT one value by popping it off the stack and pushing the return value to the stack.
            20: 'OR     ',
            # Logical OR 2 values by popping them off the stack and pushing the return value to the stack.
            21: 'AND    ',
            # Logical AND 2 values by popping them off the stack and pushing the return value to the stack.
            22: 'EQ     ',
            # Check 2 values for equality by popping them off the stack and pushing the return value to the stack.
            23: 'NEQ    ',
            # Check 2 values for non-equality by popping them off the stack and pushing the return value to the stack.
            24: 'S      ',
            # Check if the first value is smaller than the second value by popping them off the stack and pushing the return value to the stack.
            25: 'L      ',
            # Check if the first value is larger than the second value by popping them off the stack and pushing the return value to the stack.
            26: 'SE     ',
            # Check if the first value is smaller than or equal to the second value by popping them off the stack and pushing the return value to the stack.
            27: 'LE     ',
            # Check if the first value is larger than or equal to the second value by popping them off the stack and pushing the return value to the stack.
            28: 'IF     ',
            # Pop a value off the stack and check if it isn't zero. If it is zero then jump to the specified label by index
            29: 'PUSHIS ',  # Push a short integer value to the stack.
            30: 'PUSHLIX',  # Push the value of a local indexed int to the stack.
            31: 'PUSHLFX',  # Push the value of a local indexed float to the stack.
            32: 'POPLIX ',  # Pop a value off the stack and assign it to a local indexed integer.
            33: 'POPLFX ',  # Pop a value off the stack and assign it to a local indexed float.
            34: 'PUSHSTR',  # Push the start index of a null terminated string in the string table to the stack
        }

        if opcode in opcodes_dict:
            return opcodes_dict[opcode]

        return f"NOT_IMPL{{{opcode}}}"

    @dataclass
    class NormalInstruction:
        opcode: int
        operand: int

        @staticmethod
        def from_bytes(b: bytes):
            (opcode, operand) = struct.unpack('>HH', b)
            return Opcodes.NormalInstruction(opcode, operand)

        def __str__(self):
            return f"{Opcodes._lookup_opcode(self.opcode)} {self.operand:04x}"

    @dataclass
    class PushInt(NormalInstruction):
        operand_int: int

        @staticmethod
        def with_operand(previous_instruction, b: bytes):
            result = struct.unpack('>L', b)
            return Opcodes.PushInt(
                opcode=previous_instruction.opcode,
                operand=previous_instruction.operand,
                operand_int=result[0]
            )

        def __str__(self):
            return f"{Opcodes._lookup_opcode(self.opcode)} {self.operand_int:08x}"

    @dataclass
    class PushFloat(NormalInstruction):
        operand_float: float

        @staticmethod
        def with_operand(previous_instruction, b: bytes):
            result = struct.unpack('>f', b)
            return Opcodes.PushFloat(
                opcode=previous_instruction.opcode,
                operand=previous_instruction.operand,
                operand_float=result[0]
            )

        def __str__(self):
            return f"{Opcodes._lookup_opcode(self.opcode)} {self.operand_float}"


class InstructionDataSection:
    def __init__(self, header: SectionHeader):
        self.header = header
        self.instructions = []

    def read_instructions(self, fp):
        if self.header.element_size != 4:
            raise ValueError(f"Trying to parse instructions section, but element size isn't 4")

        fp.seek(self.header.first_element_address)
        bytes_remaining = self.header.element_count * self.header.element_size

        while bytes_remaining > 0:
            next_bytes = fp.read(self.header.element_size)
            bytes_remaining -= self.header.element_size
            next_instruction = Opcodes.NormalInstruction.from_bytes(next_bytes)

            if next_instruction.opcode == Opcodes.PUSHI:
                operand_bytes = fp.read(4)
                bytes_remaining -= 4
                next_instruction = Opcodes.PushInt.with_operand(next_instruction, operand_bytes)
            elif next_instruction.opcode == Opcodes.PUSHF:
                operand_bytes = fp.read(4)
                bytes_remaining -= 4
                next_instruction = Opcodes.PushFloat.with_operand(next_instruction, operand_bytes)

            self.instructions.append(next_instruction)


class MessageScriptSection:
    @dataclass
    class Header:
        file_type: int
        format: int
        user_id: int
        file_size: int
        magic: bytes
        ext_size: int
        reloc_table_offset: int
        reloc_table_size: int
        dialog_count: int
        is_relocated: int
        version: int

        @staticmethod
        def from_bytes(header_bytes: bytes):
            (file_type, format, user_id, file_size, magic, ext_size, reloc_table_offset, reloc_table_size, dialog_count,
             is_relocated, version) = struct.unpack('>BBHI4sLLLLHH', header_bytes)

            if magic != b'MSG1':
                if magic == b'1GSM':
                    (file_type, format, user_id, file_size, magic, ext_size, reloc_table_offset, reloc_table_size,
                     dialog_count,
                     is_relocated, version) = struct.unpack('<BBHI4sLLLLHH', header_bytes)
                else:
                    raise ValueError(f"Unexpected magic number, got {magic}")

            return MessageScriptSection.Header(file_type, format, user_id, file_size, magic, ext_size,
                                               reloc_table_offset, reloc_table_size,
                                               dialog_count, is_relocated, version)

        def to_bytes(self) -> bytes:
            return struct.pack('>BBHI4sLLLLHH', self.file_type, self.format, self.user_id, self.file_size, self.magic,
                               self.ext_size, self.reloc_table_offset, self.reloc_table_size, self.dialog_count,
                               self.is_relocated, self.version)

    def __init__(self, fp):
        self.header = MessageScriptSection.Header.from_bytes(fp.read(32))
        self.unparsed_file = fp.read(self.header.file_size)