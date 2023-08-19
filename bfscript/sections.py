"""
Special handling for sections we're trying to understand

- https://github.com/KeykKal/Haven-IDE/blob/master/AtlusScriptLibrary/FlowScriptLanguage/BinaryModel/Structs.cs#L6
"""
import dataclasses
import struct
from dataclasses import dataclass

import jsonpickle


class LabelSection:
    @dataclass
    class Label:
        name: str
        instruction_index: int

    @staticmethod
    def from_binary(fpin, sh, is_little_endian):
        s0 = LabelSection()
        s0.name_len = sh.element_size - 8
        s0.is_little_endian = is_little_endian
        s0.labels = []

        fpin.seek(sh.first_element_address)
        for n in range(sh.element_count):
            b = fpin.read(sh.element_size)
            if s0.is_little_endian:
                (name_bytes, instruction_index, reserved) = struct.unpack(f'<{s0.name_len}sLL', b)
            else:
                (name_bytes, instruction_index, reserved) = struct.unpack(f'>{s0.name_len}sLL', b)

            if reserved != 0:
                raise ValueError(f"Found unexpected value for \"reserved\": {reserved}")

            name_end = name_bytes.find(b'\x00')
            name = name_bytes[:name_end].decode('ascii')

            l = LabelSection.Label(name, instruction_index)
            s0.labels.append(l)

        return s0

    def to_bytes(self) -> bytes:
        encoded_labels = []
        for label in self.labels:
            name_bytes = label.name.encode('ascii')
            padded_name_bytes = name_bytes + b'\x00' * (self.name_len - len(name_bytes))
            if self.is_little_endian:
                b = struct.pack(f'<{self.name_len}sLL', padded_name_bytes, label.instruction_index, 0)
            else:
                b = struct.pack(f'>{self.name_len}sLL', padded_name_bytes, label.instruction_index, 0)
            encoded_labels.append(b)

        return b''.join(encoded_labels)

    @staticmethod
    def from_json_ish(j):
        return jsonpickle.Unpickler().restore(j)

    def to_json_ish(self):
        return jsonpickle.Pickler().flatten(self)


known_opcodes = {
    0: ('PUSHI', 'Push integer value to the stack'),
    1: ('PUSHF', 'Push float value to the stack'),
    2: ('PUSHIX', 'Push the value of a global indexed integer to the stack'),
    3: ('PUSHIF', 'Push the value of a global indexed float to the stack'),
    4: ('PUSHREG', 'Push result of a native function onto the stack' \
                   'Push the value of the register to the stack. Used to store COMM return values'),
    5: ('POPIX', 'Pop a value off the stack and assign it to a global indexed integer'),
    6: ('POPFX', 'Pop a value off the stack and assign it to a global indexed float'),
    7: ('PROC', 'Start of procedure'),
    8: ('COMM', 'Communicate with game through calling a native registered function'),
    9: ('END', 'Jumps to the return address'),
    10: ('JUMP', 'Jump to a procedure by index'),
    11: ('CALL', 'Call into a procedure by index'),
    12: ('RUN', 'Run script. Not supported by any game'),
    13: ('GOTO', 'Jump to a label by index'),
    14: ('ADD', 'Add 2 values by popping them off the stack and pushing the return value to the stack'),
    15: ('SUB', 'Subtract 2 values by popping them off the stack and pushing the return value to the stack'),
    16: ('MUL', 'Multiply 2 values by popping them off the stack and pushing the return value to the stack'),
    17: ('DIV', 'Divide 2 values by popping them off the stack and pushing the return value to the stack'),
    18: ('MINUS', 'Negate one value by popping it off the stack and pushing the return value to the stack'),
    19: ('NOT', 'Logical NOT one value by popping it off the stack and pushing the return value to the stack'),
    20: ('OR', 'Logical OR 2 values by popping them off the stack and pushing the return value to the stack'),
    21: ('AND', 'Logical AND 2 values by popping them off the stack and pushing the return value to the stack'),
    22: ('EQ', 'Check 2 values for equality by popping them off the stack and pushing the return value to the stack'),
    23: ('NEQ', 'Check 2 values for non-equality by popping them off the stack and pushing the return value to the stack'),
    24: ('S', 'Check if the first value is smaller than the second value by popping them off the stack and pushing the return value to the stack'),
    25: ('L', 'Check if the first value is larger than the second value by popping them off the stack and pushing the return value to the stack'),
    26: ('SE', 'Check if the first value is smaller than or equal to the second value by popping them off the stack and pushing the return value to the stack'),
    27: ('LE', 'Check if the first value is larger than or equal to the second value by popping them off the stack and pushing the return value to the stack'),
    28: ('IF', 'Pop a value off the stack and check if it isn\'t zero. If it is zero then jump to the specified label by index'),
    29: ('PUSHIS', 'Push a short integer value to the stack'),
    30: ('PUSHLIX', 'Push the value of a local indexed int to the stack'),
    31: ('PUSHLFX', 'Push the value of a local indexed float to the stack'),
    32: ('POPLIX', 'Pop a value off the stack and assign it to a local indexed integer'),
    33: ('POPLFX', 'Pop a value off the stack and assign it to a local indexed float'),
    34: ('PUSHSTR', 'Push the start index of a null terminated string in the string table to the stack'),
}

known_opcode_names = {known_opcodes[key][0]: key for key in known_opcodes}


@dataclass
class Instruction:
    opcode: int
    operand: int

    @staticmethod
    def from_bytes(b: bytes):
        (opcode, operand) = struct.unpack('>HH', b)
        return Instruction(opcode, operand)

    def to_bytes(self) -> bytes:
        return struct.pack('>HH', self.opcode, self.operand)

    @staticmethod
    def from_json_ish(j_in):
        if 'opcode_name' in j_in:
            opcode = known_opcode_names[j_in['opcode_name']]
        else:
            opcode = j_in['opcode']

        i = Instruction(opcode, j_in['operand'])

        for field in ['comment', 'operand_int', 'operand_float']:
            if field in j_in:
                setattr(i, field, j_in[field])

        return i

    def to_json_ish(self):
        result_dict = {}
        result_dict['comment'] = str(self)

        for field in ['comment', 'instruction_index', 'operand_int', 'operand_float']:
            if hasattr(self, field):
                result_dict[field] = getattr(self, field)

        if self.opcode in known_opcodes:
            result_dict['opcode_name'] = known_opcodes[self.opcode][0]
        else:
            result_dict['opcode'] = self.opcode

        result_dict['operand'] = self.operand

        return result_dict

    def __str__(self):
        if self.opcode in known_opcodes:
            return f"{known_opcodes[self.opcode][0]}   {self.operand:04x}"

        return f"OPCODE({self.opcode})   {self.operand:04x}"


class InstructionDataSection:
    def update_proc_names(self, name_lookup_fn):
        for instruction in self.instructions:
            if instruction.opcode == known_opcode_names["PROC"]:
                instruction.comment = f"PROC {name_lookup_fn(instruction.operand)}"

    @staticmethod
    def from_binary(fpin, sh):
        if sh.element_size != 4:
            raise ValueError(f"Trying to parse instructions section, but element size isn't 4")

        s0 = InstructionDataSection()
        s0.instructions = []

        fpin.seek(sh.first_element_address)
        instruction_index = 0
        while instruction_index < sh.element_count:
            next_bytes = fpin.read(sh.element_size)
            next_instruction = Instruction.from_bytes(next_bytes)
            s0.instructions.append(next_instruction)

            next_instruction.instruction_index = instruction_index
            instruction_index += 1

            if next_instruction.opcode == known_opcode_names["PUSHI"]:
                next_next_bytes = fpin.read(sh.element_size)
                (operand_int,) = struct.unpack('>L', next_next_bytes)
                next_instruction.operand_int = operand_int

                next_next_instruction = Instruction.from_bytes(next_next_bytes)
                s0.instructions.append(next_next_instruction)

                next_next_instruction.comment = f"operand for previous PUSHI instruction: {operand_int:08x}"
                next_next_instruction.instruction_index = instruction_index
                instruction_index += 1

            elif next_instruction.opcode == known_opcode_names["PUSHF"]:
                next_next_bytes = fpin.read(sh.element_size)
                (operand_float,) = struct.unpack('>f', next_next_bytes)
                next_instruction.operand_float = operand_float

                next_next_instruction = Instruction.from_bytes(next_next_bytes)
                s0.instructions.append(next_next_instruction)

                next_next_instruction.comment = f"operand for previous PUSHF instruction: {operand_float}"
                next_next_instruction.instruction_index = instruction_index
                instruction_index += 1

        return s0

    def to_bytes(self) -> bytes:
        return b''.join([instr.to_bytes() for instr in self.instructions])

    @staticmethod
    def from_json_ish(j):
        s0 = InstructionDataSection()
        s0.instructions = []

        for instruction in j:
            next_instruction = Instruction.from_json_ish(instruction)
            s0.instructions.append(next_instruction)

        return s0

    def to_json_ish(self):
        flattened_instructions = []
        for i in self.instructions:
            flattened_i = dataclasses.asdict(i)
            if isinstance(i, Instruction):
                flattened_i = i.to_json_ish()

            flattened_instructions.append(flattened_i)

        return flattened_instructions
