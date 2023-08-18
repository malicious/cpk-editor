from bfscript import SectionHeader, Header


def test_valid_file_header():
    in_bytes = b'\x00\x00\x00\x00\x00\x07\x17\x02' \
               b'\x46\x4c\x57\x30\x00\x00\x00\x00' \
               b'\x00\x00\x00\x05\x01\x69\x00\x00' \
               b'\x00\x00\x00\x00\x00\x00\x00\x00'
    h = Header.from_bytes(in_bytes)

    out_bytes = h.to_bytes()
    for n in range(len(in_bytes)):
        assert in_bytes[n] == out_bytes[n]

def test_valid_section_header():
    in_bytes = b'\x00\x00\x00\x01' + b'\x00\x00\x00\x30' + b'\x00\x00\x0d\xa9' + b'\x00\x00\x2c\x50'
    sh = SectionHeader.from_bytes(in_bytes)

    out_bytes = sh.to_bytes()
    for n in range(len(in_bytes)):
        assert in_bytes[n] == out_bytes[n]
