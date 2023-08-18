from pprint import pprint

import click

from bfscript import BinaryFile


@click.command()
@click.argument('filename', type=click.Path(exists=True))
def disassemble(filename):
    """Disassembles {filename} and prints its contents to stdout"""
    script = BinaryFile.from_binary(filename)
    # print(script.file_header)
    # pprint(script.section_headers)


@click.command()
@click.argument('filename', type=click.Path(exists=True))
def dis_re_assemble(filename):
    script = BinaryFile.from_binary(filename)
    script.to_json(filename + ".json")

    script2 = BinaryFile.from_json(filename + ".json")
    script2.to_binary(filename + "-reassembled")


if __name__ == '__main__':
    dis_re_assemble()
