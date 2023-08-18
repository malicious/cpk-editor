from pprint import pprint

import click

from bfscript import BinaryFile


@click.command()
@click.argument('filename', type=click.Path(exists=True))
def disassemble(filename):
    script = BinaryFile(filename)
    # print(script.file_header)
    # pprint(script.section_headers)


if __name__ == '__main__':
    disassemble()
