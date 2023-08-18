from pprint import pprint

import click

from bfscript import CompiledScript


@click.command()
@click.argument('filename', type=click.Path(exists=True))
def disassemble(filename):
    script = CompiledScript(filename)
    # print(script.file_header)
    # pprint(script.section_headers)


if __name__ == '__main__':
    disassemble()
