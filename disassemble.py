import click

from bfscript import BinaryFile


@click.command()
@click.argument('filename', type=click.Path(exists=True))
def disassemble(filename):
    script = BinaryFile.from_binary(filename)
    script.to_json(filename + ".json")


if __name__ == '__main__':
    disassemble()
