import click

from bfscript import BinaryFile


@click.command()
@click.argument('filename', type=click.Path(exists=True))
def reassemble(filename):
    script2 = BinaryFile.from_json(filename)
    script2.to_binary(filename + ".BF")


if __name__ == '__main__':
    reassemble()
