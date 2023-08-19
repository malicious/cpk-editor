import click

from bfscript import BinaryFile


@click.command()
@click.option('--position', required=True, type=int)
@click.option('--count', default=1, show_default=True, type=int)
@click.option('--opcode', default=0, show_default=True, type=int)
@click.option('--operand', default=0, show_default=True, type=int)
@click.argument('filename', type=click.Path(exists=True))
def inject(position, count, opcode, operand, filename):
    script = BinaryFile.from_json(filename)
    script.inject_instruction(position, count, opcode, operand)
    script.to_json(filename + f"-{position}")


if __name__ == '__main__':
    inject()
