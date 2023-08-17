import click
from pprint import pprint

from cpkfile import CpkFile


@click.command()
@click.argument('filename', type=click.Path(exists=True))
def dump_info(filename):
    cpk = CpkFile.fromLocalPath(filename)
    pprint(cpk.infolist())

if __name__ == '__main__':
    dump_info()