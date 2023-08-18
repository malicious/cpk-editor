import click

from cpkfile import CpkFile
from cpkfile.patch import UnionCpk


@click.command()
@click.argument('filenames', type=click.Path(exists=True), nargs=-1)
def dump_multiple(filenames):
    if len(filenames) < 2:
        raise ValueError("Must pass at least two .CPK files")

    cpk_list = []
    for filename in filenames:
        cpk = CpkFile.fromLocalPath(filename)
        cpk_list.append(cpk)

    ucpk = UnionCpk(cpk_list)
    ucpk.dump_patch_info()


if __name__ == '__main__':
    dump_multiple()
