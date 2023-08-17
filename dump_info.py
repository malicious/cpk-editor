import click

from cpkfile import CpkFile


@click.command()
@click.argument('filename', type=click.Path(exists=True))
def dump_info(filename):
    cpk = CpkFile.fromLocalPath(filename)
    for file in cpk.infolist():
        print(f"{file.get('DirName')} -- {file.get('FileName')}")


if __name__ == '__main__':
    dump_info()
