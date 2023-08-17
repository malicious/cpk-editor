import click

from cpkfile import CpkFile

@click.command()
@click.option('--count', default=1, help='Number of greetings.')
@click.option('--name', prompt='Your name',
              help='The person to greet.')
def hello(count, name):
    for x in range(count):
        test_obj = CpkFile()
        click.echo(f"Hello {name}! Here's a test_obj: {test_obj}")

if __name__ == '__main__':
    hello()

