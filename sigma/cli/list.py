from rich import box
from rich.table import Table, Column

from sigma.cli import cli, console, aliased_group
from sigma.transform import Transformation
from sigma.serializer import get_builtin_serializers


@aliased_group(parent=cli)
def list():
    """List built-in transforms and serializers"""


@list.command()
def serializers():
    """List built-in serializers"""

    table = Table(
        Column("Name", style="blue"),
        Column("Description", style="italic"),
        box=box.MINIMAL,
    )

    for name, description in get_builtin_serializers():
        table.add_row(name, description)

    console.print(table)


@list.command()
def transforms():
    """List built-in transforms"""

    table = Table(
        Column("Name", style="blue"),
        Column("Description", style="italic"),
        box=box.MINIMAL,
    )

    for name, description in Transformation.enumerate_builtin():
        table.add_row(name, description)

    console.print(table)
