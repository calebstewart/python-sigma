from typing import List, Optional

import click
from rich import box
from rich.table import Table, Column

from sigma.cli import cli, console, aliased_group
from sigma.mitre import Attack
from sigma.errors import SigmaError


@aliased_group(parent=cli)
def mitre():
    """Browse and update the MITRE ATT&CK data cache"""


@mitre.command()
@click.option(
    "--output",
    "-o",
    help="Output path for the downloaded data (default: $XDG_DATA_HOME/sigma/mitre.json)",
)
def update(output: Optional[str]):
    """Update the MITRE ATT&CK data file. The default data file is kept within
    the sigma package, but a data file in $XDG_DATA_HOME/sigma/mitre.json will
    automatically override the built-in data file. If no output path is specified,
    this will be the default output path."""

    try:
        attack = Attack.download(path=output)
    except Exception as exc:
        raise SigmaError(f"{output}: {exc}") from exc

    console.print(
        f"Loaded {len(attack.tactics)} tactics and {len(attack.techniques)} techniques"
    )


@mitre.command()
@click.argument("query", nargs=1, required=False)
def tactic(query: Optional[str]):
    """Lookup a tactic by a simple search (contains on title and ID)."""

    attack = Attack.load()
    table = Table(
        Column("ID", style="cyan"),
        Column("Title", style="italic"),
        Column("URL"),
        box=box.MINIMAL,
    )

    query = query.lower() if query is not None else query

    for tactic in attack.tactics:
        if query is None or (
            query in tactic.id.lower() or query in tactic.title.lower()
        ):
            table.add_row(tactic.id, tactic.title, tactic.url)

    console.print(table)


@mitre.command()
@click.argument("query", nargs=1, required=False)
def technique(query: Optional[str]):
    """Lookup a technique by a simple search (contains on title and ID)."""

    attack = Attack.load()
    table = Table(
        Column("ID", style="cyan"),
        Column("Title", style="italic"),
        Column("URL"),
        box=box.MINIMAL,
    )

    query = query.lower() if query is not None else query

    for technique in attack.techniques:
        if query is None or (
            query in technique.id.lower() or query in technique.title.lower()
        ):
            table.add_row(technique.id, technique.title, technique.url)

    console.print(table)
