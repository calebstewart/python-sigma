from typing import Optional

import click
from rich import box
from rich.table import Table, Column

from sigma.cli import cli, console, aliased_group, error_console
from sigma.mitre import Attack


@aliased_group(parent=cli)
def mitre():
    """Browse and update the MITRE ATT&CK data cache. Sigma uses MITRE ATT&CK
    data during conversion to formats which support more specific technique
    and tactic data. In those cases, tags such as 'attack.t00001' are converted
    along with other rule data to include the technique and/or tactic information.
    By default, the sigma command will load cached MITRE ATT&CK data from the
    package resources, but you can update this data at any time from the MITRE/cti
    GitHub repository with the 'mitre update' command. If a data file exists in
    $XDG_DATA_HOME/sigma/mitre.json, it will be used instead of the embedded data
    file."""


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

    attack = Attack.download(path=output)

    console.print(
        f"Loaded {len(attack.tactics)} tactics and {len(attack.techniques)} techniques"
    )


@mitre.command()
@click.argument("query", nargs=1, required=False)
@click.pass_context
def tactic(ctx: click.Context, query: Optional[str]):
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

    if not table:
        error_console.print("No matching tactics found.")
        ctx.exit(1)

    console.print(table)


@mitre.command()
@click.argument("query", nargs=1, required=False)
@click.pass_context
def technique(ctx: click.Context, query: Optional[str]):
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

    if not table:
        error_console.print("No matching techniques found.")
        ctx.exit(1)

    console.print(table)
