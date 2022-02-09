"""
Sigma converter command line interface.
"""
import sys
from typing import List, Optional

import click
from rich.syntax import Syntax

from sigma.cli import cli, console
from sigma.errors import SigmaError
from sigma.schema import Rule
from sigma.serializer import Serializer


@cli.command()
@click.option(
    "--ignore-errors",
    "-i",
    is_flag=True,
    help="Ignore errors when converting rules (default: stop processing after first failure)",
)
@click.option(
    "--serializer",
    "-s",
    help="Name, path or fully-qualified class name of the serializer to use",
    required=True,
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["raw", "yaml", "json", "yml"]),
    help="Format of the output (must be supported by serializer)",
)
@click.option(
    "--pretty",
    "-p",
    is_flag=True,
    help="Pretty-format the output",
)
@click.argument("rules", nargs=-1)
def convert(
    ignore_errors: bool,
    serializer: str,
    format: Optional[str],
    pretty: bool,
    rules: List[str],
):
    """
    Convert Sigma rules to various formats using built-in or custom serializers.
    To list built-in serializers, see the `sigma list` command.
    """

    try:
        # Attempt to load the specified serializer
        serializer: Serializer = Serializer.load(serializer)
    except Exception as exc:
        raise SigmaError(f"failed to load serializer: {exc}")

    rule_list = []
    for rule_path in rules:
        try:
            # Load the rule
            rule = Rule.from_yaml(rule_path)
            rule_list.append(rule)
        except Exception as exc:
            if not ignore_errors:
                raise SigmaError(f"{rule_path}: {exc}")
            else:
                sys.stderr.write(f"{rule_path}: {exc}\n")

    result = serializer.dumps(rule_list, format=format, pretty=pretty)

    if format == "yaml" or format == "yml":
        console.print(Syntax(result, "yaml"))
    elif format == "json":
        console.print(Syntax(result, "json"))
    else:
        console.print(result)

    return 0
