"""
Sigma converter command line interface.
"""
import sys
import logging
from typing import Any, Dict, List, Optional

import click
from rich.syntax import Syntax
from rich.logging import RichHandler

from sigma import logging
from sigma.cli import CommandWithVerbosity, cli, console, error_console
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
@click.pass_obj
def convert(
    obj: Dict[str, Any],
    ignore_errors: bool,
    serializer: str,
    format: Optional[str],
    pretty: bool,
    rules: List[str],
):
    """
    Convert Sigma rules to various formats using built-in or custom serializers.
    To list built-in serializers, see the `sigma list` command. If no format is
    given, the default format defined by your serializer will be used to render
    and highlight the resulting output. In general, the pretty argument forces
    formats like JSON to include newlines and indentation to make reading easier.

    If the output is non-interactive (e.g. not a TTY), the serializer output is
    not rendered in any special way. It is simply printed with the built-in print
    function. This is useful when ingesting output with things like `jq`.
    """

    # Attempt to load the specified serializer
    serializer: Serializer = Serializer.load(serializer)

    rule_list = []
    for rule_path in rules:
        try:
            # Load the rule
            rule = Rule.from_yaml(rule_path)
            rule_list.append(rule)
        except Exception as exc:
            if not ignore_errors:
                raise
            if obj.get("traceback"):
                logging.exception(f"failed to load {rule_path}")
            else:
                logging.error(f"{rule_path}: {exc}")

    if ignore_errors:
        logging.warn(
            f"{len(rules) - len(rule_list)} of {len(rules)} [red]failed[/red] conversion.",
            extra={"markup": True},
        )

    result = serializer.dumps(rule_list, format=format, pretty=pretty)

    if format is None:
        format = serializer.DEFAULT_FORMAT

    if not console.is_interactive:
        print(result)
    elif format == "yaml" or format == "yml":
        console.print(Syntax(result, "yaml", word_wrap=True))
    elif format == "json":
        console.print(Syntax(result, "json", word_wrap=True))
    else:
        console.print(result)

    return 0
