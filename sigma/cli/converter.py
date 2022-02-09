"""
Sigma converter command line interface.
"""
import sys

import click

from sigma.cli import cli
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
@click.argument("rules", nargs=-1)
def convert(ignore_errors, serializer, rules):
    """
    Convert Sigma rules to various formats using built-in or custom serializers.
    To list built-in serializers, see the `sigma list` command.
    """

    try:
        # Attempt to load the specified serializer
        serializer = Serializer.load(serializer)
    except Exception as exc:
        raise SigmaError(f"failed to load serializer: {exc}")

    for rule_path in rules:
        try:
            # Load the rule
            rule = Rule.from_yaml(rule_path)

            # Serialize the rule and dump the output
            print(serializer.serialize(rule))
        except Exception as exc:
            if not ignore_errors:
                raise SigmaError(f"{rule_path}: {exc}")
            else:
                sys.stderr.write(f"{rule_path}: {exc}\n")

    return 0