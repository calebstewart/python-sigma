import sys
import json
from typing import Type

import yaml
import click

from sigma.cli import cli
from sigma.errors import SigmaError
from sigma.schema import Rule
from sigma.serializer import Serializer, get_serializer_class


@cli.group()
def schema():
    """Dump the schema for rules, serializers, and transforms"""


@schema.command()
@click.option(
    "--format",
    "-f",
    type=click.Choice(["yaml", "json"]),
    default="yaml",
    help="Format of the schema output",
)
def rule(format):
    """Dump the schema for Sigma rules"""

    if format == "yaml":
        print(yaml.safe_dump(json.loads(Rule.schema_json())))
    else:
        print(json.dumps(Rule.schema(), indent=2))


@schema.command()
@click.option(
    "--format",
    "-f",
    type=click.Choice(["yaml", "json"]),
    default="yaml",
    help="Format of the schema output",
)
@click.argument("serializer")
def serializer(format, serializer):
    """Dump the schema for the configuration for the given serializer

    \b
    SERIALIZER the path, name or fully-qualified class name of a serializer
    """

    try:
        clazz: Type[Serializer] = get_serializer_class(serializer)
    except SigmaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return

    if not issubclass(clazz, Serializer):
        print(f"error: {serializer}: not a valid serializer")
        return

    if format == "yaml":
        print(yaml.safe_dump(json.loads(clazz.Schema.schema_json())))
    else:
        print(json.dumps(clazz.Schema.schema(), indent=2))
