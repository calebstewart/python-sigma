import sys
import json
from typing import Type

import yaml
import click
from rich.syntax import Syntax

from sigma.cli import cli, console, aliased_group
from sigma.errors import SigmaError
from sigma.schema import Rule
from sigma.transform import Transformation
from sigma.serializer import Serializer, get_serializer_class


@aliased_group(parent=cli)
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
@click.option(
    "--examples",
    "-e",
    is_flag=True,
    help="Only show examples",
)
def rule(format: str, examples: bool):
    """Dump the schema for Sigma rules"""

    schema = json.loads(Rule.schema_json())

    if examples:
        schema = schema.get("examples", [])

    if format == "yaml":
        console.print(Syntax(yaml.safe_dump(schema), "yaml"))
    else:
        console.print(Syntax(json.dumps(schema, indent=2), "json"))


@schema.command()
@click.option(
    "--format",
    "-f",
    type=click.Choice(["yaml", "json"]),
    default="yaml",
    help="Format of the schema output",
)
@click.option(
    "--examples",
    "-e",
    is_flag=True,
    help="Only show examples",
)
@click.argument("serializer")
def serializer(format: str, examples: bool, serializer: str):
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

    schema = json.loads(clazz.Schema.schema_json())

    if examples:
        schema = schema.get("examples", [])

    if format == "yaml":
        console.print(Syntax(yaml.safe_dump(schema), "yaml"))
    else:
        console.print(Syntax(json.dumps(schema, indent=2), "json"))


@schema.command()
@click.option(
    "--format",
    "-f",
    type=click.Choice(["yaml", "json"]),
    default="yaml",
    help="Format of the schema output",
)
@click.option(
    "--examples",
    "-e",
    is_flag=True,
    help="Only show examples",
)
@click.argument("name")
def transformation(format: str, examples: bool, name: str):
    """Dump the transformation configuration schema.

    \b
    NAME name of built-in or fully-qualified class name the transformation
    """

    clazz: Type[Transformation] = Transformation.lookup_class(name)

    schema = json.loads(clazz.Schema.schema_json())
    if examples:
        schema = schema.get("examples", [])

    if format == "yaml":
        console.print(Syntax(yaml.safe_dump(schema), "yaml"))
    else:
        console.print(Syntax(json.dumps(schema, indent=2), "json"))
