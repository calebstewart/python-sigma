import sys
from typing import List

import click

from sigma.cli import cli
from sigma.schema import Rule
from sigma.serializer import Serializer


@cli.group()
def validate():
    """Validate Sigma rule or serializer schema"""


@validate.command()
@click.argument("rules", nargs=-1)
def rule(rules):
    """Validate the schema conformancy of Sigma rule(s).

    \b
    RULES File paths to rules for validation
    """

    failed = 0
    for rule_path in rules:
        try:
            Rule.from_yaml(rule_path)
        except Exception as exc:
            failed += 1
            print(f"{rule_path}: {exc}", file=sys.stderr)

    print(f"{len(rules)-failed} of {len(rules)} passed validation ({failed} failed)")


@validate.command()
@click.argument("serializers", nargs=-1)
def serializer(serializers: List[str]):
    """Validate the schema conformancy of Sigma serializer(s).

    \b
    SERIALIZERS Name, path or fully-qualified class name of serializers to validate
    """

    failed = 0
    for name in serializers:
        try:
            Serializer.load(name)
        except Exception as exc:
            failed += 1
            print(f"{name}: {exc}", file=sys.stderr)

    print(
        f"{len(serializers)-failed} of {len(serializers)} passed validation ({failed} failed)"
    )
