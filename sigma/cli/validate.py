from typing import Any, Dict, List

import click

from sigma import logger
from sigma.cli import cli, console, aliased_group
from sigma.schema import Rule
from sigma.serializer import Serializer


@aliased_group(parent=cli)
def validate():
    """Validate Sigma rule or serializer schema"""


@validate.command()
@click.argument("rules", nargs=-1)
@click.pass_obj
def rule(obj: Dict[str, Any], rules):
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
            if obj.get("traceback"):
                logger.exception(rule_path)
            else:
                logger.warn("%s: %s", rule_path, str(exc))

    console.print(
        f"{len(rules)-failed} of {len(rules)} [green]passed[/green] validation ({failed} [red]failed[/red])"
    )


@validate.command()
@click.argument("serializers", nargs=-1)
@click.pass_obj
def serializer(obj: Dict[str, Any], serializers: List[str]):
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
            if obj.get("traceback"):
                logger.exception(name)
            else:
                logger.warn("%s: %s", name, str(exc))

    console.print(
        f"{len(serializers)-failed} of {len(serializers)} [green]passed[/green] validation ({failed} [red]failed[/red])"
    )
