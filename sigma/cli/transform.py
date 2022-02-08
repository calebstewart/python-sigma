import pathlib
from typing import List, TextIO, Optional

import yaml
import click
from pydantic import ValidationError, parse_obj_as

from sigma.cli import cli
from sigma.errors import SigmaError
from sigma.schema import Rule
from sigma.transform import Transformation


@cli.command()
@click.option(
    "--output", "-o", help="Output path for the converted rule (only for single rule)"
)
@click.option(
    "--output-format",
    "-oF",
    help="Output format string for multiple rule transformations (default: '{}-transformed.yml')",
)
@click.option(
    "--use-basename",
    is_flag=True,
    help="When formatting the output name, only use the basename instead of the full path",
)
@click.option(
    "--config",
    "-c",
    type=click.File("r"),
    help="A YAML file containing a list of transformation configurations to apply",
    required=True,
)
@click.argument("rules", type=click.File("r"), nargs=-1)
def transform(
    output: Optional[str],
    output_format: Optional[str],
    use_basename: bool,
    config: TextIO,
    rules: List[TextIO],
):
    """Transform a list of rules using a list of transforms in a YAML file. This loses the
    selector names within the detection, but should produce a functionally identical rule.
    It is worth putting some human eyes on the conversion, though.

    \b
    RULES paths to rules which you would like to convert
    """

    try:
        # Load the transformation list
        transforms: List[Transformation] = [
            definition.load()
            for definition in parse_obj_as(
                List[Transformation.Schema], yaml.safe_load(config)
            )
        ]
    except (ValidationError, yaml.YAMLError) as exc:
        raise SigmaError(f"{config.name}: {exc}") from exc

    if output is not None and len(rules) > 1:
        raise SigmaError("expected --output-format for multiple rule transformations")

    if output_format is not None and output is not None:
        raise SigmaError("cannot use --output-format and --output")
    elif output_format is None and output is None:
        raise SigmaError("expected either --output-format or --output")

    for rule_definition in rules:
        try:
            # Load the rule
            rule = Rule.from_sigma(yaml.safe_load(rule_definition))
        except yaml.YAMLError as exc:
            raise SigmaError(f"{rule_definition.name}: {exc}") from exc

        # Transform the rule
        rule = rule.transform(transforms)

        # Construct the output path based on the output and output_format arguments
        output_path = ""
        if output is not None:
            output_path = output
        elif output_format is not None:
            rule_path = pathlib.Path(rule_definition.name)
            if use_basename:
                output_path = output_format.format(rule_path.stem)
            else:
                output_path = output_format.format(rule_path.parent / rule_path.stem)

        try:
            # Dump the transformed rule back to a file
            with open(output_path, "w") as filp:
                yaml.safe_dump(rule.to_sigma(), filp)
        except (FileNotFoundError, PermissionError) as exc:
            raise SigmaError(f"failed to open output path: {output_path}")
