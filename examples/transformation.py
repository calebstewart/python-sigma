#!/usr/bin/env python3
from rich.console import Console

from sigma.schema import Rule
from sigma.transform import Transformation

if __name__ == "__main__":

    console = Console()

    # Loading the sigma rule
    rule = Rule.from_yaml("rule.yml")

    # Construct a transformation
    transform = Transformation.Schema.parse_obj(
        {
            "type": "field_map",
            "mapping": {
                "CommandLine": "my_custom_commandline_field",
            },
        }
    ).load()

    # Apply one or more transformations (in order)
    rule = rule.transform([transform])

    print(repr(rule.detection.expression))
