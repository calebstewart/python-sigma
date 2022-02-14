#!/usr/bin/env python3
from rich.console import Console

from sigma.schema import Rule
from sigma.transform import Transformation
from sigma.serializer import Serializer

if __name__ == "__main__":

    console = Console()

    # Loading the sigma rule
    rule = Rule.from_yaml("rule.yml")

    # Load a serializer
    serializer = Serializer.load("eql")

    # Add our own transformation
    serializer.transforms.append(
        Transformation.Schema.parse_obj(
            {
                "type": "field_map",
                "mapping": {"CommandLine": "my_custom_commandline_field"},
            }
        ).load()
    )

    # Serialize the rule
    print(serializer.serialize(rule))
