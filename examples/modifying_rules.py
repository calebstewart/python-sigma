#!/usr/bin/env python3
import yaml
from rich.console import Console

from sigma.schema import Rule

if __name__ == "__main__":

    console = Console()

    # Loading the sigma rule
    rule = Rule.from_yaml("rule.yml")

    # Modify rule properties
    rule.title = "My Custom Title"

    # Save the rule back to disk in sigma format
    with open("rule-modified.yml", "w") as filp:
        yaml.safe_dump(rule.to_sigma(), filp)
