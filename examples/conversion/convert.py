#!/usr/bin/env python3
import argparse

from sigma.schema import Rule
from sigma.serializer import Serializer

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--serializer", "-s", required=True, help="Path to a serializer configuration"
    )
    parser.add_argument("rule", help="Path to a YAML rule file")
    args = parser.parse_args()

    try:
        serializer = Serializer.from_yaml(args.serializer)
        rule = Rule.from_yaml(args.rule)

        print(serializer.serialize(rule))
    except FileNotFoundError as exc:
        parser.error(str(exc))
