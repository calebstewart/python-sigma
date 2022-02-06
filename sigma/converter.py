"""
Sigma converter command line interface.
"""
import sys
import json
import argparse
import textwrap
import importlib.resources

import yaml

from sigma.schema import Rule
from sigma.serializer import Serializer


def convert():
    """Entrypoint for the conversion command line interface"""

    parser = argparse.ArgumentParser(
        description="""
            Convert or validate Sigma rules.

            During validation, only errors for rules which fail validation are output.
            During conversion, rule serializations are printed one-per-line for every
            rule provided, and stop at the first failed rule, unless the
            --ignore-errors option is used. A non-zero exit code indicates at least one
            rule failure.
        """
    )
    parser.add_argument(
        "--list-builtin",
        "-l",
        action="store_true",
        help="List built-in serializer names and exit",
    )
    parser.add_argument(
        "--dump-schema",
        choices=["yaml", "json", "yml"],
        help="Dump the sigma rule schema in the selected format",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate the provided rule schema (do not perform conversion)",
    )
    parser.add_argument(
        "--ignore-errors",
        "-i",
        action="store_true",
        help="Ignore errors when converting rules (default: stop processing after first failure)",
    )
    parser.add_argument(
        "--serializer",
        "-s",
        help="Name, path or fully-qualified class name of the serializer to use",
    )
    parser.add_argument("rules", nargs="*", help="Path to a sigma rule for conversion")
    args = parser.parse_args()

    # Dump the sigma rule schema
    if args.dump_schema:
        schema = Rule.schema_json()
        if args.dump_schema in ["yml", "yaml"]:
            print(yaml.safe_dump(json.loads(schema)))
        else:
            print(schema)
        return 0

    if args.list_builtin:
        # Locate all built-in serializer definitions in the reosurces
        for item in (
            importlib.resources.files("sigma") / "data" / "serializers"
        ).iterdir():
            if item.is_file() and item.name.endswith(".yml"):
                print(item.name.removesuffix(".yml"))

        return 0
    elif not args.serializer and not args.validate:
        # Must specify a serializer or request rule validation
        parser.error("no serializer specified")
        return 1
    elif args.serializer:
        try:
            # Attempt to load the specified serializer
            serializer = Serializer.load(args.serializer)
        except Exception as exc:
            parser.error(f"failed to load serializer: {exc}")
            return 1
    else:
        # We are validating the rules, we don't need a serializer
        serializer = None

    for rule_path in args.rules:
        try:
            # Load the rule
            rule = Rule.from_yaml(rule_path)

            if serializer is not None:
                # Serialize the rule and dump the output
                print(serializer.serialize(rule))
            else:
                # Parse the grammar to ensure that the condition
                # is valid as well as the schema
                rule.detection.parse_grammar()

        except Exception as exc:
            sys.stderr.write(f"{rule_path}: {exc}\n")
            if serializer is not None and not args.ignore_errors:
                return 1

    return 0
