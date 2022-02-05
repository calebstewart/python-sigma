"""
Sigma converter command line interface.
"""
import argparse
import importlib.resources

from sigma.schema import Rule
from sigma.serializer import Serializer


def convert():
    """Entrypoint for the conversion command line interface"""

    parser = argparse.ArgumentParser(
        description="Convert Sigma rules to a variety of formats"
    )
    parser.add_argument(
        "--list-builtin",
        "-l",
        action="store_true",
        help="List built-in serializer names and exit",
    )
    parser.add_argument(
        "--serializer",
        "-s",
        help="Name, path or fully-qualified class name of the serializer to use",
    )
    parser.add_argument("rules", nargs="*", help="Path to a sigma rule for conversion")
    args = parser.parse_args()

    if args.list_builtin:
        for item in (
            importlib.resources.files("sigma") / "data" / "serializers"
        ).iterdir():
            if item.is_file() and item.name.endswith(".yml"):
                print(item.name.removesuffix(".yml"))

        return 0
    elif not args.serializer:
        parser.error("no serializer specified")

    try:
        serializer = Serializer.load(args.serializer)
    except Exception as exc:
        parser.error(f"failed to load serializer: {exc}")
        return 1

    for rule_path in args.rules:
        try:
            rule = Rule.from_yaml(rule_path)
            print(serializer.serialize(rule))
        except (FileNotFoundError, PermissionError) as exc:
            parser.error(f"{rule_path}: {exc}")

    return 0
