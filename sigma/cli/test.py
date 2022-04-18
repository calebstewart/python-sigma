import json
from typing import IO, Any, Dict, Iterable, Optional, Generator
from json.decoder import JSONDecodeError

import click

from sigma import logger
from sigma.cli import cli, aliased_group
from sigma.errors import NoTestData, SigmaError
from sigma.schema import Rule


def stream_json_list(filp: IO) -> Generator[Dict[str, Any], None, None]:

    for line in filp:
        if not line.startswith("{"):
            continue
        yield json.loads(line)


def get_list_or_stream(
    filp: Optional[IO], stream: Optional[bool]
) -> Iterable[Dict[str, Any]]:

    if filp is not None:
        if filp.name.endswith("jsonl") or stream:
            return stream_json_list(filp)
        else:
            try:
                result = json.loads(filp.read())
                if not isinstance(result, list):
                    raise SigmaError(f"{filp.name}: test case file is not a list")

                return result
            except JSONDecodeError as exc:
                raise SigmaError(f"{filp.name}: failed to parse json: {exc}") from exc

    return []


@cli.command()
@click.argument("rule_file", nargs=-1, type=click.File("r"))
def test(
    rule_file: IO,
):
    """Evaluate a rule against test data. The test data must be embedded
    within the rule itself in the custom "test_data" field. The rule can
    contain lists of positive and negative rules to test.

    If any test data for any rule fails evaluation, a non-zero exit status
    is returned. Otherwise, a zero exit status is returned. Rules with no
    embedded test data are treated as passing tests, but a warning is
    printed.

    \b
    \x08\x08Arguments:
    RULE_FILE\tPath to a Sigma rule file to test
    """

    result = 0

    for filp in rule_file:
        try:
            rule = Rule.from_yaml(filp)
        except SigmaError as exc:
            logger.error(f"{filp.name}: {str(exc)}")
            result = 1
            continue

        try:
            rule.test()
            logger.info("%s: all tests passed", filp.name)
        except NoTestData as exc:
            # We don't want to exit with a non-zero status if no test data was provided.
            logger.warn("%s: %s", filp.name, exc)
        except AssertionError as exc:
            # Show the error and continue other tests.
            logger.error(f"{filp.name}: {str(exc)}")
            result = 1

    return result
