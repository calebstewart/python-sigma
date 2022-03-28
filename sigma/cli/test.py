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
@click.argument("rule_file", type=click.File("r"))
@click.option(
    "--stream",
    "-s",
    is_flag=True,
    help="Treat positive and negative arguments as jsonl stream files",
)
@click.option(
    "--positive",
    "-p",
    type=click.File("r"),
    help="Positive test cases (must match to succeed)",
)
@click.option(
    "--negative",
    "-n",
    type=click.File("r"),
    help="Negative test cases (must NOT match to succeed)",
)
def test(
    stream: Optional[bool],
    positive: Optional[IO],
    negative: Optional[IO],
    rule_file: IO,
):
    """Evaluate a rule against test data. If the given rule contains embedded
    test data, it will always be tested against this data. The positive and
    negative arguments can be used to augment embedded testing data as well.

    For the custom test cases, if the file extension is jsonl, the files are
    treated as json list files with one dictionary object per line in the file.
    Otherwise, the given files must consist of a single JSON list object
    containing dictionaries which represent individual events.

    This tool exits with a non-zero status if the rule fails to pass all tests.
    If no test data is defined in the rule and none is provided through arguments,
    then a zero exit status is returned, and a warning is printed.

    \b
    \x08\x08Arguments:
    RULE_FILE\tPath to a Sigma rule file to test
    """

    rule = Rule.from_yaml(rule_file)
    positive_list = get_list_or_stream(positive, stream)
    negative_list = get_list_or_stream(negative, stream)

    try:
        rule.test(positive=positive_list, negative=negative_list)
        logger.info("all tests passed")
    except NoTestData as exc:
        # We don't want to exit with a non-zero status if no test data was provided.
        logger.warn(str(exc))
        return
    except AssertionError as exc:
        raise SigmaError(str(exc))
