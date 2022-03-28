import os
import glob
import json
import pathlib
import functools
from io import StringIO
from typing import IO, Any, Dict, List, Tuple, Iterable, Iterator, Optional

import yaml
import click
import requests
from eql.utils import ParserConfig
from eql.engine import PythonEngine
from eql.errors import EqlError
from eql.parser import parse_query
from yaml.error import YAMLError
from pydantic.main import BaseModel
from pydantic.error_wrappers import ValidationError

from sigma import logger
from sigma.cli import cli, aliased_group
from sigma.util import iter_chunked, joined_iterator
from sigma.errors import SkipRule, SigmaError, SerializerValidationError
from sigma.schema import Rule, RuleTestData
from sigma.grammar import FieldComparison
from sigma.cli.test import get_list_or_stream
from sigma.transform import FieldMap, FieldFuzzyMap
from sigma.serializer import Serializer
from sigma.serializer.elastic import ElasticSecurityRule


class ElasticDeploymentSpec(BaseModel):
    """Definition of serializers and rules for an elastic deployment."""

    serializers: Dict[str, ElasticSecurityRule.Schema]
    rules: Dict[str, List[pathlib.Path]]


@aliased_group(parent=cli, name="elastic")
def elastic():
    """Interact directly with an Elastic Search instance"""


@elastic.command()
@click.argument("serializer_name", type=str)
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
    serializer_name: str,
    rule_file: IO,
):
    """Convert the given rule to an EQL format and then test the rule validity
    using the Python eql module. This command requires the eql extra dependency
    to be installed. The arguments are similar to the base "sigma test" command
    but will first serialize the rule then test the resulting EQL query.

    \b
    \x08\x08Arguments:
    SERIALIZER  Name or path to a valid EQL-based serializer config.
    RULE        Path to a valid Sigma rule.
    """

    serializer = Serializer.load(serializer_name)
    rule = Rule.from_yaml(rule_file)
    converted = serializer.serialize(rule)

    if isinstance(converted, dict):
        # This means we used an es-rule serializer
        eql_query = converted.get("query")
    elif isinstance(converted, str):
        # This means we used an eql  serializer
        eql_query = converted
    else:
        # Uh-oh, bad serializer...
        raise SigmaError(
            "invalid serialization format (expected dictionary or string). Is this an EQL or es-rule serializer?"
        )

    print(eql_query)

    # Pull the built-in test data from the rule, if it exists
    if isinstance(rule.test_data, RuleTestData):
        positive_cases = rule.test_data.positive
        negative_cases = rule.test_data.negative
    else:
        positive_cases = []
        negative_cases = []

    # Also load the command-line test data
    if positive:
        positive_cases = joined_iterator(
            positive_cases, get_list_or_stream(positive, stream)
        )
    if negative:
        negative_cases = joined_iterator(
            negative_cases, get_list_or_stream(negative, stream)
        )

    # Ensure we have some tests
    if not positive_cases and not negative_cases:
        raise SigmaError("no test cases")

    # Tell the eql package to parse rules according to elasticsearch syntax
    with ParserConfig(elasticsearch_syntax=True):
        # Execute the positive tests
        positive_hits, positive_total = execute_eql_query_tests(
            serializer, rule, eql_query, positive_cases
        )
        if positive_hits != positive_total:
            raise SigmaError(
                f"{positive_hits} of {positive_total} positive cases matched."
            )

        # Execute the negative tests
        negative_hits, negative_total = execute_eql_query_tests(
            serializer, rule, eql_query, negative_cases
        )
        if negative_hits != 0:
            raise SigmaError(
                f"{negative_hits} of {negative_total} negative cases matched."
            )

    logger.info(
        f"{positive_total+negative_total} test cases [green]passed[/green]",
        extra={"markup": True},
    )


@elastic.command()
@click.argument("deployment_spec", type=click.File())
@click.option(
    "--username",
    "-u",
    help="Elastic User Name",
    envvar="ELASTIC_USER",
)
@click.option(
    "--password",
    "-p",
    help="Elastic User Password",
    envvar="ELASTIC_PASS",
)
@click.option(
    "--url",
    help="Elastic Base URL",
    envvar="ELASTIC_URL",
)
@click.option(
    "--dry-run",
    "-d",
    is_flag=True,
    help="Dump the resulting JSON serialized rules",
)
@click.option(
    "--backup",
    "-b",
    help="Backup existing rules via a rule export to the specified file prior to import.",
    type=click.File("wb"),
)
def deploy(
    deployment_spec: IO,
    url: str,
    username: str,
    password: str,
    dry_run: bool,
    backup: IO[str],
):
    """Use the given serializer to convert all rules defined in the deployment
    specification and upload directly to an ElasticSearch instance.

    \b
    DEPLOYMENT_SPEC\tPath to a deployment specification YAML file.
    """

    # Strip slashes so we can reliably construct URLs
    url = url.rstrip("/")

    if not dry_run:
        if not username or not password or not url:
            raise SigmaError("username, password and url must be provided")

    # Load the deployment specification
    with deployment_spec:
        try:
            logger.info("loading deployment specification")
            schema = yaml.safe_load(deployment_spec)
            spec = ElasticDeploymentSpec.parse_obj(schema)
        except (YAMLError, ValidationError) as exc:
            raise SigmaError(f"failed to parse deployment spec: {exc}")

    # Build the serializers
    logger.info("building serializers from schema")
    serializers: Dict[str, Serializer] = {}
    for key, value in spec.serializers.items():
        try:
            serializers[key] = Serializer.load(value.base, value)
        except SerializerValidationError as exc:
            raise SigmaError(f"serializer: {key}: {exc}") from exc

    # Export Elastic Security Rules before uploading as a backup
    if not dry_run and backup:
        logger.info("exporting existing rules and exceptions")
        r = requests.post(
            f"{url}/api/detection_engine/rules/_export",
            headers={"kbn-xsrf": "true"},
            auth=(username, password),
            stream=True,
        )
        if not r.ok:
            logger.error("failed to export existing rules: %s", r.status_code)
            return

        logger.info("writing rule backup file: %s", backup.name)
        with backup:
            for chunk in r.iter_content(chunk_size=8192):
                backup.write(chunk)

    elastic_rules = []
    known_ids = {}

    for key, rule_paths in spec.rules.items():

        # Grab the corresponding serializer or load it if possible
        if key not in serializers:
            try:
                serializer = Serializer.load(key)
            except SigmaError as exc:
                raise SigmaError(f"serializer: {key}: {exc}") from exc
        else:
            serializer = serializers[key]

        # Load the rules for this serializer
        logger.info("loading and serializing '%s' rules", key)
        rules = load_rules_from_paths(rule_paths)

        try:
            for rule in rules:
                # Verify we don't have the same rule in multiple sections
                if rule.id in known_ids:
                    raise SigmaError(
                        f"rule '{rule.id}' found in multiple sections: {key}, {known_ids[rule.id]}"
                    )
                else:
                    known_ids[rule.id] = key

                try:
                    # Serialize the rule
                    elastic_rules.append(serializer.serialize(rule))
                except SkipRule as exc:
                    exc.log(rule)
        except SigmaError as exc:
            raise SigmaError(f"{key}: rule serialization failed: {exc}") from exc

    if dry_run:
        print("\n".join(json.dumps(rule) for rule in elastic_rules))
    else:
        logger.info("uploading %s total converted rules", len(elastic_rules))

        for chunk in iter_chunked(elastic_rules, 50):
            logger.info("  uploading chunk of %s rules", len(chunk))
            r = requests.post(
                f"{url}/api/detection_engine/rules/_import",
                params={"overwrite": "true"},
                headers={"kbn-xsrf": "true"},
                auth=(username, password),
                files={
                    "file": (
                        "rules.ndjson",
                        StringIO("\n".join(json.dumps(rule) for rule in chunk)),
                    ),
                },
            )

            if not r.ok:
                raise SigmaError(
                    f"rule upload failed: elastic returned status code: {r.status_code}: {r.text}"
                )


def load_rules_from_paths(rule_paths) -> List[Rule]:

    rules = []

    for path in rule_paths:
        if "*" in str(path):
            new_paths = glob.glob(str(path), recursive=True)
            rules.extend(load_rules_from_paths(new_paths))
        elif os.path.isdir(path):
            new_paths = list(pathlib.Path(path).rglob("*.yml"))
            rules.extend(load_rules_from_paths(new_paths))
        elif os.path.isfile(path):
            try:
                rules.append(Rule.from_yaml(path))
            except SigmaError as exc:
                logger.warn("%s: ignoring malformed rule: %s", path, exc)
        else:
            logger.warn("%s: ignoring non-existent rule path", path)

    return rules


def eql_rule_event_hook(event, *, results: Dict[str, Any]):
    """Called once for each of the results from executing an EQL query with execute_eql_query_tests.
    This simply tracks the number of results or "hits" that a given query has against a set of test
    data. The count is stored in results["hits"]."""
    if isinstance(event, list):
        results["hits"] += len(event)
    else:
        results["hits"] += 1


def apply_mapping_to_all_cases(
    serializer: Serializer,
    rule: Rule,
    results: Dict[str, Any],
    cases: Iterable[Dict[str, Any]],
) -> Iterable[Dict[str, Any]]:
    """Apply any field mappings to the given test case data, expand the dictionary if needed
    and yield the new modified cases. This also tracks the total number of cases in results["total"].
    """

    for case in cases:
        for transform in serializer.transforms:
            if not isinstance(transform, FieldMap) and not isinstance(
                transform, FieldFuzzyMap
            ):
                continue

            # This is a dumb way to transform the data, but :shrug:
            keys = list(case.keys())
            for key in keys:
                try:
                    expression = transform.transform_expression(
                        rule, FieldComparison(field=key, value="")
                    )
                except SkipRule:
                    continue
                case[expression.field] = case[key]
                del case[key]

        case = expand_dict(case)
        case["event_type"] = "process"
        results["total"] += 1
        print(case)
        yield case


def expand_dict(d):
    """Expand a dictionary from something like {"a.b.c": 1, "a.d": 2} to
    something like {"a": {"b": {"c": 1}}, "d": 2}."""

    keys = list(d.keys())
    for key in keys:
        if "." in key:
            *new_keys, value_name = key.split(".")
            child = d
            for k in new_keys:
                if k not in child:
                    child[k] = {}
                child = child[k]

            child[value_name] = d[key]
            del d[key]

    return d


def execute_eql_query_tests(
    serializer: Serializer, rule: Rule, query: str, cases: Iterator[Dict[str, Any]]
) -> Tuple[int, int]:
    """Execute the given query against the test case data and collect the results"""

    # Dictionary of results accessible to callbacks
    results = {"hits": 0, "total": 0}

    # Construct the EQL engine for executing the query
    engine = PythonEngine(
        {
            "hooks": [functools.partial(eql_rule_event_hook, results=results)],
            "flatten": True,
        }
    )

    # Parse and add the query
    with engine.schema:
        try:
            engine.add_query(parse_query(query, implied_any=True, implied_base=True))
        except EqlError as exc:
            raise SigmaError(f"failed to add eql query to engine: {exc}") from exc

    # Stream events through the engine
    engine.stream_events(
        apply_mapping_to_all_cases(serializer, rule, results, cases), finalize=True
    )

    # Return results
    return results["hits"], results["total"]
