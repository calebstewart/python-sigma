import datetime
import os
import glob
import json
import pathlib
from io import StringIO
import time
from typing import IO, Any, Dict, List
import math

import yaml
import click
import requests
from yaml.error import YAMLError
from pydantic.main import BaseModel
from pydantic.error_wrappers import ValidationError
from rich.progress import track

from sigma import logger
from sigma.cli import cli, aliased_group, error_console
from sigma.util import iter_chunked
from sigma.errors import SkipRule, SigmaError, SerializerValidationError
from sigma.schema import Rule
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
@click.option(
    "--serializer",
    "-s",
    "serializer_name",
    help="The serializer used to create the EQL rule.",
    required=True,
)
@click.option("--username", "-u", help="Elastic User Name", prompt="Elastic User")
@click.option(
    "--password",
    "-p",
    help="Elastic User Password",
    prompt="Elastic Password",
    hide_input=True,
)
@click.option("--url", help="Elastic Base URL", required=True)
@click.option(
    "--count",
    help="The number of times to run the query",
    default=10,
    show_default=True,
    type=int,
)
@click.option(
    "--period",
    help="Amount of time to sleep between query execution",
    default=3.0,
    show_default=True,
    type=float,
)
@click.argument("rule_path", type=pathlib.Path)
def benchmark(
    serializer_name: str,
    username: str,
    password: str,
    url: str,
    rule_path: pathlib.Path,
    count: int,
    period: float,
):
    """Execute a query and retrieve performance benchmarks. The elastic URL must
    be for an Elasticsearch instance and not a Kibana instance.

    \b
    RULE\tThe rule to execute in elastic.
    """

    # Serialize the rule to an EQL Elastic Detection Rule
    serializer = Serializer.load(serializer_name)
    rule = Rule.from_yaml(rule_path)
    elastic_rule: Dict[str, Any] = serializer.serialize(rule)

    target = ",".join(elastic_rule["index"])
    body = {
        "query": elastic_rule["query"],
        "keep_on_completion": False,
        "wait_for_completion_timeout": "10s",
    }

    if "timestamp_override" in elastic_rule:
        body["timestamp_field"] = elastic_rule["timestamp_override"]
        timestamp = elastic_rule["timestamp_override"]
    else:
        timestamp = "@timestamp"

    body["filter"] = {
        "range": {
            "@timestamp": {
                "gte": elastic_rule["from"],
                "lt": "now",
            }
        },
    }

    times = []
    hits = []
    first = True

    logger.debug(
        "beginning rule benchmark with %s query executions and a period of %s",
        count,
        period,
    )

    for _ in track(
        range(count),
        description="Calculating average query time...",
        transient=True,
        console=error_console,
    ):

        if not first:
            # We want this to happen after the first but not after the last
            time.sleep(period)
            first = False

        req = requests.get(
            f"{url.rstrip('/')}/{target}/_eql/search",
            json=body,
            auth=(username, password),
        )
        if not req.ok:
            logger.error(
                "search query failed: %s",
                req.json()["error"]["root_cause"][-1]["reason"],
            )
            return 1

        result = req.json()

        if result.get("is_partial") and not result.get("is_running"):
            logger.warn(
                "query execution returned partial results indicating failure on some shards"
            )
            continue

        if result.get("is_partial") and result.get("is_running"):
            logger.warn("query timed out; deleting async search...")
            search_id = result.get("id")
            requests.delete(f"{url}/_eql/search/{search_id}", auth=(username, password))
            continue

        if result.get("timed_out"):
            logger.warning("query timed out for unknown reason")
            continue

        took = datetime.timedelta(milliseconds=result.get("took"))
        logger.debug(
            "query completed in %s with %s hits.",
            took,
            result.get("hits")["total"]["value"],
        )

        times.append(result.get("took"))
        hits.append(result.get("hits")["total"]["value"])

    if len(times) == 0:
        logger.error("no queries succeeded within the timeout window")
        return 1
    elif len(times) != count:
        logger.warn(
            "only %s of %s queries succeeded within the timeout window",
            len(times),
            count,
        )

    avg_time = datetime.timedelta(milliseconds=sum(times) / len(times))
    avg_hits = sum(hits) / len(hits)
    logger.info(f"average query time: {avg_time}")
    logger.info(f"average hit count: {avg_hits}")


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
@click.option(
    "--all",
    "import_all",
    help="Import all rules instead of only importing new or changed rules",
    is_flag=True,
)
@click.option(
    "--chunk-count",
    type=int,
    help="Number of chunks to divide the rules into for importing",
    default=5,
    show_default=True,
)
@click.option(
    "--chunk-period",
    type=float,
    help="Number of seconds to sleep between chunk uploading",
    default=60.0,
    show_default=True,
)
def deploy(
    deployment_spec: IO,
    url: str,
    username: str,
    password: str,
    dry_run: bool,
    backup: IO[str],
    import_all: bool,
    chunk_count: int,
    chunk_period: float,
):
    """Use the given serializer to convert all rules defined in the deployment
    specification and upload directly to an ElasticSearch instance.

    \b
    DEPLOYMENT_SPEC\tPath to a deployment specification YAML file.
    """

    # Strip slashes so we can reliably construct URLs
    elastic_rules = []
    known_ids = {}
    old_rules = {}

    if not dry_run:
        if not username or not password or not url:
            raise SigmaError("username, password and url must be provided")

        url = url.rstrip("/")

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
    if username and password and url:
        logger.info("exporting existing rules and exceptions")
        r = requests.post(
            f"{url}/api/detection_engine/rules/_export",
            headers={"kbn-xsrf": "true"},
            auth=(username, password),
        )
        if not r.ok:
            logger.error("failed to export existing rules: %s", r.status_code)
            return

        if backup:
            logger.info("writing rule backup file: %s", backup.name)
            with backup:
                for chunk in r.iter_content(chunk_size=8192):
                    backup.write(chunk)

        for line in r.text.splitlines():
            rule = json.loads(line)
            if "rule_id" not in rule:
                continue

            old_rules[rule["rule_id"]] = rule

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
                    serialized = serializer.serialize(rule)

                    # Only upload if the rule is modified
                    if import_all or check_rule_modified(old_rules, serialized):
                        elastic_rules.append(serialized)
                except SkipRule as exc:
                    exc.log(rule)
        except SigmaError as exc:
            raise SigmaError(f"{key}: rule serialization failed: {exc}") from exc

    if dry_run:
        print(
            "\n".join(
                json.dumps(rule)
                for rule in elastic_rules
                if import_all or check_rule_modified(old_rules, rule)
            )
        )
    else:
        logger.info("uploading %s total converted rules", len(elastic_rules))

        # We want to upload over a 5-minute time frame
        chunk_size = math.ceil(len(elastic_rules) / chunk_count)
        first = False

        for chunk in iter_chunked(elastic_rules, chunk_size):

            if not first:
                # We want this to happen after the first but not after the last
                time.sleep(chunk_period)
                first = False

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


def check_rule_modified(
    old_rules: Dict[str, Dict[str, Any]], new_rule: Dict[str, Any]
) -> bool:
    """Check if the new rule exists and has been modified from the list of old rules.
    The old rules should be a mapping of rule_id's to rules.

    :param old_rules: dict mapping rule_id to rule of backed up rules from ELK
    :type old_rules: Dict[str, Dict[str, Any]]
    :param new_rule: a rule which has been serialized
    :type new_rule: Dict[str, Any]
    :returns: True if the rule did not exist or has been modified from the old list
    :rtype: bool
    """

    # The new rule doesn't exist in ELK
    if new_rule["rule_id"] not in old_rules:
        return True

    # Lookup the old rule
    old_rule = old_rules[new_rule["rule_id"]]

    # Iterate over all properties of the new rule
    for key, value in new_rule.items():
        if key == "tags":
            # The sorting of tags is weird sometimes
            value = sorted(value)
            old_rule[key] = sorted(old_rule[key])
        if key == "version":
            # The version is updated by ELK every time a rule is changed,
            # so this isn't important for comparison.
            continue
        # Check if the new rule has changed
        if key not in old_rule or value != old_rule[key]:
            logger.debug(
                "%s: changed: %s: %s -> %s",
                new_rule["rule_id"],
                key,
                repr(value),
                repr(old_rule[key]),
            )
            return True

    return False


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
