import os
import glob
import json
import pathlib
from io import StringIO
from typing import IO, Dict, List

import yaml
import click
import requests
from yaml.error import YAMLError
from pydantic.main import BaseModel
from pydantic.error_wrappers import ValidationError

from sigma import logger
from sigma.cli import cli, aliased_group
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
