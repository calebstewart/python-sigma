import os
import glob
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
from sigma.errors import SigmaError, SerializerValidationError
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
def deploy(deployment_spec: IO, url: str, username: str, password: str, dry_run: bool):
    """Use the given serializer to convert all rules defined in the deployment
    specification and upload directly to an ElasticSearch instance.

    \b
    DEPLOYMENT_SPEC\tPath to a deployment specification YAML file.
    """

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
        logger.info("%s: loading rules", key)
        rules = load_rules_from_paths(rule_paths)

        if not rules:
            logger.info("%s: skipping empty section", key)
            continue

        try:
            logger.info("%s: serializing rules", key)
            result = serializer.dumps(
                rules, format="json", pretty=False, ignore_skip=True
            )
        except SigmaError as exc:
            raise SigmaError(f"{key}: rule serialization failed: {exc}") from exc

        if result.strip() == "":
            logger.info("%s: all rules skipped; skipping upload.")
            continue

        if dry_run:
            print(result)
        else:
            logger.info("%s: uploading rules", key)
            r = requests.post(
                f"{url}/api/detection_engine/rules/_import",
                params={"overwrite": "true"},
                headers={"kbn-xsrf": "true"},
                auth=(username, password),
                files={
                    "file": ("rules.ndjson", StringIO(result)),
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
            raise SigmaError(f"{path}: no such file or directory")

    return rules
