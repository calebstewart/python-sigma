import json
import uuid
from enum import Enum
from typing import Any, Set, Dict, List, Union, Literal, ClassVar, Optional, Annotated
from datetime import datetime

import yaml
from pydantic.main import BaseModel
from pydantic.tools import parse_obj_as
from pydantic.fields import Field

from sigma import logger
from sigma.util import CopyableSchema
from sigma.mitre import Attack, Tactic, Technique
from sigma.errors import SkipRule, UnsupportedSerializerFormat
from sigma.schema import Rule, RuleTag
from sigma.grammar import Expression, FieldComparison
from sigma.serializer import TextQuerySerializer, CommonSerializerSchema


class EventQueryLanguage(TextQuerySerializer):
    """Elastic EQL Serializer"""

    class Schema(TextQuerySerializer.Schema):
        """Text Query configuration options which define how to combine the logical expressions
        into the correct query syntax for your detection engine."""

        quote: str = '"{}"'
        """ The character used for literal escapes in strings """
        escape: str = "\\{}"
        """ The character used to escape the following character in a string """
        list_separator: str = ","
        """ The string used to separate list items """
        or_format: str = "{} or {}"
        """ A format string to construct an OR expression (e.g. "{} or {}") """
        and_format: str = "{} and {}"
        """ A format string to construct an AND expression (e.g. "{} or {}") """
        not_format: str = "not {}"
        """ A format string to construct a NOT expression (e.g. "not {}") """
        grouping: str = "({})"
        """ A format string to construct a grouping (e.g. "({})") """
        escaped_characters: str = r'(["\\])'
        """ Characters aside from the quote and escape character that require escaping """
        field_equality: str = "{}: {}"
        """ A format string to test field equality (e.g. "{} == {}") """
        field_like: str = "{}: {}"
        field_lookup: str = "{}: {}"
        field_lookup_regex: str = "{} regex {}"
        field_match: str = "{}: {}"
        """ A format string to test a field with a globbing pattern (e.g. "{}: {}") """
        field_regex: str = "{} regex {}"
        """ A format string to test if a field matches a regex (e.g. "{} match {}")"""
        keyword: str = "{}"
        """ A format string to match a keyword across all fields (e.g. "{}") """
        field_startswith: Optional[str] = "startsWith~({},{})"
        """ A format string to test if a field starts with a string """
        field_endswith: Optional[str] = "endsWith~({},{})"
        """ A format string to test if a field ends with a string """
        field_contains: Optional[str] = "stringContains~({},{})"
        """ A format string to test if a field contains another string """
        field_not_empty: Optional[str] = "?{field} != null"
        """ Test if a field exists """
        prepend_result: str = ""
        """ String to prepend to the resulting query """
        rule_separator: str = "\n"
        """ Separator for when outputting multiple rules to a file """

        class Config(CopyableSchema):
            schema_extra = CommonSerializerSchema.Config.copy_schema({"base": "eql"})

    def serialize(self, rule: Rule, transform: bool = True) -> str:

        if transform:
            rule = rule.transform(self.transforms)

        categories = set()

        def _find_category(e: Expression) -> Expression:
            """Callback which collects the categories from the field comparisons"""

            if not isinstance(e, FieldComparison):
                return e

            try:
                category, _ = e.field.split(".", maxsplit=1)
                categories.add(category)
            except ValueError:
                pass

            return e

        # Lookup all the categories
        rule.detection.expression.visit(_find_category)

        # Serialize the query
        result = super().serialize(rule, transform=False)

        if len(categories) > 1 or not categories:
            category = "any"
        else:
            category = categories.pop()

        return f"{category} where {result}"


class ElasticSecurityActionType(str, Enum):

    SLACK = "slack"
    EMAIL = "email"
    PAGERDUTY = "pagerduty"
    WEBHOOK = "webhook"


class ElasticSecurityBaseAction(BaseModel):
    """Schema for Elastic Security Rule actions"""

    type: ElasticSecurityActionType
    """ The connector type used for sending notifications """
    group: str = "default"
    """ Optionally groups actions by use cases. Use default for alert notifications. """
    id: str
    """ The connector ID """
    tags: List[RuleTag] = list()
    """ List of tags to filter action application. If any of the given tags matches
    a rule, this action will be applied to the rule. If no tags are given, the action
    will be applied to all serialized rules. """

    def to_rule_format(self) -> Dict[str, Any]:
        """Convert this elastic security action into a rule-compliant dictionary"""
        return {
            "action_type_id": f".{self.type.value}",
            "group": self.group,
            "id": self.id,
            "params": {},
        }

    class Config(CopyableSchema):
        schema_extra = {
            "examples": [
                {
                    "type": "action-type",
                    "group": "default",
                    "id": "connector-id",
                    "tags": ["my_custom_tag"],
                }
            ]
        }


class ElasticSecuritySlackAction(ElasticSecurityBaseAction):

    type: Literal[ElasticSecurityActionType.SLACK]
    message: str

    def to_rule_format(self) -> Dict[str, Any]:
        result = super().to_rule_format()
        result["params"].update({"message": self.message})
        return result

    class Config(CopyableSchema):
        schema_extra = ElasticSecurityBaseAction.Config.copy_schema(
            {
                "type": ElasticSecurityActionType.SLACK.value,
                "message": "OH NO! {{ context.rule.name }} FIRED!",
            }
        )


class ElasticSecurityEmailAction(ElasticSecurityBaseAction):

    type: Literal[ElasticSecurityActionType.EMAIL]
    to: Optional[List[str]]
    cc: Optional[List[str]]
    bcc: Optional[List[str]]
    subject: Optional[str]
    message: str

    def to_rule_format(self) -> Dict[str, Any]:
        result = super().to_rule_format()

        if self.to:
            result["params"]["to"] = ";".join(self.to)
        if self.cc:
            result["params"]["cc"] = ";".join(self.cc)
        if self.bcc:
            result["params"]["bcc"] = ";".join(self.bcc)
        if self.subject:
            result["params"]["subject"] = self.subject

        result["params"]["message"] = self.message

        return result

    class Config(CopyableSchema):
        schema_extra = ElasticSecurityBaseAction.Config.copy_schema(
            {
                "type": ElasticSecurityActionType.EMAIL.value,
                "to": "security@company.com",
                "subject": "NEW ALERT",
                "message": "OH NO! {{ context.rule.name }} FIRED!",
            }
        )


class ElasticSecurityWebhookAction(ElasticSecurityBaseAction):

    type: Literal[ElasticSecurityActionType.WEBHOOK]
    body: Any

    def to_rule_format(self) -> Dict[str, Any]:

        result = super().to_rule_format()

        if isinstance(self.body, list) or isinstance(self.body, dict):
            result["params"]["body"] = json.dumps(self.body)
        else:
            result["params"]["body"] = self.body

        return result

    class Config(CopyableSchema):
        schema_extra = ElasticSecurityBaseAction.Config.copy_schema(
            {
                "type": ElasticSecurityActionType.SLACK.value,
                "body": {
                    "my_custom": "data",
                },
            }
        )


class ElasticSecurityPagerDutyAction(ElasticSecurityBaseAction):

    type: Literal[ElasticSecurityActionType.PAGERDUTY]
    severity: str
    event_action: str
    dedup_key: Optional[str]
    timestamp: Optional[datetime]
    component: Optional[str]
    group: Optional[str]
    source: Optional[str]
    summary: Optional[str]
    clazz: Optional[str]

    def to_rule_format(self) -> Dict[str, Any]:
        result = super().to_rule_format()

        result["params"].update(
            {
                "severity": self.severity,
                "eventAction": self.event_action,
            }
        )

        if self.dedup_key:
            result["params"]["dedupKey"] = self.dedup_key
        if self.timestamp:
            result["params"]["timestamp"] = self.timestamp.isoformat()
        if self.component:
            result["params"]["component"] = self.component
        if self.group:
            result["params"]["group"] = self.group
        if self.source:
            result["params"]["source"] = self.source
        if self.summary:
            result["params"]["summary"] = self.summary
        if self.clazz:
            result["params"]["class"] = self.clazz

        return result

    class Config(CopyableSchema):
        schema_extra = ElasticSecurityBaseAction.Config.copy_schema(
            {
                "type": ElasticSecurityActionType.SLACK.value,
                "severity": "Critical",
                "event_action": "trigger",
            }
        )


ElasticSecurityAction = Annotated[
    Union[
        ElasticSecurityWebhookAction,
        ElasticSecurityEmailAction,
        ElasticSecuritySlackAction,
        ElasticSecurityPagerDutyAction,
    ],
    Field(discriminator="type"),
]


class ElasticSecurityRule(EventQueryLanguage):
    """Serialize to a JSON Elastic Security Rule"""

    DEFAULT_FORMAT: ClassVar[Optional[str]] = "json"

    class Schema(EventQueryLanguage.Schema):
        """Elastic Security Rule Configuration Schema"""

        enable_rule: bool = False
        """ Set the enable field in the resulting rule to True """
        interval: str = "5m"
        """ Rule test interval """
        rule_type: str = "eql"
        """ The rule query type """
        output_index: str = ".siem-signals-default"
        """ Output index for rule alerts """
        max_signals: int = 100
        risk_map: Dict[str, int] = {"low": 5, "medium": 35, "high": 65, "critical": 95}
        """ Mapping of sigma rule levels to risk values """
        risk_default: int = 35
        """ Default risk value if the given level is not in the risk map or not provided """
        severity_map: Dict[str, str] = {
            "low": "low",
            "medium": "medium",
            "high": "high",
            "critical": "critical",
            "informational": "low",
        }
        """ Mapping of sigma rule levels to severity values """
        severity_default: str = "medium"
        """ Default severity value if the level is not in the above map """
        timestamp_override: Optional[str] = None
        """ Sets the time field used to query indices. When unspecified, rules query the
        @timestamp field. The source field must be an Elasticsearch date data type. """
        actions: List[ElasticSecurityAction] = []

        class Config(CopyableSchema):
            extra = "forbid"
            schema_extra = CommonSerializerSchema.Config.copy_schema(
                {
                    "base": "es-rule",
                    "enable_rule": True,
                    "interval": "5m",
                    "rule_type": "eql",
                    "output_index": ".siem-signals-default",
                    "max_signals": 100,
                    "risk_map": {"low": 0, "medium": 25, "high": 75, "critical": 100},
                    "risk_default": 10,
                    "timestamp_override": "event.ingested",
                    "actions": [
                        ElasticSecuritySlackAction.Config.schema_extra["examples"][0],
                    ],
                }
            )

    RULE_LANGUAGE_MAP: ClassVar[Dict[str, str]] = {
        "eql": "eql",
        "query": "lucene",
        "threat-match": "lucene",
        "threshold": "lucene",
    }
    """ Mapping of rule types to query languages """

    schema: Schema

    def dumps(
        self,
        rule: List[Rule],
        format: Optional[str] = None,
        pretty: bool = False,
        ignore_skip: bool = False,
    ) -> str:
        """Dump the rule as a string in either JSON or YAML format"""

        serialized = []
        for r in rule:
            try:
                serialized.append(self.serialize(r))
            except SkipRule as exc:
                if ignore_skip:
                    exc.log(r)
                else:
                    raise

        if format is None or format == "json":
            if pretty:
                return "\n".join([json.dumps(s, indent=2) for s in serialized])
            return "\n".join([json.dumps(s) for s in serialized])
        elif format == "yaml" or format == "yml":
            return yaml.safe_dump_all(serialized)
        else:
            raise UnsupportedSerializerFormat(format)

    def serialize(self, rule: Rule, transform: bool = True) -> Dict[str, Any]:
        """Serialize the rule(s) to a dictionary representing an Elastic Security
        EQL rule."""

        if transform:
            rule = rule.transform(self.transforms)

        # Lookup the indices and add extra conditions based on the logsource
        indices, rule = self.schema.logsource.match_rule(rule)
        if not indices:
            indices = [
                "apm-*-transaction",
                "auditbeat-*",
                "endgame-*",
                "filebeat-*",
                "packetbeat-*",
                "winlogbeat-*",
            ]

        # Serialize the rule to an EQL query
        query = super().serialize(rule, transform=False)

        attack = Attack.load()
        tags: Set[str] = set()
        threat: List[Dict[str, Any]] = []
        techniques: Dict[str, Technique] = {}
        tactics: Dict[str, Tactic] = {}

        # Parse MITRE ATTACK techniques and tactics out of the tags
        if rule.tags:
            for tag in rule.tags:
                # MITRE ATTACK tag
                if tag.namespace == "attack":

                    # Tactic name
                    if "_" in tag.name:
                        name = tag.name.replace("_", " ").lower()
                        for tactic in attack.tactics:
                            if tactic.title.lower() == name:
                                tags.add(tactic.id.upper())
                                tactics[tactic.id] = tactic
                                break
                        else:
                            tags.add(tag.name)

                        continue

                    # Tactic ID
                    tactic = attack.get_tactic(tag.name)
                    if tactic is not None:
                        tags.add(tactic.id.upper())
                        tactics[tactic.id] = tactic
                        continue

                    # Technique ID
                    technique = attack.get_technique(tag.name)
                    if technique is not None:
                        tags.add(technique.id.upper())
                        if technique.tactics:
                            for tactic_id in technique.tactics:
                                tactic = attack.get_tactic(tactic_id)
                                if tactic:
                                    tags.add(tactic.title)
                                    tactics[tactic.id] = tactic

                        techniques[technique.id] = technique

                        # Add parent technique for sub-techniques
                        if "." in technique.id:
                            technique = attack.get_technique(technique.id.split(".")[0])
                            if technique is not None:
                                tags.add(technique.id.upper())
                                if technique.tactics:
                                    for tactic_id in technique.tactics:
                                        tactic = attack.get_tactic(tactic_id)
                                        if tactic:
                                            tags.add(tactic.title)
                                            tactics[tactic.id] = tactic
                                techniques[technique.id] = technique

                        continue

                    tags.add(tag.name.upper())
                else:
                    tags.add(str(tag))

        if tactics:
            for tactic in tactics.values():
                definition = {
                    "framework": "MITRE ATT&CK®",
                    "technique": [],
                    "tactic": {
                        "id": tactic.id,
                        "name": tactic.title,
                        "reference": tactic.url,
                    },
                }

                for technique in techniques.values():
                    # Only directly process main techniques
                    if "." in technique.id:
                        continue

                    # Only techniques under this tactic
                    if technique.tactics is None or tactic.id not in technique.tactics:
                        continue

                    tech_def = {
                        "id": technique.id,
                        "name": technique.title,
                        "reference": technique.url,
                        "subtechnique": [],
                    }

                    for sub in techniques.values():
                        if "." in sub.id and sub.id.startswith(technique.id):
                            tech_def["subtechnique"].append(
                                {"id": sub.id, "name": sub.title, "reference": sub.url}
                            )

                    definition["technique"].append(tech_def)

                threat.append(definition)

        actions = []
        for action in self.schema.actions:

            if not action.tags:
                actions.append(action.to_rule_format())

            if not rule.tags:
                continue

            for tag in action.tags:
                if tag in rule.tags:
                    break
            else:
                continue

            actions.append(action.to_rule_format())

        result = {
            "author": [rule.author] if rule.author else None,
            "description": rule.description,
            "enabled": self.schema.enable_rule,
            "false_positives": rule.falsepositives or [],
            "filters": [],
            "from": f"now-{rule.detection.timeframe}"
            if rule.detection.timeframe
            else "now-360s",
            "immutable": False,
            "index": indices,
            "interval": self.schema.interval,
            "rule_id": str(rule.id) if rule.id else str(uuid.uuid4()),
            "language": self.RULE_LANGUAGE_MAP.get(self.schema.rule_type, "eql"),
            "output_index": self.schema.output_index,
            "max_signals": self.schema.max_signals,
            "risk_score": self.schema.risk_map.get(
                rule.level.value, self.schema.risk_default
            )
            if rule.level
            else self.schema.risk_default,
            "name": rule.title or "",
            "query": query,
            "severity": self.schema.severity_map.get(
                rule.level.value, self.schema.severity_default
            )
            if rule.level
            else self.schema.severity_default,
            "tags": list(tags),
            "to": "now",
            "type": self.schema.rule_type,
            "threat": threat,
            "version": 1,
            "references": rule.references or [],
            "actions": actions,
        }

        if self.schema.timestamp_override:
            result["timestamp_override"] = self.schema.timestamp_override

        return result

    def merge_config(self, config: Dict[str, Any]):

        if "actions" in config:
            self.schema.actions.extend(
                parse_obj_as(List[ElasticSecurityAction], config["actions"])
            )

        return super().merge_config(config)
