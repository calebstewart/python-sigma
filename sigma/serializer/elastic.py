import json
import uuid
from typing import Any, Dict, List, Union, ClassVar, Optional

from sigma.mitre import Attack, Tactic, Technique
from sigma.schema import Rule
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
        field_match: str = "{} like {}"
        """ A format string to test a field with a globbing pattern (e.g. "{}: {}") """
        field_in: str = "{}: {}"
        """ A format string to test if a field is in a list (e.g. "{} in {}") """
        field_regex: str = "{} regex {}"
        """ A format string to test if a field matches a regex (e.g. "{} match {}")"""
        keyword: str = "{}"
        """ A format string to match a keyword across all fields (e.g. "{}") """
        field_startswith: Optional[str] = "startsWith({},{})"
        """ A format string to test if a field starts with a string """
        field_endswith: Optional[str] = "endsWith({},{})"
        """ A format string to test if a field ends with a string """
        field_contains: Optional[str] = "stringContains({},{})"
        """ A format string to test if a field contains another string """
        prepend_result: str = ""
        """ String to prepend to the resulting query """
        rule_separator: str = "\n"
        """ Separator for when outputting multiple rules to a file """

        class Config:
            schema_extra = CommonSerializerSchema.Config.schema_extra.copy()
            schema_extra["examples"][0].update(
                {
                    "base": "eql",
                }
            )

    def serialize(
        self, rule: Union[Rule, List[Rule]], transform: bool = True
    ) -> Union[str, List[str]]:

        if isinstance(rule, list):
            return [self.serialize(r) for r in rule]

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
        result = super().serialize(rule)

        if len(categories) > 1 or not categories:
            category = "any"
        else:
            category = categories.pop()

        return f"{category} where {result}"


class ElasticSecurityRule(EventQueryLanguage):
    """Serialize to a JSON Elastic Security Rule"""

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
        extra_tags: Optional[List[str]]
        """ Extra tags to add to all converted rules """

        class Config:
            extra = "forbid"
            schema_extra = EventQueryLanguage.Schema.Config.schema_extra.copy()
            schema_extra["examples"][0].update(
                {
                    "base": "es-rule",
                    "enable_rule": True,
                    "interval": "5m",
                    "rule_type": "eql",
                    "output_index": ".siem-signals-default",
                    "max_signals": 100,
                    "risk_map": {"low": 0, "medium": 25, "high": 75, "critical": 100},
                    "risk_default": 10,
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

    def serialize(
        self, rule: Union[Rule, List[Rule]], transform: bool = True
    ) -> Union[str, List[str]]:

        if isinstance(rule, list):
            return [self.serialize(r) for r in rule]

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
        tags = []
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
                                tags.append(tactic.id.upper())
                                tactics[tactic.id] = tactic
                                break
                        else:
                            tags.append(tag.name)

                        continue

                    # Tactic ID
                    tactic = attack.get_tactic(tag.name)
                    if tactic is not None:
                        tags.append(tactic.id.upper())
                        tactics[tactic.id] = tactic
                        continue

                    # Technique ID
                    technique = attack.get_technique(tag.name)
                    if technique is not None:
                        tags.append(technique.id.upper())
                        if technique.tactics:
                            for tactic_id in technique.tactics:
                                tactic = attack.get_tactic(tactic_id)
                                if tactic:
                                    tags.append(tactic.title)
                                    tactics[tactic.id] = tactic

                        techniques[technique.id] = technique

                        # Add parent technique for sub-techniques
                        if "." in technique.id:
                            technique = attack.get_technique(technique.id.split(".")[0])
                            if technique is not None:
                                tags.append(technique.id.upper())
                                if technique.tactics:
                                    for tactic_id in technique.tactics:
                                        tactic = attack.get_tactic(tactic_id)
                                        if tactic:
                                            tags.append(tactic.title)
                                            tactics[tactic.id] = tactic
                                techniques[technique.id] = technique

                        continue

                    tags.append(tag.name.upper())
                else:
                    tags.append(str(tag))

        if self.schema.extra_tags:
            tags.extend(self.schema.extra_tags)

        tags.sort()

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
            "interval": "5m",
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
            "tags": tags,
            "to": "now",
            "type": self.schema.rule_type,
            "threat": threat,
            "version": 1,
            "references": rule.references or [],
        }

        return json.dumps(result)
