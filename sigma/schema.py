"""
Sigma rule schema is the core functionality of this package. The rule schema allows
you to generically read and write Sigma rules in Python. Rules can be loaded from
a dictionary or directly from a YAML file. You can also reproduce compliant Sigma
rules from in-memory representations with the :py:meth:`Rule.to_sigma` method. This
can be used to load, modify and save sigma rules without conversion if needed.

Sigma rule detection conditions can also be parsed using the ``pyparsing`` package
into a python-native format, which is normally used in conjunction with a serializer.

.. code-block:: python
    :caption: Loading and Inspecting a Rule

    from sigma.schema import Rule

    rule = Rule.from_yaml("path/to/rule.yml")

    # Retrieve common properties
    print(rule.title)
    print(rule.detection.condition)
    print(rule.tags)
    print(rule.author)

    # Retrieve a parsed expression representing the full detection condition
    print(rule.detection.expression)


"""
import re
import fnmatch
import pathlib
from enum import Enum
from uuid import UUID
from typing import Any, Dict, List, Union, Callable, ClassVar, Optional, Generator
from datetime import date

import yaml
import pydantic
from pydantic.fields import Field, PrivateAttr
from pyparsing.exceptions import ParseException

from sigma.errors import ConditionSyntaxError, UnknownIdentifierError
from sigma.grammar import (
    LogicalOr,
    Expression,
    LogicalAnd,
    KeywordSearch,
    build_grammar_parser,
    build_key_value_expression,
)


class LowercaseString(str):
    def __str__(self) -> str:
        return self.lower()


class SimpleDate(date):
    """Simple date class which has a custom parser to handle either YYYY/MM/DD or YYYY-MM-DD"""

    @classmethod
    def __get_validators__(cls) -> Generator[Callable, None, None]:
        yield cls._pydantic_validate

    @classmethod
    def _pydantic_validate(cls, v):

        if isinstance(v, date):
            return v

        # I don't know why anyone would do this, but I typed it so now it's supported...
        if isinstance(v, int):
            return date.fromtimestamp(v)

        if not isinstance(v, str):
            raise TypeError("expected string or integer")

        if re.fullmatch("([0-9]{4})/([0-9]{1,2})/([0-9]{1,2})", v):
            v = v.replace("/", "-")

        if not re.fullmatch("([0-9]{4})-([0-9]{1,2})-([0-9]{1,2})", v):
            raise ValueError("invalid date format")

        return date.fromisoformat(v)


class RuleStatus(LowercaseString, Enum):
    """Indicates the development status for a sigma rule"""

    STABLE = "stable"
    """ the rule is considered as stable and may be used in production systems
    or dashboards. """
    TESTING = "testing"
    """ an almost stable rule that possibly could require some fine tuning. """
    TEST = "test"
    """ an almost stable rule that possibly could require some fine tuning. """
    EXPERIMENTAL = "experimental"
    """ an experimental rule that could lead to false results or be noisy, but
    could also identify interesting events. """
    DEPRECATED = "deprecated"
    """ the rule is replace or cover by another one. The link is made by the
    related field. """
    UNSUPPORTED = "unsupported"
    """ the rule can not be use in its current state (special correlation log,
    home-made fields) """


class RuleLevel(LowercaseString, Enum):
    """The level field contains one of five string values. It describes the
    criticality of a triggered rule. While low and medium level events have an
    informative character, events with high and critical level should lead to
    immediate reviews by security analysts."""

    INFORMATIONAL = "informational"
    """ Rule is intended for enrichment of events, e.g. by tagging them. No case
    or alerting should be triggered by such rules because it is expected that a
    huge amount of events will match these rules. """
    LOW = "low"
    """ Notable event but rarely an incident. Low rated events can be relevant
    in high numbers or combination with others. Immediate reaction shouldn't be
    necessary, but a regular review is recommended. """
    MEDIUM = "medium"
    """ Relevant event that should be reviewed manually on a more frequent basis. """
    HIGH = "high"
    """ Relevant event that should trigger an internal alert and requires a
    prompt review. """
    CRITICAL = "critical"
    """ Highly relevant event that indicates an incident. Critical events should
    be reviewed immediately. """

    def to_severity(self) -> int:
        """Convert the rule level to an integer severity level in the range 0-100"""
        return 0


class RuleRelationType(LowercaseString, Enum):
    """Type of rule relationship"""

    DERIVED = "derived"
    """ Rule was derived from the referred rule or rules, which may remain active. """
    OBSOLETES = "obsoletes"
    """ Rule obsoletes the referred rule or rules, which aren't used anymore. """
    MERGED = "merged"
    """ Rule was merged from the referred rules. The rules may be still existing and in use. """
    RENAMED = "renamed"
    """ The rule had previously the referred identifier or identifiers but was renamed
    for any other reason, e.g. from a private naming scheme to UUIDs, to resolve
    collisions etc. It's not expected that a rule with this id exists anymore. """


class RuleTag(str):
    """
    A Sigma rule can be categorised with tags. Tags should generally follow this syntax:

    - Character set: lower-case letters, underscores and hyphens
    - no spaces
    - Tags are namespaced, the dot is used as separator. e.g. attack.t1234 refers to
      technique 1234 in the namespace attack; Namespaces may also be nested
    - Keep tags short, e.g. numeric identifiers instead of long sentences
    - If applicable, use predefined tags. Feel free to send pull request or issues
      with proposals for new tags

    Predefined tags: https://github.com/SigmaHQ/sigma/wiki/Tags
    """

    @property
    def namespace(self) -> Optional[str]:
        """The namespace is everything prior to the first period in the tag"""

        if "." not in self:
            return None

        return self.split(".", maxsplit=1)[0]

    @property
    def name(self) -> str:
        """The name is everything after the first period in the tag. If there
        are no periods, then the name is an empty string."""

        if "." not in self:
            return str(self)

        return self.split(".", maxsplit=1)[1]

    @classmethod
    def __get_validators__(cls) -> Generator[Callable, None, None]:
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not isinstance(v, str):
            raise TypeError("string required")

        if not re.fullmatch("[a-z][a-z0-9_.-]*", v):
            raise ValueError("invalid tag format")

        return cls(v)

    @classmethod
    def __modify_schema__(cls, field_schema):
        field_schema.update(
            pattern="[a-z][a-z0-9_.-]*",
            examples=["attack.t1234", "attack.initial_access"],
        )

    def __repr__(self) -> str:
        return f"Tag(namespace={repr(self.namespace)}, name={repr(self.name)})"


class RuleLicense(str):
    """License of the rule according the SPDX ID specification."""


class RuleLogSource(pydantic.BaseModel):
    """Defines the source of log entries for a sigma rule"""

    category: Optional[str]
    product: Optional[str]
    service: Optional[str]
    definition: Optional[str]

    def __contains__(self, other: "RuleLogSource") -> bool:
        """Compare two log sources. This returns true if the sources are
        equal or self contains less attributes than other, which all match."""

        if not isinstance(other, self.__class__):
            raise TypeError(f"expected {self.__class__} object not {other.__class__}")

        return self == other or (
            (self.category is None or self.category == other.category)
            and (self.product is None or self.product == other.product)
            and (self.service is None or self.service == other.service)
        )

    class Config:
        extra = "allow"


class RuleRelation(pydantic.BaseModel):
    """Defines detections/queries for this rule"""

    id: UUID
    type: RuleRelationType

    class Config:
        schema_extra = {
            "examples": [
                {
                    "id": "7aa7009a-28b9-4344-8c1f-159489a390df",
                    "type": RuleRelationType.DERIVED.value,
                }
            ]
        }


class RuleDetectionFields(Dict[str, Any]):
    """Defines the detection criteria by AND-separated field matching."""

    def build_expression(self) -> Expression:
        """Build the logical AND expression for these keywords"""

        args = []
        for key, value in self.items():
            args.append(build_key_value_expression(key, value))

        return LogicalAnd(args=args) if len(args) > 1 else args[0]


class RuleDetectionList(List[Union[str, RuleDetectionFields]]):
    """Defines the detection criteria by OR-separated keyword strings."""

    def build_expression(self) -> Expression:
        """Build the logical OR expression for these keywords"""

        args = []
        for item in self:
            if isinstance(item, str):
                args.append(KeywordSearch(value=item))
            else:
                args.append(RuleDetectionFields(item).build_expression())

        return LogicalOr(args=args) if len(args) > 1 else args[0]


class RuleDetection(pydantic.BaseModel):
    """Defines the detection criteria for this rule including the timeframe,
    condition specification and any number of detection field lists/keywords
    grouped by arbitrary names."""

    GRAMMAR_PARSER: ClassVar[Any] = build_grammar_parser()
    timeframe: Optional[str] = Field(None, regex="[0-9]+[smhdMY]")
    condition: Union[List[str], str]
    __parsed_expression: Expression = PrivateAttr()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Parse the condition grammar
        self.__parsed_expression = self.parse_grammar()

    def transform(self, rule: "Rule", transforms: "sigma.transform.Transformation"):
        """Transform all expressions with the given transformations"""

        def expression_visitor(expression: Expression) -> Expression:
            for t in transforms:
                expression = t.transform_expression(rule, expression)

            return expression

        self.__parsed_expression = self.expression.visit(expression_visitor)

    @property
    def expression(self) -> Expression:
        return self.__parsed_expression

    def update_expression(self, expression: Expression):
        self.__parsed_expression = expression

    def parse_grammar(self) -> Expression:
        """Parse the condition and evaluate fields to produce a single
        search expression."""

        if isinstance(self.condition, list):
            results = []
            for idx, condition in enumerate(self.condition):
                try:
                    condition_grammar = list(
                        self.GRAMMAR_PARSER.parse_string(condition)
                    )
                except ParseException as exc:
                    raise ConditionSyntaxError(
                        exc, fmt=f"condition[{idx}]: {{}}"
                    ) from exc

                if len(condition_grammar) > 1:
                    results.append(LogicalAnd(args=condition_grammar))
                else:
                    results.append(condition_grammar[0])

            if len(results) > 1:
                return LogicalOr(args=results).postprocess(self)
            else:
                return results[0].postprocess(self)
        else:
            try:
                grammar = list(self.GRAMMAR_PARSER.parse_string(self.condition))
            except ParseException as exc:
                raise ConditionSyntaxError(exc, fmt="condition: {}") from exc
            if len(grammar) > 1:
                return LogicalAnd(args=grammar).postprocess(self)

            return grammar[0].postprocess(self)

    def get_expression(self, identifier: str) -> Expression:
        """Construct an expression from the specified identifier. If the requested
        identifier does not exist, a MissingIdentifier exception is raised."""

        try:
            definition = getattr(self, identifier)
            if not isinstance(
                definition, Union[RuleDetectionList, RuleDetectionFields]
            ):
                raise AttributeError
        except AttributeError:
            raise UnknownIdentifierError(f"{identifier}: invalid detection identifier")

        return definition.build_expression()

    def lookup_expression(self, pattern: str) -> Generator[str, None, None]:
        """Lookup identifier expressions by a glob pattern"""

        for key in self.dict().keys():
            if fnmatch.fnmatch(key, pattern):
                definition = getattr(self, key)
                if isinstance(
                    definition,
                    Union[RuleDetectionFields, RuleDetectionList],
                ):
                    yield key

    @classmethod
    def __get_validators__(cls):
        yield cls.validate_detection
        yield from super().__get_validators__()

    @classmethod
    def validate_detection(cls, v):
        """Validate the schema for the"""

        for key in v.keys():
            if key in ["timeframe", "condition"]:
                continue
            elif isinstance(v[key], dict):
                v[key] = RuleDetectionFields(v[key])
            elif isinstance(v[key], list):
                v[key] = RuleDetectionList(v[key])
            else:
                raise TypeError(f"{key}: expected list or dict")

        return v

    class Config:
        extra = "allow"
        schema_extra = {
            "examples": [
                {
                    "timeframe": "5m",
                    "condition": "(selection1 or selection2) and not filter",
                    "selection1": {
                        "Imphash": [
                            "a53a02b997935fd8eedcb5f7abab9b9f",
                            "e96a73c7bf33a464c510ede582318bf2",
                        ]
                    },
                    "selection2": {
                        "CommandLine|endswith": ".exe -S",
                        "ParentImage|endswith": "\\services.exe",
                    },
                    "filter": {"Image|endswith": "\\clussvc.exe"},
                }
            ]
        }


class Rule(pydantic.BaseModel):
    """Sigma Rule Specification"""

    title: str = Field(..., max_length=256)
    """ A brief title for the rule that should contain what the rules is supposed
    to detect (max. 256 characters). """
    id: Optional[UUID]
    """ Sigma rules should be identified by a globally unique identifier in the id
    attribute. """
    related: Optional[List[RuleRelation]]
    """ List of rule IDs and associated relationships to this rule. """
    status: Optional[RuleStatus]
    """ Declares the status of the rule. """
    description: Optional[str] = Field(None, max_length=65535)
    """ A short description of the rule and the malicious activity that can be
    detected (max. 65,535 characters). """
    author: Optional[str]
    """ Creator of the rule """
    license: Optional[str]
    """ SPDX License Name """
    references: Optional[List[str]]
    """ References to the source that the rule was derived from. These could be
    blog articles, technical papers, presentations or even tweets."""
    logsource: RuleLogSource
    """ This section describes the log data on which the detection is meant to be
    applied to. It describes the log source, the platform, the application and the
    type that is required in detection. """
    detection: RuleDetection
    """ A set of search-identifiers that represent searches on log data. """
    fields: Optional[List[str]]
    """ A list of log fields that could be interesting in further analysis of the
    event and should be displayed to the analyst. """
    falsepositives: Optional[List[Union[None, str]]]
    """ A list of known false positives that may occur. """
    level: Optional[RuleLevel]
    """ The level field contains one of five string values. It describes the
    criticality of a triggered rule. """
    tags: Optional[List[RuleTag]]
    """ A Sigma rule can be categorised with tags. """
    date: Optional[Union[SimpleDate, str]] = Field(
        None, examples=["1999/1/31", "2021-12-25"]
    )
    """ The date the rule was created. This should be YYYY-MM-DD or YYYY/MM/DD. If
    the field is not formatted in this way, it will be saved as a simple string. """
    modified: Optional[Union[SimpleDate, str]] = Field(
        None, examples=["1999/1/31", "2021-12-25"]
    )
    """ The date the rule was last modified. This should be YYYY-MM-DD or YYYY/MM/DD.
    If the field is not formatted in this way, it will be saved as a simple string."""

    def transform(self, transforms: List["sigma.transorms.Transformation"]) -> "Rule":
        """Apply all transformations to this rule and all condition expressions"""

        # Apply all rule transformations (potentially replacing this rule)
        rule = self
        for transform in transforms:
            rule = transform.transform_rule(rule)

        # Apply all expression transformations to the detection
        rule.detection.transform(rule, transforms)

        return rule

    @classmethod
    def from_yaml(cls, path: Union[str, pathlib.Path]) -> "Rule":
        """Load a rule from a YAML file"""

        with open(path) as filp:
            return cls.from_sigma(yaml.safe_load(filp))

    @classmethod
    def from_sigma(cls, definition: Dict[str, Any]) -> "Rule":
        """Alias for parse_obj to be more expressive"""
        return cls.parse_obj(definition)

    def to_sigma(self) -> Dict[str, Any]:
        """Convert this rule back into a JSON-serializable dictionary representing
        the sigma rule. This dictionary can safely be converted to JSON or YAML and
        written back to disk as a valid Sigma rule."""

        def _recursive_pydantic_dict(m):

            if isinstance(m, Enum):
                return str(m.value)
            elif isinstance(m, str):
                return str(m)
            elif isinstance(m, float):
                return float(m)
            elif isinstance(m, int):
                return int(m)
            elif isinstance(m, list):
                return [_recursive_pydantic_dict(v) for v in m]
            elif isinstance(m, pydantic.BaseModel):
                return {key: _recursive_pydantic_dict(value) for key, value in m}
            elif isinstance(m, dict):
                return {
                    key: _recursive_pydantic_dict(value) for key, value in m.items()
                }
            elif m is None:
                return None
            else:
                return str(m)

        result: Dict[str, Any] = _recursive_pydantic_dict(self.dict())
        result["detection"] = {
            key: value
            for key, value in result["detection"].items()
            if key in ["timeframe"]
        }

        condition, selectors = self.detection.expression.to_detection(group=False)
        selector_names = [f"selector{i}" for i in range(len(selectors))]
        result["detection"]["condition"] = condition.format(*selector_names)
        result["detection"].update(
            {selector_names[i]: selectors[i] for i in range(len(selectors))}
        )

        return result

    class Config:
        extra = "allow"
        schema_extra = {
            "examples": [
                {
                    "title": "Windows Credential Editor",
                    "id": "7aa7009a-28b9-4344-8c1f-159489a390df",
                    "description": "Detects the use of Windows Credential Editor (WCE)",
                    "status": "experimental",
                    "author": "Florian Roth",
                    "references": [
                        "https://www.ampliasecurity.com/research/windows-credentials-editor/"
                    ],
                    "date": "2019/12/31",
                    "modified": "2021/07/15",
                    "tags": [
                        "attack.credential_access",
                        "attack.t1003.001",
                        "attack.s0005",
                    ],
                    "logsource": {"category": "process_creation", "product": "windows"},
                    "detection": {
                        "selection1": {
                            "Imphash": [
                                "a53a02b997935fd8eedcb5f7abab9b9f",
                                "e96a73c7bf33a464c510ede582318bf2",
                            ]
                        },
                        "selection2": {
                            "CommandLine|endswith": ".exe -S",
                            "ParentImage|endswith": "\\services.exe",
                        },
                        "filter": {"Image|endswith": "\\clussvc.exe"},
                        "condition": "( selection1 or selection2 ) and not filter",
                    },
                    "falsepositives": [
                        "Another service that uses a single -s command line switch"
                    ],
                    "level": "critical",
                }
            ]
        }
