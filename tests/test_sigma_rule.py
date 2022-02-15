import uuid
import base64
import pathlib
from typing import Any, Dict, Type

import yaml
import pytest

from sigma.errors import (
    RuleValidationError,
    ConditionSyntaxError,
    UnknownIdentifierError,
)
from sigma.schema import Rule
from sigma.grammar import (
    FieldLike,
    LogicalOr,
    Expression,
    FieldRegex,
    LogicalAnd,
    FieldContains,
    FieldEndsWith,
    FieldEquality,
    KeywordSearch,
    FieldStartsWith,
    FieldLookupRegex,
)


def test_load_from_yaml(tmp_path: pathlib.Path):
    """Test loading a rule from a YAML file"""

    rule_path = tmp_path / "rule.yml"

    # Write a test rule to disk
    with rule_path.open("w") as filp:
        yaml.safe_dump(Rule.Config.schema_extra["examples"][0], filp)

    # Attempt to load the rule
    Rule.from_yaml(rule_path)


@pytest.mark.parametrize(
    "detection,expected",
    [
        (
            {
                "selector1": {
                    "field": "value",
                    "field|endswith": "value",
                    "field|re": "value",
                    "field|startswith": "value",
                    "field|contains": "value",
                    "field|base64": "value",
                    "field|wide|base64": "value",
                    "field|utf16le|base64": "value",
                    "field|utf16be|base64": "value",
                    "field|utf16|base64": "value",
                },
                "condition": "selector1",
            },
            LogicalAnd(
                args=[
                    FieldLike(field="field", value="value"),
                    FieldEndsWith(field="field", value="value"),
                    FieldRegex(field="field", value="value"),
                    FieldStartsWith(field="field", value="value"),
                    FieldContains(field="field", value="value"),
                    FieldLike(
                        field="field", value=base64.b64encode(b"value").decode("utf-8")
                    ),
                    FieldLike(
                        field="field",
                        value=base64.b64encode("value".encode("utf-16le")).decode(
                            "utf-8"
                        ),
                    ),
                    FieldLike(
                        field="field",
                        value=base64.b64encode("value".encode("utf-16le")).decode(
                            "utf-8"
                        ),
                    ),
                    FieldLike(
                        field="field",
                        value=base64.b64encode("value".encode("utf-16be")).decode(
                            "utf-8"
                        ),
                    ),
                    FieldLike(
                        field="field",
                        value=base64.b64encode(
                            b"\xFF\xFE" + "value".encode("utf-16le")
                        ).decode("utf-8"),
                    ),
                ]
            ),
        ),
        (
            {
                "selector1": {
                    "field1": "value1",
                    "field2|re": ["value2-1", "value2-2"],
                },
                "selector2": ["keyword1", "keyword2", {"field3": "value3"}],
                "condition": "selector1 or selector2",
            },
            LogicalOr(
                args=[
                    LogicalAnd(
                        args=[
                            FieldLike(field="field1", value="value1"),
                            FieldLookupRegex(
                                field="field2", value=["value2-1", "value2-2"]
                            ),
                        ]
                    ),
                    LogicalOr(
                        args=[
                            KeywordSearch(value="keyword1"),
                            KeywordSearch(value="keyword2"),
                            FieldLike(field="field3", value="value3"),
                        ]
                    ),
                ]
            ),
        ),
    ],
)
def test_condition_grammer(detection: Dict[str, Any], expected: Expression):
    """Test rule condition grammar parsing"""

    # Load the example rule
    rule = Rule.from_sigma(
        {
            "title": "test",
            "logsource": {"category": "test", "product": "test"},
            "detection": detection,
        }
    )

    assert rule.detection.expression == expected


def test_saving(tmp_path: pathlib.Path):
    """Test saving a parsed rule to a Sigma rule file"""

    rule_path = tmp_path / "rule.yml"

    # Load the example rule
    orig_rule = Rule.from_sigma(Rule.Config.schema_extra["examples"][0])

    # Modify the title
    orig_rule.title = "modified"

    # Write to disk
    with rule_path.open("w") as filp:
        yaml.safe_dump(orig_rule.to_sigma(), filp)

    # Read back
    rule = Rule.from_yaml(rule_path)

    # unmodified fields are the same and modified fields have changed
    assert rule.title == "modified" and rule.description == orig_rule.description


@pytest.mark.parametrize(
    "rule,exception",
    [
        (
            {},
            RuleValidationError,
        ),
        (
            {
                "title": "test",
                "logsource": {},
                "detection": {"condition": "fake_identifier"},
            },
            UnknownIdentifierError,
        ),
        (
            {
                "title": "test",
                "logsource": {},
                "detection": {
                    "identifier": {"field": "value"},
                    "condition": "identifier && identifier",
                },
            },
            ConditionSyntaxError,
        ),
    ],
)
def test_validation(rule: Dict[str, Any], exception: Type[Exception]):

    with pytest.raises(exception):
        Rule.from_sigma(rule)
