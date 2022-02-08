from typing import Any, Dict, List

import pytest

from sigma.schema import Rule
from sigma.grammar import (
    LogicalOr,
    Expression,
    LogicalAnd,
    FieldEndsWith,
    FieldEquality,
    FieldComparison,
    FieldStartsWith,
)
from sigma.transform import Transformation


def test_load():

    Transformation.Schema.parse_obj(
        {
            "type": "field_map",
            "mapping": {
                "CommandLine": "process.commandline",
            },
        }
    ).load()


@pytest.mark.parametrize(
    "transform_type,config,valid_names",
    [
        (
            "field_map",
            {
                "mapping": {"first_field": "transformed", "SecondField": "transformed"},
            },
            ["transformed"],
        ),
        (
            "field_fuzzy_map",
            {
                "mapping": {
                    "first_field": "transformed",
                    "second_field": "transformed",
                },
            },
            ["transformed"],
        ),
    ],
)
def test_field_transforms(
    transform_type: str, config: Dict[str, Any], valid_names: List[str]
):
    """Test application of built-in field transforms"""

    # Construct the transformation
    config["type"] = transform_type
    transform = Transformation.Schema.parse_obj(config).load()

    print(transform)

    # Load the rule and apply transformation
    rule = Rule.from_sigma(
        {
            "title": "test",
            "logsource": {},
            "detection": {
                "identifier": {"first_field": "value", "SecondField": "value"},
                "condition": "identifier",
            },
        }
    ).transform([transform])

    def visit_expression(e: Expression):
        if isinstance(e, FieldComparison):
            assert e.field in valid_names
        return e

    rule.detection.expression.visit(visit_expression)


@pytest.mark.parametrize(
    "config,detection,expected",
    [
        (
            {
                "expression": "endswith",
                "field": "statement",
                "target": "location",
                "pattern": "hello_(.*)",
            },
            {
                "selector": {
                    "statement|endswith": "hello_world",
                    "statement|startswith": "hello_world",
                    "other_field|endswith": "hello_world",
                },
                "condition": "selector",
            },
            LogicalAnd(
                args=[
                    FieldEquality(field="location", value="world"),
                    FieldStartsWith(field="statement", value="hello_world"),
                    FieldEndsWith(field="other_field", value="hello_world"),
                ]
            ),
        )
    ],
)
def test_match_replace(
    config: Dict[str, Any], detection: Dict[str, Any], expected: Expression
):
    """Test application of the built-in match_replace transform"""

    # Construct the transformation
    config["type"] = "match_replace"
    transform = Transformation.Schema.parse_obj(config).load()

    rule = Rule.from_sigma(
        {
            "title": "test",
            "logsource": {},
            "detection": detection,
        }
    ).transform([transform])

    assert rule.detection.expression == expected
