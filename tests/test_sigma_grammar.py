from typing import List, Type, Union

import pytest
from pyparsing.core import ParserElement
from pyparsing.exceptions import ParseException

from sigma.grammar import (
    Selector,
    LogicalOr,
    Identifier,
    LogicalAnd,
    LogicalNot,
    CoreExpression,
)


@pytest.mark.parametrize(
    "condition,expected",
    [
        ("identifier1", [Identifier(args=["identifier1"])]),
        (
            "identifier1 identifier2",
            [Identifier(args=["identifier1"]), Identifier(args=["identifier2"])],
        ),
        (
            "identifier1 and identifier2",
            [
                LogicalAnd(
                    args=[
                        Identifier(args=["identifier1"]),
                        Identifier(args=["identifier2"]),
                    ]
                )
            ],
        ),
        (
            "identifier1 or identifier2",
            [
                LogicalOr(
                    args=[
                        Identifier(args=["identifier1"]),
                        Identifier(args=["identifier2"]),
                    ]
                )
            ],
        ),
        (
            "not identifier",
            [LogicalNot(args=[Identifier(args=["identifier"])])],
        ),
        (
            "1 of identifier*",
            [Selector(args=["1", "identifier*"])],
        ),
        (
            "any of identifier*",
            [Selector(args=["any", "identifier*"])],
        ),
    ],
)
def test_core_conditions(
    condition: str,
    expected: List[CoreExpression],
    grammar_parser: ParserElement,
):
    """Test core conditions like logical operations and identifiers"""

    parsed = grammar_parser.parse_string(condition)
    for parsed_expr, expected_expr in zip(parsed, expected):
        assert parsed_expr == expected_expr


@pytest.mark.parametrize(
    "condition,exception",
    [
        ("identifier && identifier2", ParseException),
        ("identifier &&", ParseException),
        ("2 of selector*", ParseException),
        ("identifier | count(field)", ParseException),
    ],
)
def test_condition_errors(
    condition: str, exception: Type[Exception], grammar_parser: ParserElement
):

    with pytest.raises(exception):
        grammar_parser.parse_string(condition, parse_all=True)
