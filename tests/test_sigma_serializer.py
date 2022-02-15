from typing import Any, Dict, List

import pytest

from sigma.schema import Rule
from sigma.serializer import Serializer

builtin_serializer_tests = [
    {
        "definition": {
            "name": "eql",
            "description": "eql",
            "base": "eql",
            "logsource": {},
            "transforms": [],
        },
        "rules": [
            {
                "title": "string-escape",
                "logsource": {},
                "detection": {
                    "selector": {"process.field": 'value"'},
                    "condition": "selector",
                },
                "expected": 'process where process.field like~ "value\\""',
            },
            {
                "title": "modifiers",
                "logsource": {},
                "detection": {
                    "selector1": {"field1": "value", "field2|contains": "value"},
                    "selector2": ["keyword1", {"field3|re": ".*"}],
                    "condition": "selector1 or selector2",
                },
                "expected": 'any where (field1 like~ "value" and stringContains(field2,"value")) or ("keyword1" or field3 regex ".*")',
            },
        ],
    }
]


@pytest.mark.parametrize(
    "definition, rule_def",
    [
        (test["definition"], rule)
        for test in builtin_serializer_tests
        for rule in test["rules"]
    ],
    ids=lambda v: v.get("name", v.get("title")),
)
def test_buitlin_serializers(definition: Dict[str, Any], rule_def: Dict[str, Any]):
    """Test all built-in serializers"""

    serializer = Serializer.from_dict(definition)
    rule = Rule.from_sigma(rule_def)

    assert rule_def["expected"] == serializer.serialize(rule)
