"""
Condition grammar specification
"""
import base64
from typing import Any, Dict, List, Type, Union, ClassVar, Optional

from pydantic import BaseModel
from pyparsing import Word, Keyword, Literal, opAssoc, alphanums, infixNotation
from pyparsing.results import ParseResults


class Expression(BaseModel):
    """Base class for all grammar expressions (and, or, not, identifier, selector)"""

    operator: ClassVar[bool] = False
    parent: Optional["Expression"] = None

    def postprocess(
        self, rule: "sigma.schema.RuleDetection", parent: Optional["Expression"] = None
    ) -> "Expression":

        # Save the parent
        self.parent = parent

        return self


class CoreExpression(Expression):
    """Core expressions are the ones directly parsed from the condition
    grammar (as opposed to equality expressions parsed from detection
    tests)."""

    args: List[Union[Expression, str]]

    @classmethod
    def from_parsed(cls, s: str, loc: int, tokens: ParseResults) -> "Expression":
        """Convert the parsed expression into an expression instance"""

        if len(tokens) and isinstance(tokens[0], ParseResults):
            tokens = tokens[0]

        if len(tokens) > 2:
            return cls(args=tokens[::2])
        elif len(tokens) > 1:
            return cls(args=[tokens[1]])
        else:
            return cls(args=[tokens[0]])

    def postprocess(
        self, rule: "sigma.schema.RuleDetection", parent: Optional["Expression"] = None
    ) -> "Expression":

        self.parent = parent

        # Postprocess all children
        self.args = [arg.postprocess(rule, self) for arg in self.args]

        return self


class LogicalNot(CoreExpression):
    """Logical not expression"""

    operator: ClassVar[bool] = True

    def __repr__(self):
        return f"NOT({repr(self.args[0])})"


class LogicalOr(CoreExpression):
    """Logical Or expression"""

    operator: ClassVar[bool] = True

    def __repr__(self):
        return f"OR({','.join([repr(a) for a in self.args])})"


class LogicalAnd(CoreExpression):
    """Logical And Expression"""

    operator: ClassVar[bool] = True

    def __repr__(self):
        return f"AND({','.join([repr(a) for a in self.args])})"


class Identifier(CoreExpression):
    """Expression which identifies a specific detection condition"""

    @property
    def identifier(self) -> str:
        """Shortcut for grabbing the identifier"""

        if not isinstance(self.args[0], str):
            raise RuntimeError("expected string identifier")

        return self.args[0]

    def __repr__(self) -> str:
        return self.identifier

    def postprocess(
        self, rule: "sigma.schema.Rule", parent: Optional[Expression]
    ) -> Expression:
        """Resolve the detection identifier"""

        # Save the parent
        self.parent = parent

        # Lookup the detection condition expression and post-process it
        return rule.get_expression(self.identifier).postprocess(rule, self)


class Selector(CoreExpression):
    """Selector expression which is converted to LogicalAnd or LogicalOr"""

    @property
    def condition(self) -> Type[CoreExpression]:
        return LogicalOr if self.args[0] in ["1", "any"] else LogicalAnd

    @property
    def pattern(self) -> str:
        return str(self.args[1])

    def postprocess(
        self, rule: "sigma.schema.Rule", parent: Optional[Expression]
    ) -> Expression:
        """Collapse selector into either a logical OR or AND expression"""

        return self.condition(
            args=[
                Identifier(args=[identifier])
                for identifier in rule.lookup_expression(self.pattern)
            ]
        ).postprocess(rule, parent)


class FieldComparison(Expression):
    """Base class for direct field comparisons"""

    field: str
    value: Any

    def __repr__(self) -> str:
        raise NotImplementedError


class FieldEquality(FieldComparison):
    """Test for field equality"""

    def __repr__(self) -> str:
        return f"EQ({self.field}, {repr(self.value)})"


class FieldContains(FieldComparison):
    """Test if a string is in the field somewhere"""

    def __repr__(self) -> str:
        return f"CONTAINS({self.field}, {repr(self.value)})"


class Base64FieldEquality(FieldComparison):
    """Test for field equality of base64 string"""

    def __repr__(self) -> str:
        return f"EQ({self.field}, b64decode({repr(self.value)}))"


class FieldEndsWith(FieldComparison):
    """Test if a field ends with a token"""

    def __repr__(self) -> str:
        return f"ENDSWITH({self.field}, {repr(self.value)})"


class FieldStartsWith(FieldComparison):
    """Test if a field starts with a token"""

    def __repr__(self) -> str:
        return f"STARTSWITH({self.field}, {repr(self.value)})"


class FieldIn(FieldComparison):
    """Test if a field is in a list of constants"""

    values: List[str]

    def __repr__(self) -> str:
        return f"IN({self.field}, {repr(self.values)})"


class ListContainsField(Expression):
    """Test for a field in a specific list of literals"""

    field: str
    values: List[str]

    def __repr__(self) -> str:
        return f"IN({self.field}, {repr(self.values)})"


class KeywordSearch(Expression):
    """Search for a literal keyword/string instead of a direct comparison"""

    value: str

    def __repr__(self) -> str:
        return repr(self.value)


class FieldContains(Expression):
    """Test for a field that contains a string"""

    field: str
    value: str

    def __repr__(self) -> str:
        return f"CONTAINS({self.field}, {repr(self.value)}"


MODIFIER_MAPPING: Dict[str, Type[FieldComparison]] = {
    "contains": FieldContains,
    "base64": Base64FieldEquality,
    "endswith": FieldEndsWith,
    "startswith": FieldStartsWith,
}


def build_key_value_expression(key: str, value: Union[list, str]) -> Expression:
    """Evaluate any modifiers in the given key and return a valid expression
    representing the key/value pair. These are taken directly from the detection
    definition.

    NOTE: this needs the most work. We need to figure out how to represent all of
    the possible transformations within the grammar parsing expressions. For now,
    we only support single transformations + "all" where appropriate.
    """

    field, *modifiers = key.split("|")
    if "all" in modifiers:
        modifiers.remove("all")
        combo_class = LogicalAnd
    else:
        combo_class = LogicalOr

    if isinstance(value, list):
        return combo_class(args=[build_key_value_expression(key, v) for v in value])

    if len(modifiers) > 1:
        raise RuntimeError("only a single modifier (plus optional all) is supported")
    elif modifiers:
        if modifiers[0] not in MODIFIER_MAPPING:
            raise RuntimeError(f"no such modifier: {modifiers[0]}")

        return MODIFIER_MAPPING[modifiers[0]](field=field, value=value)
    else:
        return FieldEquality(field=field, value=value)


def build_grammar_parser():
    """Build the pyparsing grammar parser for the condition field"""

    # Detection Search Identifier names
    identifier = Word(alphanums + "_-")
    identifier.set_parse_action(Identifier.from_parsed)

    # Identifier name patterns used in quantifier expressions
    identifier_pattern = Word(alphanums + "_*")
    # Quantifier types
    quantifier = Keyword("1") | Keyword("any") | Keyword("all")

    # Quantified selectors
    selector = quantifier + Literal("of") + identifier_pattern
    selector.set_parse_action(Selector.from_parsed)

    # All operand types
    operand = selector | identifier
    # Setup infix notation (e.g. "(identifier1 or identifier2) and identifier3")
    condition = infixNotation(
        base_expr=operand,
        op_list=[
            ("not", 1, opAssoc.RIGHT, LogicalNot.from_parsed),
            ("and", 2, opAssoc.LEFT, LogicalAnd.from_parsed),
            ("or", 2, opAssoc.LEFT, LogicalOr.from_parsed),
        ],
    )

    return condition
