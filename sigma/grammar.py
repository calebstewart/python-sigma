"""
Sigma rule detection condition grammar parsing rules and classes. The classes defined
here facilitate the abstract parsing of detection rules into Python-processable class
structures. You should not need to interact directly with this module except when
implementing serializers.

There are two main types of expressions defined here: core expressions and field
comparisons. Core expressions are parsed from the `Rule.detection.condition`
property and are things like the core logical expressions. While field comparisons
are constructed from the detection matching identifiers and are things like
field equality tests
"""
import base64
import itertools
from typing import Any, Dict, List, Type, Tuple, Union, Callable, ClassVar, Optional

from pydantic import BaseModel
from pyparsing import Word, Keyword, Literal, opAssoc, alphanums, infixNotation
from pyparsing.results import ParseResults

from sigma.errors import (
    UnknownModifierError,
    InvalidFieldValueError,
    UnknownIdentifierError,
    InvalidModifierCombinationError,
)


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

    def visit(self, callback: Callable[["Expression"], "Expression"]) -> "Expression":
        """Execute the given callback for each expression in the tree. The callback
        must return an expression to replace to visited expression (or the same reference
        to leave it unchanged)."""

        from sigma.grammar import CoreExpression

        expression = callback(self)
        if isinstance(expression, CoreExpression):
            expression.args = [
                e.visit(callback) if isinstance(e, Expression) else e
                for e in expression.args
            ]

        return expression

    def to_detection(self) -> Tuple[str, List[Union[List, Dict]]]:
        """Convert an expression to a condition string and a dict of new detection
        selectors."""

        raise NotImplementedError


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


class LogicalExpression(CoreExpression):
    """Logical expression"""

    operator: ClassVar[bool] = True

    def postprocess(
        self, rule: "sigma.schema.RuleDetection", parent: Optional["Expression"] = None
    ) -> "Expression":

        expression = super().postprocess(rule, parent)
        if not isinstance(expression, CoreExpression):
            return expression

        # This is some very basic expression simplification.
        # It ensures AND(AND(1,2),AND(3,4),AND(5,6)) is resolved
        # to AND(1,2,3,4,5,6), and does the same for other logical
        # expressions as well. Some more complicated simplifications
        # can probably be done, but I'm not going to mess with it
        # for now.
        subtypes = {type(a) for a in expression.args}
        subtype = subtypes.pop()
        if len(subtypes) == 0 and isinstance(self, subtype):
            return type(self)(
                args=list(itertools.chain(*[a.args for a in expression.args]))
            ).postprocess(rule, parent)

        return expression


class LogicalNot(LogicalExpression):
    """Logical not expression"""

    operator: ClassVar[bool] = True

    def __repr__(self):
        return f"NOT({repr(self.args[0])})"

    def to_detection(self) -> Tuple[str, List[Union[List, Dict]]]:
        """Convert a not expression to a detection condition"""

        condition, selectors = self.args[0].to_detection()

        return f"not {condition}", selectors


class LogicalOr(LogicalExpression):
    """Logical Or expression"""

    operator: ClassVar[bool] = True

    def __repr__(self):
        return f"OR({','.join([repr(a) for a in self.args])})"

    def to_detection(self, group: bool = True) -> Tuple[str, List[Union[List, Dict]]]:
        """Convert a not expression to a detection condition"""

        if all([isinstance(e, Keyword) for e in self.args]):
            return "{}", [[e.value for e in self.args]]

        if (
            all([isinstance(e, FieldComparison) for e in self.args])
            and len(set([type(e) for e in self.args])) == 1
        ):
            return "{}", [
                {self.args[0].to_field_with_modifiers(): [e.value for e in self.args]}
            ]

        conditions = []
        selectors = []
        for expression in self.args:
            condition, selector_list = expression.to_detection()
            conditions.append(condition)
            selectors.extend(selector_list)

        if group:
            return "(" + " or ".join(conditions) + ")", selectors
        else:
            return " or ".join(conditions), selectors


class LogicalAnd(LogicalExpression):
    """Logical And Expression"""

    operator: ClassVar[bool] = True

    def __repr__(self):
        return f"AND({','.join([repr(a) for a in self.args])})"

    def to_detection(self, group: bool = True) -> Tuple[str, List[Union[List, Dict]]]:
        """Convert a not expression to a detection condition"""

        if all([isinstance(e, FieldComparison) for e in self.args]):
            return "{}", [{e.to_field_with_modifiers(): e.value for e in self.args}]

        conditions = []
        selectors = []
        for expression in self.args:
            condition, selector_list = expression.to_detection()
            conditions.append(condition)
            selectors.extend(selector_list)

        if group:
            return "(" + " and ".join(conditions) + ")", selectors
        else:
            return " and ".join(conditions), selectors


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
        self,
        rule: "sigma.schema.Rule",
        parent: Optional[Expression] = None,
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
        self,
        rule: "sigma.schema.Rule",
        parent: Optional[Expression] = None,
    ) -> Expression:
        """Collapse selector into either a logical OR or AND expression"""

        args = [
            Identifier(args=[identifier])
            for identifier in rule.lookup_expression(self.pattern)
        ]
        if not args:
            raise UnknownIdentifierError(
                f"selector pattern {self.pattern} did not match any identifiers"
            )

        return self.condition(args=args).postprocess(rule, parent)


class FieldComparison(Expression):
    """Base class for direct field comparisons"""

    field: str
    value: Any

    def __repr__(self) -> str:
        raise NotImplementedError

    def to_field_with_modifiers(self) -> str:
        return self.field

    def to_detection(self) -> Tuple[str, List[Union[List, Dict]]]:
        """Convert a not expression to a detection condition"""

        return "{}", [{self.field: self.value}]


class FieldEquality(FieldComparison):
    """Test for field equality"""

    def __repr__(self) -> str:
        return f"EQ({self.field}, {repr(self.value)})"

    def to_detection(self) -> Tuple[str, List[Union[List, Dict]]]:
        """Convert a not expression to a detection condition"""

    def to_detection(self) -> Tuple[str, List[Union[List, Dict]]]:
        """Convert a not expression to a detection condition"""

        return "{}", [{self.field: self.value}]


class FieldContains(FieldComparison):
    """Test if a string is in the field somewhere"""

    value: str

    def __repr__(self) -> str:
        return f"CONTAINS({self.field}, {repr(self.value)})"

    def to_field_with_modifiers(self) -> str:
        return f"{self.field}|contains"

    def to_detection(self) -> Tuple[str, List[Union[List, Dict]]]:
        """Convert a not expression to a detection condition"""

        return "{}", [{self.field + "|contains": self.value}]


class Base64FieldEquality(FieldComparison):
    """Test for field equality of base64 string"""

    value: Union[str, bytes]

    def __repr__(self) -> str:
        return f"EQ({self.field}, b64decode({repr(self.value)}))"

    def to_detection(self) -> Tuple[str, List[Union[List, Dict]]]:
        """Convert a not expression to a detection condition"""

        return "{}", [{self.field + "|contains": self.value}]


class FieldEndsWith(FieldComparison):
    """Test if a field ends with a token"""

    value: str

    def __repr__(self) -> str:
        return f"ENDSWITH({self.field}, {repr(self.value)})"

    def to_field_with_modifiers(self) -> str:
        return f"{self.field}|endswith"

    def to_detection(self) -> Tuple[str, List[Union[List, Dict]]]:
        """Convert a not expression to a detection condition"""

        return "{}", [{self.field + "|endswith": self.value}]


class FieldStartsWith(FieldComparison):
    """Test if a field starts with a token"""

    value: str

    def __repr__(self) -> str:
        return f"STARTSWITH({self.field}, {repr(self.value)})"

    def to_field_with_modifiers(self) -> str:
        return f"{self.field}|startswith"

    def to_detection(self) -> Tuple[str, List[Union[List, Dict]]]:
        """Convert a not expression to a detection condition"""

        return "{}", [{self.field + "|startswith": self.value}]


class FieldIn(FieldComparison):
    """Test if a field is in a list of constants"""

    value: List[str]

    def __repr__(self) -> str:
        return f"IN({self.field}, {repr(self.value)})"

    def to_detection(self) -> Tuple[str, List[Union[List, Dict]]]:
        """Convert a not expression to a detection condition"""

        return "{}", [{self.field + "|startswith": self.value}]


class FieldRegex(FieldComparison):
    """Compare a field with a regular expression"""

    value: str

    def __repr__(self):
        return f"MATCH({self.field}, {repr(self.value)})"

    def to_field_with_modifiers(self) -> str:
        return f"{self.field}|re"

    def to_detection(self) -> Tuple[str, List[Union[List, Dict]]]:
        """Convert a not expression to a detection condition"""

        return "{}", [{self.field + "|re": self.value}]


class KeywordSearch(Expression):
    """Search for a literal keyword/string instead of a direct comparison"""

    value: Any

    def __repr__(self) -> str:
        return f"KEYWORD({repr(self.value)})"

    def to_detection(self) -> Tuple[str, List[Union[List, Dict]]]:
        """Convert a not expression to a detection condition"""

        return "{}", [[self.value]]


def base64offset_modifier(field: str, value: Any) -> List[str]:
    """Build the expression for matching a base64offset modified expression.

    NOTE: I don't fully understand what's going on here, but I ripped it from
    pySigma... :eyes:
    """

    start = (0, 2, 3)
    end = (None, -3, -2)

    if not isinstance(value, Union[str, bytes]):
        raise InvalidFieldValueError(
            field, Union[str, bytes], type(value), "base64offset"
        )

    encoded: bytes
    if isinstance(value, str):
        encoded = value.encode("utf-8")
    else:
        encoded = value

    return [
        base64.b64encode(i * b" " + encoded)[
            start[i] : end[(len(encoded) + 1) % 3]
        ].decode("utf-8")
        for i in range(3)
    ]


def base64_modifier(field: str, value: Any) -> str:
    """Base64 encode the field"""

    if not isinstance(value, Union[str, bytes]):
        raise InvalidFieldValueError(field, Union[str, bytes], type(value), "base64")

    if isinstance(value, str):
        value = value.encode("utf-8")

    return base64.b64encode(value).decode("utf-8")


def utf16le_modifier(field: str, value: Any, modifier: str = "utf16le") -> bytes:
    """Transform the value into bytes"""

    if not isinstance(value, str):
        raise InvalidFieldValueError(field, str, type(value), modifier)

    return value.encode("utf16le")


def wide_modifier(field: str, value: Any) -> bytes:
    return utf16le_modifier(field, value, modifier="wide")


def utf16_modifier(field: str, value: Any) -> bytes:
    return b"\xFF\xFE" + utf16le_modifier(field, value, modifier="utf16")


def utf16be_modifier(field: str, value: Any) -> bytes:

    if not isinstance(value, str):
        raise InvalidFieldValueError(field, str, type(value), "utf16be")

    return value.encode("utf16be")


MODIFIER_MAPPING: Dict[str, Callable] = {
    "contains": FieldContains,
    "base64": base64_modifier,
    "base64offset": base64offset_modifier,
    "endswith": FieldEndsWith,
    "startswith": FieldStartsWith,
    "utf16le": utf16le_modifier,
    "wide": lambda field, value: utf16le_modifier(field, value, "wide"),
    "utf16be": utf16be_modifier,
    "re": FieldRegex,
}


def build_key_value_expression(key: str, value: Union[list, str]) -> Expression:
    """Evaluate any modifiers in the given key and return a valid expression
    representing the key/value pair. These are taken directly from the detection
    definition."""

    field, *modifiers = key.split("|")

    # NOTE: We assume that "all" applied anywhere in the pipeline does the same
    # thing. The specification is vague on this, though...
    if "all" in modifiers:
        modifiers.remove("all")
        combo_class = LogicalAnd
    else:
        combo_class = LogicalOr

    if isinstance(value, list):
        return combo_class(args=[build_key_value_expression(key, v) for v in value])

    completed_modifiers = []
    modified: Any = value
    reversed_modifiers = modifiers[::-1]

    while reversed_modifiers:
        modifier = reversed_modifiers.pop()

        # If the last modifier yielded an expression, we can't apply more modifications
        if isinstance(modified, Expression):
            raise InvalidModifierCombinationError(field, modifier, completed_modifiers)

        # Make sure this modifier is valid
        if modifier not in MODIFIER_MAPPING:
            raise UnknownModifierError(field, modifier)

        # Build new modified value
        try:
            modified = MODIFIER_MAPPING[modifier](field=field, value=modified)
        except (TypeError, ValueError) as exc:
            # Construction of an expression seems to have failed due to the type of
            # the value, so we raise an invalid combination error here.
            raise InvalidModifierCombinationError(field, modifier, completed_modifiers)

        # If this modifier returned a list of new items, process them according to the
        # combination class (normally "or", but could be "and")
        if isinstance(modified, list):
            return combo_class(
                args=[
                    build_key_value_expression(
                        f"{field}|{'|'.join(reversed_modifiers[::-1])}", v
                    )
                    for v in modified
                ]
            )

        # Save list of completed modifiers
        completed_modifiers.append(modifier)

    # Some modifiers produce an expression explicitly while others
    # only modify the value.
    if isinstance(modified, Expression):
        return modified
    else:
        return FieldEquality(field=field, value=modified)


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
