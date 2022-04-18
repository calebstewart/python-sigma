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
import fnmatch
import itertools
from typing import Any, Dict, List, Type, Tuple, Union, Callable, ClassVar, Optional

from pydantic import BaseModel
from pyparsing import Word, Keyword, Literal, opAssoc, alphanums, infixNotation
from pyparsing.results import ParseResults

from sigma import logger
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

        if isinstance(self, CoreExpression):
            self.args = [
                e.visit(callback) if isinstance(e, Expression) else e for e in self.args
            ]

        return callback(self)

    def to_detection(self) -> Tuple[str, List[Union[List, Dict]]]:
        """Convert an expression to a condition string and a dict of new detection
        selectors."""

        raise NotImplementedError

    def evaluate(self, fields: Dict[str, Any]) -> bool:
        """Evaluate this expression with the given field values

        :param fields: dictionary mapping field names to values
        :type fields: Dict[str, Any]
        :rtype: bool
        :returns: True if the fields set matches; False otherwise
        """

        raise NotImplementedError


class CoreExpression(Expression):
    """Core expressions are the ones directly parsed from the condition
    grammar (as opposed to equality expressions parsed from detection
    tests)."""

    args: List[Union[Expression, str]]

    def __eq__(self, other):
        """Compare two core expressions for equality"""

        if not isinstance(other, type(self)):
            return False

        return repr(self) == repr(other)

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

    def postprocess(
        self,
        detection: "sigma.schema.RuleDetection",
        parent: Optional["Expression"] = None,
    ) -> "Expression":
        """Handle "not null" situations"""

        expression = super().postprocess(detection, parent)

        if isinstance(self.args[0], LogicalOr) or isinstance(self.args[0], LogicalAnd):
            new_type = LogicalOr if isinstance(self.args[0], LogicalAnd) else LogicalAnd

            return new_type(args=[LogicalNot(args=[a]) for a in self.args[0].args])

        if isinstance(self.args[0], FieldComparison) and self.args[0].value is None:
            logger.warn(
                "rule: %s: %s: using deprecated 'not null' expression",
                detection.rule.id,
                self.args[0].field,
            )
            return FieldNotEmpty(field=self.args[0].field)

        return expression

    def to_detection(self) -> Tuple[str, List[Union[List, Dict]]]:
        """Convert a not expression to a detection condition"""

        condition, selectors = self.args[0].to_detection()

        return f"not {condition}", selectors

    def evaluate(self, fields: Dict[str, Any]) -> bool:
        if not isinstance(self.args[0], Expression):
            return False
        return not self.args[0].evaluate(fields)


class LogicalOr(LogicalExpression):
    """Logical Or expression"""

    operator: ClassVar[bool] = True

    def postprocess(
        self, rule: "sigma.schema.RuleDetection", parent: Optional["Expression"] = None
    ) -> "Expression":

        # if len(self.args) == 1:
        #     return self.args[0].postprocess(rule, parent=parent)
        #

        # Post-process sub-arguments
        self.args = [arg.postprocess(rule, self) for arg in self.args]

        grouped_re = {}
        grouped_like = {}
        others = []
        for arg in self.args:
            if isinstance(arg, FieldLike):
                if arg.field not in grouped_like:
                    grouped_like[arg.field] = []
                grouped_like[arg.field].append(arg)
            elif isinstance(arg, FieldRegex):
                if arg.field not in grouped_re:
                    grouped_re[arg.field] = []
                grouped_re[arg.field].append(arg)
            else:
                others.append(arg)

        for field, args in grouped_re.items():
            if len(args) == 1:
                others.append(args[0])
            else:
                others.append(
                    FieldLookupRegex(
                        field=field, value=[a.value for a in args]
                    ).postprocess(rule, self)
                )

        for field, args in grouped_like.items():
            if len(args) == 1:
                others.append(args[0])
            else:
                others.append(
                    FieldLookup(field=field, value=[a.value for a in args]).postprocess(
                        rule, self
                    )
                )

        if len(others) == 1:
            others[0].parent = parent
            return others[0]

        self.args = others
        self.parent = parent

        return self

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

    def evaluate(self, fields: Dict[str, Any]) -> bool:
        for arg in self.args:
            if not isinstance(arg, Expression):
                continue
            if arg.evaluate(fields):
                return True
        return False


class LogicalAnd(LogicalExpression):
    """Logical And Expression"""

    operator: ClassVar[bool] = True

    def postprocess(
        self, rule: "sigma.schema.RuleDetection", parent: Optional["Expression"] = None
    ) -> "Expression":

        # if len(self.args) == 1:
        #    return self.args[0].postprocess(rule, parent=parent)

        return super().postprocess(rule, parent=parent)

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

    def evaluate(self, fields: Dict[str, Any]) -> bool:
        for arg in self.args:
            if not isinstance(arg, Expression):
                continue
            if not arg.evaluate(fields):
                return False
        return True


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

    def __eq__(self, other) -> bool:

        return (
            isinstance(other, type(self))
            and self.field == other.field
            and self.value == other.value
        )

    def to_field_with_modifiers(self) -> str:
        return self.field

    def to_detection(self) -> Tuple[str, List[Union[List, Dict]]]:
        """Convert a not expression to a detection condition"""

        return "{}", [{self.to_field_with_modifiers(): self.value}]


class FieldNotEmpty(FieldComparison):
    """A field comparison such as 'field is not null'"""

    value: None = None

    def __repr__(self) -> str:
        return f"NOTNULL({self.field})"

    def to_detection(self) -> Tuple[str, List[Union[List, Dict]]]:
        return "not {}", [{self.to_field_with_modifiers(): None}]


class FieldEquality(FieldComparison):
    """Test for field equality"""

    def __repr__(self) -> str:
        return f"EQ({self.field}, {repr(self.value)})"

    def to_detection(self) -> Tuple[str, List[Union[List, Dict]]]:
        """Convert a not expression to a detection condition"""

        return "{}", [{self.field: self.value}]

    def evaluate(self, fields: Dict[str, Any]) -> bool:

        try:
            if isinstance(fields[self.field], list):
                return any(v == self.value for v in fields[self.field])

            return fields[self.field] == self.value
        except KeyError:
            return False


class FieldLike(FieldComparison):
    """Test for field equality"""

    def __repr__(self) -> str:
        return f"LIKE({self.field}, {repr(self.value)})"

    def to_detection(self) -> Tuple[str, List[Union[List, Dict]]]:
        """Convert a not expression to a detection condition"""

        return "{}", [{self.field: self.value}]

    def evaluate(self, fields: Dict[str, Any]) -> bool:
        try:
            if isinstance(fields[self.field], list):
                return any(fnmatch.fnmatch(self.value, v) for v in fields[self.field])
            return fnmatch.fnmatch(self.value, fields[self.field])
        except KeyError:
            return False


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

    def evaluate(self, fields: Dict[str, Any]) -> bool:
        try:
            if isinstance(fields[self.field], list):
                return any(self.value in v for v in fields[self.field])
            return self.value in fields[self.field]
        except KeyError:
            return False


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

    def evaluate(self, fields: Dict[str, Any]) -> bool:
        try:
            if isinstance(fields[self.field], list):
                return any(v.endswith(self.value) for v in fields[self.field])
            return fields[self.field].endswith(self.value)
        except KeyError:
            return False


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

    def evaluate(self, fields: Dict[str, Any]) -> bool:
        try:
            if isinstance(fields[self.field], list):
                return any(v.startsswith(self.value) for v in fields[self.field])
            return fields[self.field].startswith(self.value)
        except KeyError:
            return False


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

    def evaluate(self, fields: Dict[str, Any]) -> bool:
        import re

        try:
            if isinstance(fields[self.field], list):
                return any(
                    re.search(self.value, v) is not None for v in fields[self.field]
                )
            return re.search(self.value, fields[self.field]) is not None
        except KeyError:
            return False


class FieldLookup(FieldComparison):
    """Check if the field is in a list of values with wildcard matching"""

    value: List[Any]

    def __repr__(self):
        return f"IN({self.field}, {repr(self.value)})"

    def evaluate(self, fields: Dict[str, Any]) -> bool:
        try:
            field_value = fields[self.field]
            for pattern in self.value:
                if isinstance(field_value, list):
                    for v in field_value:
                        if fnmatch.fnmatch(v, pattern):
                            return True
                elif fnmatch.fnmatch(field_value, pattern):
                    return True
        except KeyError:
            pass
        return False


class FieldLookupRegex(FieldLookup):
    """Field lookup but with a regex modifier"""

    value: List[str]

    def to_field_with_modifiers(self) -> str:
        return f"{self.field}|re"

    def __repr__(self):
        return f"REGEX({self.field}, {repr(self.value)})"

    def evaluate(self, fields: Dict[str, Any]) -> bool:
        import re

        try:
            field_value = fields[self.field]
            for pattern in self.value:
                if isinstance(field_value, list):
                    for v in field_value:
                        if re.search(pattern, v) is not None:
                            return True
                elif re.search(pattern, field_value) is not None:
                    return True
        except KeyError:
            pass
        return False


class KeywordSearch(Expression):
    """Search for a literal keyword/string instead of a direct comparison"""

    value: Any

    def __repr__(self) -> str:
        return f"KEYWORD({repr(self.value)})"

    def to_detection(self) -> Tuple[str, List[Union[List, Dict]]]:
        """Convert a not expression to a detection condition"""

        return "{}", [[self.value]]

    def evaluate(self, fields: Dict[str, Any]) -> bool:
        for field_value in fields.values():
            if fnmatch.fnmatch(str(field_value), self.value):
                return True

        return False


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

    return value.encode("utf-16le")


def wide_modifier(field: str, value: Any) -> bytes:
    return utf16le_modifier(field, value, modifier="wide")


def utf16_modifier(field: str, value: Any) -> bytes:
    return b"\xFF\xFE" + utf16le_modifier(field, value, modifier="utf16")


def utf16be_modifier(field: str, value: Any) -> bytes:

    if not isinstance(value, str):
        raise InvalidFieldValueError(field, str, type(value), "utf16be")

    return value.encode("utf-16be")


MODIFIER_MAPPING: Dict[str, Callable] = {
    "contains": FieldContains,
    "base64": base64_modifier,
    "base64offset": base64offset_modifier,
    "endswith": FieldEndsWith,
    "startswith": FieldStartsWith,
    "utf16le": utf16le_modifier,
    "wide": lambda field, value: utf16le_modifier(field, value, "wide"),
    "utf16be": utf16be_modifier,
    "utf16": utf16_modifier,
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
            if isinstance(modified, list):
                modified = [
                    MODIFIER_MAPPING[modifier](field=field, value=m) for m in modified
                ]
            else:
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
    elif isinstance(modified, list):
        return LogicalOr(
            args=[
                FieldLike(field=field, value=v) if not isinstance(v, Expression) else v
                for v in modified
            ]
        )
    else:
        return FieldLike(field=field, value=modified)


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
