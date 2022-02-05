import re
import pathlib
import functools
import importlib
from abc import ABC, abstractmethod
from typing import IO, Any, Dict, List, Type, Union, ClassVar, Optional

import yaml
from pydantic.main import BaseModel

from sigma.schema import Rule
from sigma.grammar import (
    FieldIn,
    LogicalOr,
    Expression,
    FieldRegex,
    LogicalAnd,
    LogicalNot,
    FieldEndsWith,
    FieldEquality,
    KeywordSearch,
    CoreExpression,
    FieldComparison,
    FieldStartsWith,
    LogicalExpression,
)
from sigma.transform import Transformation, TransformationSchema


class CommonSerializerSchema(BaseModel):
    """Base serializer schema which all schemas should inherit"""

    name: str
    """ Arbitrary name for this serialization schema """
    description: str
    """ Description of the schema """
    transforms: Optional[List[TransformationSchema]]
    """ List of transforms to be applied """
    base: str
    """ The base type for this serialization. This is either the name of a builtin
    serializer class (e.g. TextQuerySerializer) or the name of another serialization
    schema file. If the latter case, the transforms from this serializer will be
    appended to the base, and any further configuration is ignored. """


class Serializer(ABC):
    """Base serialization class for Sigma rules. This class facilitates
    the transformation and serialization of sigma rules into a variety
    of arbitrary formats."""

    Schema: ClassVar[Type[CommonSerializerSchema]]

    def __init__(self, schema: CommonSerializerSchema):
        self.schema = schema
        self.transforms: List[Transformation] = []

        self._extend_transforms(self.schema)

    @abstractmethod
    def serialize(self, rule: Union[Rule, List[Rule]]) -> Any:
        """Serialize the given sigma rule into a new format"""

    # @abstractmethod
    def dump(self, rule: Union[Rule, List[Rule]], filp: IO):
        """Serialize one or more rules and dump them to a file"""

    def _extend_transforms(self, schema: CommonSerializerSchema):

        if schema.transforms is None:
            return

        for transform in schema.transforms:
            self.transforms.append(transform.build())

    def apply_rule_transform(self, rule: Rule) -> Rule:
        """Apply all rule-level transformations"""

        for transform in self.transforms:
            rule = transform.transform_rule(rule)

        return rule

    def apply_expression_transform(
        self, rule: Rule, expression: Expression
    ) -> Expression:
        """Apply all transformations to this expression and every sub-expression"""

        if isinstance(expression, CoreExpression):
            expression.args = [
                self.apply_expression_transform(rule, a)
                if isinstance(a, Expression)
                else a
                for a in expression.args
            ]

        for transform in self.transforms:
            expression = transform.transform_expression(rule, expression)

        return expression

    @classmethod
    def from_dict(cls, definition: Dict[str, Any]) -> "Serializer":
        """Construct a serializer from a dictionary definition (normally loaded from
        yaml or JSON)."""

        schema = CommonSerializerSchema.parse_obj(definition)

        if pathlib.Path(schema.base).is_file():
            with open(schema.base) as filp:
                base = cls.from_dict(yaml.safe_load(filp))
                base._extend_transforms(schema)

            return base
        elif schema.base in BUILTIN_SERIALIZERS:
            schema = BUILTIN_SERIALIZERS[schema.base].Schema.parse_obj(definition)
            return BUILTIN_SERIALIZERS[schema.base](schema)
        else:
            module_name, clazz_name = schema.base.split(":", maxsplit=1)
            module = importlib.import_module(module_name)
            serializer_type: Type[Serializer] = getattr(module, clazz_name)

            schema = serializer_type.Schema.parse_obj(definition)
            return serializer_type(schema)

    @classmethod
    def from_yaml(cls, path: Union[pathlib.Path, str]) -> "Serializer":
        """Construct a serializer from a definition in a yaml file"""

        with open(path) as filp:
            return cls.from_dict(yaml.safe_load(filp))


class TextQuerySerializer(Serializer):
    """A basic serializer which only produces a static text query based on the
    condition and detection fields."""

    class Schema(CommonSerializerSchema):
        quote: str
        """ The character used for literal escapes in strings """
        escape: str
        """ The character used to escape the following character in a string """
        list_separator: str
        """ The string used to separate list items """
        or_format: str
        """ A format string to construct an OR expression (e.g. "{} or {}") """
        and_format: str
        """ A format string to construct an AND expression (e.g. "{} or {}") """
        not_format: str
        """ A format string to construct a NOT expression (e.g. "not {}") """
        grouping: str
        """ A format string to construct a grouping (e.g. "({})") """
        escaped_characters: str
        """ Characters aside from the quote and escape character that require escaping """
        field_equality: str
        """ A format string to test field equality (e.g. "{} == {}") """
        field_match: str
        """ A format string to test a field with a globbing pattern (e.g. "{}: {}") """
        field_in: str
        """ A format string to test if a field is in a list (e.g. "{} in {}") """
        field_regex: str
        """ A format string to test if a field matches a regex (e.g. "{} match {}")"""
        keyword: str
        """ A format string to match a keyword across all fields (e.g. "{}") """
        field_startswith: str
        """ A format string to test if a field starts with a string """
        field_endswith: str
        """ A format string to test if a field ends with a string """
        field_contains: str
        """ A format string to test if a field contains another string """
        rule_separator: str
        """ Separator for when outputting multiple rules to a file """

    def __init__(self, schema: Schema):
        super().__init__(schema)

        self.schema = schema
        self.expression_mapping = {
            LogicalAnd: functools.partial(
                self._serialize_chained_core_expression, self.schema.and_format
            ),
            LogicalOr: functools.partial(
                self._serialize_chained_core_expression, self.schema.or_format
            ),
            LogicalNot: functools.partial(
                self._serialize_core_expression, self.schema.not_format
            ),
            FieldEquality: functools.partial(
                self._serialize_comparison, self.schema.field_equality
            ),
            FieldEndsWith: functools.partial(
                self._serialize_comparison, self.schema.field_endswith
            ),
            FieldStartsWith: functools.partial(
                self._serialize_comparison, self.schema.field_startswith
            ),
            FieldIn: self._serialize_in_expression,
            FieldRegex: functools.partial(
                self._serialize_comparison, self.schema.field_regex
            ),
            KeywordSearch: functools.partial(
                self._serialize_keyword, self.schema.keyword
            ),
            str: self._serialize_string,
        }

    def serialize(self, rule: Union[Rule, List[Rule]]) -> Union[str, List[str]]:
        """Serialize the rule to a single text query"""

        if isinstance(rule, list):
            return [self.serialize(r) for r in rule]

        rule = self.apply_rule_transform(rule)
        expression = self.apply_expression_transform(
            rule, rule.detection.parse_grammar()
        )

        return self._serialize_expression(expression, group=False)

    def _serialize_expression(self, expression: Any, group: bool = True):
        """Recursively serialize an expression"""

        result = self.expression_mapping.get(type(expression), str)(expression)

        if group and isinstance(expression, LogicalExpression):
            return self.schema.grouping.format(result)

        return result

    def _serialize_in_expression(self, expression: FieldIn) -> str:
        return self.schema.grouping.format(
            self.schema.list_separator.join(
                [self._serialize_expression(a) for a in expression.value]
            )
        )

    def _serialize_comparison(self, fmt: str, expression: FieldComparison) -> str:
        return fmt.format(
            expression.field, self._serialize_expression(expression.value)
        )

    def _serialize_core_expression(
        self, fmt: str, expression: LogicalExpression
    ) -> str:
        return fmt.format(*[self._serialize_expression(a) for a in expression.args])

    def _serialize_chained_core_expression(
        self, fmt: str, expression: LogicalExpression
    ) -> str:

        result = self._serialize_expression(expression.args[0])
        for i in range(1, len(expression.args)):
            result = fmt.format(result, self._serialize_expression(expression.args[i]))

        return result

    def _serialize_keyword(self, fmt: str, expression: KeywordSearch) -> str:
        return fmt.format(self._serialize_expression(expression.value))

    def _serialize_string(self, expression: str) -> str:

        # Replace characters which need escaping and format with quoting
        return self.schema.quote.format(
            re.sub(
                self.schema.escaped_characters,
                lambda m: self.schema.escape.format(m.group(1)),
                expression,
            )
        )


BUILTIN_SERIALIZERS: Dict[str, Type[Serializer]] = {
    "TextQuerySerializer": TextQuerySerializer
}
