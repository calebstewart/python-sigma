r'''
Serializers are used to convert a rule from the in-memory python representation
to other arbitrary formats (such as Splunk queries or Elastic EQL queries).

Custom serializers must inherit from the :py:class:`Serializer` class, and define
the :py:class:`Serializer.Schema` to define the necessary configurations.

.. code-block:: python
    :caption: Example Custom Serializer

    class CustomSerializer(Serializer):
       """ Custom serialization module """

        class Schema(CommonSerializerSchema):
            # Define custom required options for the schema
            option: str

        def serialize(self, rule: Union[Rule, List[Rule]]) -> Any:
            # Access configuration through self.schema
            print(self.schema.option)

            # Operate on lists vs individual rules
            if isinstance(rule, list):
                return [self.serialize(r) for r in rule]

            # Apply rule transformations
            rule = self.apply_rule_transform(rule)

            # Get the condition expression
            expression = rule.detection.parse_grammar()

            # Apply expression transformations
            expression = self.apply_expression_transform(rule, expression)

            # Simple transform just serializes the expression
            return str(expression)

Loading Serializer from YAML or Dictionary
------------------------------------------

Serializers can be loaded and constructed automatically from a YAML file or dictionary
at runtime. The :py:class:`CommonSerializerSchema` class defines the base structure of
a serializer definition. The ``base`` field defines which serializer class will be
created from the definition. It can be any one of a name from ``BUILTIN_SERIALIZERS``,
the path to another YAML definition, or a fully qualified python class name. Class names
are formatted like ``package.module:ClassName`` and must refer to a sub-class of
:py:class:`Serializer`. Use :py:meth:`~.Serializer.from_yaml` to load from a YAML file
or :py:meth:`~Serializer.from_dict` to load from a dictionary.

.. code-block:: python
    :caption: Loading a built-in or custom serializer definition

    from sigma.serializer import Serializer

    # Load from a YAML file path
    serializer = Serializer.load("path/to/definition.yml")
    # Load from a built-in serializer definition (see sigma/data/serializers)
    serializer = Serializer.load("eql")


.. code-block:: yaml
    :caption: Example Serializer Definition File

    name: "Cool serializer"
    description: "A really cool serializer"
    base: "sigma.serializer:TextQuerySerializer"
    quote: '"{}"'
    escape: "\\{}"
    list_separator: ","
    or_format: "{} or {}"
    and_format: "{} and {}"
    not_format: "not {}"
    grouping: "({})"
    escaped_characters: "([\"\\])"
    field_equality: "{}: {}"
    field_in: "{}: {}"
    field_regex: "{} regex {}"
    field_match: "{} like {}"
    keyword: "{}"
    field_startswith: "startsWith({},{})"
    field_endswith: "endsWith({},{})"
    field_contains: "stringContains({})"
    rule_separator: "\n"
    transforms:
      - type: field
        config:
          CommandLine: process.command_line


Serializer Inheritance
----------------------

If the base field of a serializer is a path to a different YAML file, then
:py:meth:`~Serializer.from_yaml` will first load that serializer, and then augment
it by appending any newly defined transforms to the other serializer. No other
fields will be modified.

.. code-block:: yaml
    :caption: Example Inherited Serializer

    name: "Inherited Serializer"
    description: "We inherited this from someone."
    base: "path/to/serializer/definition.yml"
    transforms:
        - type: field
          config:
            Image: process.executable

When evaluating inherited base serializers, the following order of precedence is
followed:

- Default serializer definition files in ``sigma/data/serializers/`` (without ``.yml`` extension)
- Files with matching name/path
- Built-in named serializer classes (defined in ``BUILTIN_SERIALIZERS``)
- Fully qualified class names (e.g. ``package.module:ClassName``)

'''
import re
import pathlib
import functools
import importlib
import importlib.resources
from abc import ABC, abstractmethod
from typing import (
    IO,
    Any,
    Dict,
    List,
    Type,
    Tuple,
    Union,
    ClassVar,
    Optional,
    Generator,
)
from importlib.abc import Traversable

import yaml
from pydantic.main import BaseModel
from pydantic.fields import Field

from sigma.errors import SerializerNotFound
from sigma.schema import Rule
from sigma.grammar import (
    FieldIn,
    LogicalOr,
    Expression,
    FieldRegex,
    LogicalAnd,
    LogicalNot,
    FieldContains,
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
    def serialize(self, rule: Union[Rule, List[Rule]], transform: bool = True) -> Any:
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
    def load(cls, name: str, config: Optional[Dict[str, Any]] = None):
        """
        Load a serializer definition from any of:

        - Built-in definitions (under ``sigma/data/serializers/``)
        - A local file path
        - Built-in named serializers (defined by ``BUILTIN_SERIALIZERS``)
        - A fully qualified Python class path (e.g. ``package.module:ClassName``)

        If the provided name refers to a named serializer class or a fully qualified class
        name, then you should also provide the associated configuration dictionary to
        initialize the class. If no configuration is provided, an empty dictionary is
        passed to the classes initializer which could cause errors.

        If the provided name refers to a serializer definition file (built-in or local),
        then the configuration argument is ignored.

        :param name: name of the serializer to load
        :type name: str
        :rtype: Serializer
        :returns: A constructed serializer class from the given name/type
        """

        if config is None:
            config = {
                "name": "unnamed",
                "description": "unknown",
                "base": name,
                "transforms": [],
            }

        serializers_path = importlib.resources.files("sigma") / "data" / "serializers"

        if (serializers_path / (name + ".yml")).is_file():
            return cls.from_yaml(serializers_path / (name + ".yml"))
        elif pathlib.Path(name).is_file():
            return cls.from_yaml(name)
        elif name in BUILTIN_SERIALIZERS:
            schema = BUILTIN_SERIALIZERS[name][0].Schema.parse_obj(config)
            return BUILTIN_SERIALIZERS[name][0](schema)
        else:
            module_name, clazz_name = name.split(":", maxsplit=1)
            module = importlib.import_module(module_name)
            serializer_type: Type[Serializer] = getattr(module, clazz_name)

            schema = serializer_type.Schema.parse_obj(config)
            return serializer_type(schema)

    @classmethod
    def from_dict(cls, definition: Dict[str, Any]) -> "Serializer":
        """Construct a serializer from a dictionary definition conforming, at a minimum,
        to the :py:class:`CommonSerializerSchema` schema. Other configuration may be
        necessary to construct the given base serializer class.

        :param definition: a dictionary serializer configuration
        :type definition: Dict[str, Any]
        :rtype: Serializer
        :returns: A new serializer instance of the requested type
        """

        schema = CommonSerializerSchema.parse_obj(definition)

        return cls.load(schema.base, config=definition)

    @classmethod
    def from_yaml(cls, path: Union[pathlib.Path, str, Traversable]) -> "Serializer":
        """Construct a serializer from a definition in a yaml file. This is the same
        as loading the YAML into a python dictionary and using :py:meth:`Serializer.from_dict`.

        :param path: a path-like object or string path to a YAML serializer definition
        :type path: Union[pathlib.Path, str, Traversable]
        :rtype: Serializer
        :returns: A new serializer instance of the requested type
        """

        if isinstance(path, str):
            path = pathlib.Path(path)

        with path.open() as filp:
            return cls.from_dict(yaml.safe_load(filp))


class TextQuerySerializer(Serializer):
    """A basic serializer which only produces a static text query based on the
    condition and detection fields.

    :param schema: A valid TextQuerySerializer configuration schema
    :type schema: Schema
    """

    class Schema(CommonSerializerSchema):
        """Text Query configuration options which define how to combine the logical expressions
        into the correct query syntax for your detection engine."""

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
        field_startswith: Optional[str]
        """ A format string to test if a field starts with a string """
        field_endswith: Optional[str]
        """ A format string to test if a field ends with a string """
        field_contains: Optional[str]
        """ A format string to test if a field contains another string """
        prepend_result: str = Field("")
        """ String to prepend to the resulting query """
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
            FieldIn: self._serialize_in_expression,
            FieldRegex: functools.partial(
                self._serialize_comparison, self.schema.field_regex
            ),
            KeywordSearch: functools.partial(
                self._serialize_keyword, self.schema.keyword
            ),
            str: self._serialize_string,
        }

        if self.schema.field_endswith is not None:
            self.expression_mapping[FieldEndsWith] = functools.partial(
                self._serialize_comparison, self.schema.field_endswith
            )
        else:
            self.expression_mapping[FieldEndsWith] = functools.partial(
                self._serialize_with_wildcard, "*{}"
            )
        if self.schema.field_startswith is not None:
            self.expression_mapping[FieldStartsWith] = functools.partial(
                self._serialize_comparison, self.schema.field_startswith
            )
        else:
            self.expression_mapping[FieldStartsWith] = functools.partial(
                self._serialize_with_wildcard, "{}*"
            )
        if self.schema.field_contains is not None:
            self.expression_mapping[FieldContains] = functools.partial(
                self._serialize_comparison, self.schema.field_contains
            )
        else:
            self.expression_mapping[FieldContains] = functools.partial(
                self._serialize_with_wildcard, "*{}*"
            )

    def serialize(
        self, rule: Union[Rule, List[Rule]], transform: bool = True
    ) -> Union[str, List[str]]:
        """Serialize the rule to a single text query

        :param rule: a rule or list of rules to be serialized
        :type rule: Union[Rule, List[Rule]]
        :param transform: whether to apply transformations (default: True)
        :type transform: bool
        :rtype: Union[str, List[str]]
        :returns: the serialized rule or list of serialized rules (if a list was passed in)
        """

        if isinstance(rule, list):
            return [self.serialize(r) for r in rule]

        if transform:
            rule = rule.transform(self.transforms)

        return self._serialize_expression(rule.detection.expression, group=False)

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

    def _serialize_with_wildcard(self, fmt: str, expression: FieldComparison):
        return self.schema.field_match.format(
            expression.field, self._serialize_expression(fmt.format(expression.value))
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


from sigma.serializer.elastic import EventQueryLanguage, ElasticSecurityRule

BUILTIN_SERIALIZERS: Dict[str, Tuple[Type[Serializer], str]] = {
    "TextQuerySerializer": (
        TextQuerySerializer,
        "Base class for text-based queries (cannot be used directly)",
    ),
    "eql": (
        EventQueryLanguage,
        "Elastic Event Query Language (EQL) Text-Based Serializer",
    ),
    "es-rule": (
        ElasticSecurityRule,
        "Elastic Security EQL Rule in JSON format",
    ),
}


def get_builtin_serializers() -> Generator[Tuple[str, str], None, None]:
    """Iterate over built-in serializers. This method is a generator which yields
    a tuple of [name, description] for all built-in serializers."""

    for name, (_, description) in BUILTIN_SERIALIZERS.items():
        yield (name, description)

    for resource in (
        importlib.resources.files("sigma") / "data" / "serializers"
    ).iterdir():
        if not resource.name.endswith(".yml"):
            continue

        name = resource.name.removesuffix(".yml")
        with resource.open() as filp:
            definition = CommonSerializerSchema.parse_obj(yaml.safe_load(filp))

        yield (name, definition.description)


def get_serializer_class(name: str) -> Type[Serializer]:
    """Retrieve the class backing the given serializer"""

    serializers_path = importlib.resources.files("sigma") / "data" / "serializers"

    if (serializers_path / (name + ".yml")).is_file():
        with (serializers_path / (name + ".yml")).open() as filp:
            definition = CommonSerializerSchema.parse_obj(yaml.safe_load(filp))

        return get_serializer_class(definition.base)
    elif pathlib.Path(name).is_file():
        with open(name) as filp:
            definition = CommonSerializerSchema.parse_obj(yaml.safe_load(filp))

        return get_serializer_class(definition.base)
    elif name in BUILTIN_SERIALIZERS:
        return BUILTIN_SERIALIZERS[name][0]
    else:
        try:
            module_name, clazz_name = name.split(":", maxsplit=1)
            module = importlib.import_module(module_name)
            serializer_type: Type[Serializer] = getattr(module, clazz_name)

            return serializer_type
        except (ValueError, ModuleNotFoundError) as exc:
            raise SerializerNotFound(name) from exc
