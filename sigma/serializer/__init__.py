r"""
Serializers are used to convert a rule from the in-memory python representation
to other arbitrary formats (such as Splunk queries or Elastic EQL queries). A
serializer inherits from :py:class:`Serializer` and defines the
:py:meth:`~Serializer.serialize` method which can return an arbitrary object
which represents the serialized detection rule.
"""
import re
import pathlib
import functools
import importlib
import importlib.resources
from abc import ABC, abstractmethod
from typing import (
    Any,
    Dict,
    List,
    Type,
    Tuple,
    Union,
    Literal,
    ClassVar,
    Optional,
    Generator,
)
from importlib.abc import Traversable

import yaml
from yaml.error import YAMLError
from pydantic.main import BaseModel
from pydantic.error_wrappers import ValidationError

from sigma import logger
from sigma.util import CopyableSchema
from sigma.errors import (
    SerializerNotFound,
    SerializerValidationError,
    UnsupportedSerializerFormat,
)
from sigma.schema import Rule, RuleDetectionFields
from sigma.grammar import (
    FieldLike,
    LogicalOr,
    Expression,
    FieldRegex,
    LogicalAnd,
    LogicalNot,
    FieldLookup,
    FieldContains,
    FieldEndsWith,
    FieldEquality,
    KeywordSearch,
    FieldComparison,
    FieldStartsWith,
    FieldLookupRegex,
    LogicalExpression,
)
from sigma.transform import Transformation


class LogSourceMatch(BaseModel):
    """A single log source matching rule. The fields ``product``, ``service``
    and ``category`` are optional, but if specified must equal their respective
    fields in :py:attr:`Rule.logsource <sigma.schema.Rule.logsource>`.

    The provided :py:attr:`~LogSourceMatch.conditions` are in the same format
    as a field selector within the Sigma rule itself, and can contain any of
    the common modifiers. The given conditions are joined with a logical AND
    expression to any matching rules.

    The :py:attr:`~LogSourceMatch.index` can either be a string or list of
    strings and is used by some serializers to restrict the index on which
    the log search query is made.

    The name field is not used internally, but is helpful to organize your
    serializer configuration if you have multiple different logsource matching
    sections.
    """

    name: Optional[str]
    """ The matching rule name """
    product: Optional[str]
    """ Product match """
    service: Optional[str]
    """ Service name match """
    category: Optional[str]
    """ Category name match """
    conditions: Optional[RuleDetectionFields]
    """ List of field selectors to add to matching condition """
    index: Optional[Union[str, List[str]]]
    """ One or more indices to search """

    def compare(self, rule: Rule) -> bool:
        """Test if :py:attr:`Rule.logsource <sigma.schema.Rule.logsource` matches this
        logsource definition.

        :param rule: the rule to test
        :type rule: Rule
        :rtype: bool
        :returns: True if the rule's logsource details match this definition
        """

        if (
            (self.product and self.product != rule.logsource.product)
            or (self.service and self.service != rule.logsource.service)
            or (self.category and self.category != rule.logsource.category)
        ):
            return False

        return True

    @classmethod
    def __get_validators__(cls):
        yield cls.validate_detection
        yield from super().__get_validators__()

    @classmethod
    def validate_detection(cls, v):
        """Validate the schema for the"""

        assert isinstance(v, dict)

        if "conditions" in v:
            assert isinstance(v["conditions"], dict)
            v["conditions"] = RuleDetectionFields(v["conditions"])

        return v

    class Config(CopyableSchema):
        schema_extra = {
            "examples": [
                {
                    "name": "logsource match",
                    "product": "windows",
                    "category": "process_creation",
                    "index": "logs-*",
                }
            ]
        }


class LogSourceRules(BaseModel):
    """
    This class represents the ``logsource`` field of a serializer definition,
    and controls the selection of indices based on matching rule logsource
    details to a list of logsource criteria.

    A serializer can use the :py:meth:`~LogSourceRules.match_rule` method to
    identify matching logsource criteria defined by the serializer configuration
    and a list of matching indices to use when serializing the rule.
    """

    defaultindex: Optional[Union[str, List[str]]] = []
    """ The default index if no log sources match or no indices defined """
    merging: Union[Literal["or"], Literal["and"]] = "or"
    """ how to merge multiple matching log sources """
    rules: List[LogSourceMatch] = []
    """ List of log source matching rules """

    def match_rule(self, rule: Rule) -> Tuple[List[str], Rule]:
        """
        Match the given rule to one or more logsource matches and return
        a list of indices and a (possibly modified) rule. This process is
        similar to a rule transformation, but matches rules to LogSourceMatches
        by inspecting the :py:attr:`Rule.logsource <sigma.schema.Rule.logsource>`
        field.

        If no :py:class:`LogSourceMatch`'s match this rule or no indices are
        defined in the match objects, the default index will be returned. The
        indices returned will always be a list regardless of the length. If
        no default index is defined, then the first item in the returned
        tuple could be an empty list.

        The rule may have one or more conditional expressions joined to the
        original expression with a logical AND expression based on the conditions
        defined in one or more :py:class:`LogSourceMatch` matches and the
        :py:attr:`~LogSourceRules.merging` property.

        :param rule: the rule to match against logsource matches
        :type rule: Rule
        :rtype: Tuple[List[str], Rule]
        :returns: A tuple of (list_of_indices, modified_rule)
        """

        # Find matching logsource rules
        matches: List[LogSourceMatch] = []
        indices: List[str] = []
        for logsource_rule in self.rules:
            if not logsource_rule.compare(rule):
                continue

            if isinstance(logsource_rule.index, list):
                indices.extend(logsource_rule.index)
            elif isinstance(logsource_rule.index, str):
                indices.append(logsource_rule.index)

            matches.append(logsource_rule)

        if not matches:
            if self.defaultindex and isinstance(self.defaultindex, list):
                return self.defaultindex, rule
            elif self.defaultindex and isinstance(self.defaultindex, str):
                return [self.defaultindex], rule
            else:
                return [], rule

        if len(matches) > 1:
            if self.merging == "or":
                new_expression = LogicalOr(
                    args=[
                        c.conditions.build_expression()
                        for c in matches
                        if c.conditions is not None
                    ]
                ).postprocess(rule)
            else:
                new_expression = LogicalAnd(
                    args=[
                        c.conditions.build_expression()
                        for c in matches
                        if c.conditions is not None
                    ]
                ).postprocess(rule)
        elif matches[0].conditions is not None:
            new_expression = matches[0].conditions.build_expression().postprocess(rule)
        else:
            new_expression = None

        if new_expression is not None:
            rule.detection.update_expression(
                LogicalAnd(args=[rule.detection.expression, new_expression])
            )

        return (indices, rule)

    class Config(CopyableSchema):
        schema_extra = {
            "examples": [
                {
                    "defaultindex": "logs-*",
                    "merging": "or",
                    "rules": [LogSourceMatch.Config.schema_extra["examples"][0]],
                }
            ]
        }


class CommonSerializerSchema(BaseModel):
    """Base serializer schema which all schemas should inherit. Every serializer
    configuration is required to, at a minimum, conform to this schema. Custom
    serializers simply build off of this definition.

    The base definition is one of the following

    - A built-in serializer name (as seen in ``sigma list serializer``).
    - Path to a YAML serializer config
    - A fully qualified class name (e.g. ``package.module:ClassName``).

    Each transform definition must conform to the schema for the transform type,
    and at a minimum the :py:class:`Base Transformation Schema <sigma.transform.Transformation.Schema>`.
    """

    name: str
    """ Arbitrary name for this serialization schema """
    description: str
    """ Description of the schema """
    transforms: Optional[List[Transformation.Schema]]
    """ List of transforms to be applied """
    base: str
    """ The base type for this serialization. This is either the name of a builtin
    serializer class (e.g. TextQuerySerializer) or the name of another serialization
    schema file. If the latter case, the transforms from this serializer will be
    appended to the base, and any further configuration is ignored. """
    logsource: LogSourceRules = LogSourceRules()
    """ Rules to match log sources to indices """

    class Config(CopyableSchema):
        schema_extra = {
            "examples": [
                {
                    "name": "Serializer",
                    "description": "A serializer",
                    "transforms": [],
                    "base": "base_class",
                    "logsource": LogSourceRules.Config.schema_extra["examples"][0],
                }
            ]
        }


class Serializer(ABC):
    """Base serialization class for Sigma rules. This class facilitates
    the transformation and serialization of sigma rules into a variety
    of arbitrary formats."""

    DEFAULT_FORMAT: ClassVar[Optional[str]] = None
    """ Default format name when using dumps (used to highlight output) """
    Schema: ClassVar[Type[CommonSerializerSchema]]

    def __init__(self, schema: CommonSerializerSchema):
        self.schema = schema
        self.transforms: List[Transformation] = []

        self._extend_transforms(self.schema)

    @abstractmethod
    def serialize(self, rule: Union[Rule, List[Rule]], transform: bool = True) -> Any:
        """Serialize the given sigma rule into a new format. The return value can be
        any python object which represents the equivalent rule in a new format.

        :param rule: a rule or list of rules to serialize
        :type rule: Union[Rule, List[Rule]]
        :param transform: whether to apply transformations (default: True, mainly used internally for inheritence)
        :type transform: bool
        :rtype: Any
        :returns: The serialized representation of the rule or a list of serialized representations.
        """

    @abstractmethod
    def dumps(
        self,
        rule: Union[Rule, List[Rule]],
        format: Optional[str] = None,
        pretty: bool = False,
    ) -> str:
        """Serialize the given rule(s) and return a string representation. Regardless of
        the number of rules passed, this method should always return a single string in
        the requested format. Formats are things like "raw", "yaml", or "json". If the
        requested format is not supported, an :py:class:`~sigma.errors.UnsupportedSerializerFormat`
        exception should be raised. If no format is given, this method should use the
        default format for the serializer.

        :param rule: rule or list of rules to serialize and dump
        :type rule: Union[Rule, List[Rule]]
        :param format: a format for dumping (e.g. "yaml" or "json")
        :type format: str
        :param pretty: dump pretty-formatted output (default: false)
        :type pretty: bool
        :rtype: str
        :returns: A string representation of the rule in the new target format
        """

    def _extend_transforms(self, schema: CommonSerializerSchema):
        """Extend the current transform list with transforms from another
        serialization schema."""

        if schema.transforms is None:
            return

        for transform in schema.transforms:
            self.transforms.append(transform.load())

    def apply_rule_transform(self, rule: Rule) -> Rule:
        """Apply all rule and expression transformations, returning either
        a modified rule or a completely new rule depending on the transformations
        defined.

        :param rule: the rule to transform
        :type rule: Rule
        :rtype: Rule
        :returns: the transformed rule object (may be different from input)
        """

        for transform in self.transforms:
            rule = transform.transform_rule(rule)

        return rule

    @classmethod
    def load(cls, name: str, config: Optional[Dict[str, Any]] = None):
        """
        Load a serializer definition from any of:

        - Built-in definitions (see ``sigma list serializers``)
        - A local file path
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
            try:
                schema = BUILTIN_SERIALIZERS[name][0].Schema.parse_obj(config)
                return BUILTIN_SERIALIZERS[name][0](schema)
            except ValidationError as exc:
                raise SerializerValidationError(exc)
        else:
            try:
                module_name, clazz_name = name.split(":", maxsplit=1)
                module = importlib.import_module(module_name)
                serializer_type: Type[Serializer] = getattr(module, clazz_name)

                if not issubclass(serializer_type, Serializer):
                    raise ValueError

                schema = serializer_type.Schema.parse_obj(config)
                return serializer_type(schema)
            except ValidationError as exc:
                raise SerializerValidationError(exc)
            except (ValueError, ModuleNotFoundError, AttributeError) as exc:
                raise SerializerNotFound(name)

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

        try:
            schema = CommonSerializerSchema.parse_obj(definition)
        except ValidationError as exc:
            raise SerializerValidationError(exc)

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
            try:
                return cls.from_dict(yaml.safe_load(filp))
            except (ValidationError, YAMLError) as exc:
                raise SerializerValidationError(exc)


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
        field_like: str
        """ Format for matching a field to a single pattern (e.g. "{}  like~ {}") """
        field_match: str
        """ A format string to test a field with a globbing pattern (e.g. "{}: {}") """
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
        field_lookup: Optional[str]
        """ Format for matching a field to a list of patterns (e.g. "{} like~ {}") """
        field_lookup_regex: Optional[str]
        """ Format for matching a field to a list of regex patterns (e.g. "{} regex {}") """

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
            FieldLike: functools.partial(
                self._serialize_comparison, self.schema.field_like
            ),
            FieldEquality: functools.partial(
                self._serialize_comparison, self.schema.field_equality
            ),
            FieldLookup: self._serialize_in_expression,
            FieldLookupRegex: self._serialize_in_expression,
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

    def dumps(
        self,
        rule: Union[Rule, List[Rule]],
        format: Optional[str] = None,
        pretty: bool = False,
    ) -> str:
        """The rule(s) to a string. In the case of a TextQuerySerializer, this
        is the same as dumping the rule(s) directly, with newlines separating"""

        if format is not None and format != "raw":
            raise UnsupportedSerializerFormat(format)

        serialized = self.serialize(rule)

        return serialized if isinstance(serialized, str) else "\n".join(serialized)

    def _serialize_expression(self, expression: Any, group: bool = True):
        """Recursively serialize an expression"""

        result = self.expression_mapping.get(type(expression), str)(expression)
        if (
            isinstance(expression, Expression)
            and type(expression) not in self.expression_mapping
        ):
            logger.debug("%s not found in text query expression map", type(expression))

        if group and isinstance(expression, LogicalExpression):
            return self.schema.grouping.format(result)

        return result

    def _serialize_in_expression(
        self, expression: Union[FieldLookup, FieldLookupRegex]
    ) -> str:

        if isinstance(expression, FieldLookup):
            is_regex = False
            compare_clazz = FieldLike
            format_str = self.schema.field_lookup or ""
        else:
            is_regex = True
            compare_clazz = FieldRegex
            format_str = self.schema.field_lookup_regex or ""

        # No support for the correct lookup syntax
        if (self.schema.field_lookup_regex is None and is_regex) or (
            self.schema.field_lookup is None and not is_regex
        ):
            return self._serialize_expression(
                LogicalOr(
                    args=[
                        compare_clazz(field=expression.field, value=v)
                        for v in expression.value
                    ]
                )
            )

        return format_str.format(
            expression.field,
            self.schema.grouping.format(
                self.schema.list_separator.join(
                    [self._serialize_expression(a) for a in expression.value]
                )
            ),
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
