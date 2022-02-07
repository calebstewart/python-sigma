"""
Sigma rule transformation classes.

Sigma transformations can operator on either rules as a whole and/or on
individual expressions within the evaluated detection condition. The most
commonly used transform is the :py:class:`FieldTransform` which is used to
replace built-in field names with custom field names.

.. code-block:: python
    :caption: Example Custom Transformation Class

    class CustomTransform(Transformation):

        def __init__(self, config: Dict[str, Any]):
            # Validate and/or use the configuration if needed
            super().__init__(config)

        def transform_rule(self, rule: Rule) -> Rule:
            # Modify the rule
            rule.title += " a modified title!"

        def transform_expression(self, expression: Expression) -> Expression:
            # Modify an expression
            return expression

Transformation Schema
---------------------

Transformations can also be loaded from a serialized schema, normally within
a serializer configuration. A transformation schema has two fields: ``type``
and ``config``. The transformation type can either be one of the built-in
transformation names or a fully-qualified python class path formatted as
``package.module:ClassName``.

.. code-block:: yaml
    :caption: Example YAML transformation definition

    transformations:
        - type: field
          config:
            CommandLine: process.command_line
            Image: process.executable
            ParentImage: process.parent.executable

"""
import importlib
from abc import ABC
from enum import Enum
from typing import Any, Dict, Type, Tuple, Literal, Pattern, Optional, Generator

from pydantic.main import BaseModel
from pydantic.fields import Field

from sigma.errors import SigmaError, UnknownTransform
from sigma.schema import Rule
from sigma.grammar import (
    Expression,
    FieldContains,
    FieldEndsWith,
    FieldEquality,
    FieldComparison,
    FieldStartsWith,
)


class ExpressionType(str, Enum):
    """Defines the types of expressions we can modify"""

    ENDSWITH = "endswith"
    STARTSWITH = "startswith"
    CONTAINS = "contains"


class Transformation(ABC):
    """Base transformation class for inline modification during rule serialization

    :param type: type of transformation
    :type type: str
    """

    class Schema(BaseModel):
        """Common transformation configuration schema. Specific transforms extend
        this class to provide structured configuration information."""

        type: str
        """ Name of the transformation type """

        class Config:
            extra = "allow"

        def load(self) -> "Transformation":
            """Construct a transformation instance from the schema."""

            clazz = Transformation.lookup_class(self.type)
            schema = clazz.Schema.parse_obj(self.dict())
            return clazz(schema)

    def __init__(self, config: Schema):
        pass

    def transform_rule(self, rule: Rule) -> Rule:
        """Transform the given rule by either modifying it inline or returning an
        entirely new rule. The default implementation simply returns the original
        rule."""

        return rule

    def transform_expression(self, rule: Rule, expression: Expression) -> Expression:
        """Transform the given expression by either modifying it or returning an
        entirely new expression. This method is called recursively on each
        sub-expression, so you need-not evaluate sub-expressions explicitly.
        The default implementation simply returns the original expression."""

        return expression

    @classmethod
    def lookup_class(cls, name: str) -> Type["Transformation"]:
        """Lookup the class backing the given transformation type name or fully-qualified
        class name"""

        if name in BUILTIN_TRANSFORMS:
            clazz = BUILTIN_TRANSFORMS[name][0]
        else:
            try:
                module_name, class_name = name.split(":", maxsplit=1)
                module = importlib.import_module(module_name)
                clazz: Type[Transformation] = getattr(module, class_name)

                if clazz is None or not issubclass(clazz, Transformation):
                    raise UnknownTransform(f"{name}: not a transformation class")
            except (ValueError, ModuleNotFoundError) as exc:
                raise UnknownTransform(name) from exc

        return clazz

    @classmethod
    def enumerate_builtin(cls) -> Generator[Tuple[str, str], None, None]:
        """Enumerate all built-in transformations. This method yields tuples of
        (name, description) for each built-in transformation."""

        for name, (_, description) in BUILTIN_TRANSFORMS.items():
            yield (name, description)


class FieldMatchReplace(Transformation):
    r"""
    Transform a field matching expression with a matching value to a field equality
    comparison. This transformation accepts the following configs: field, pattern, target and type.
    The type is one of endswith, startswith or contains. The field is the name of the field
    being compared. Pattern is a regular expression which must match the value of the matching
    expression, and must also contain a regex group which will be substituted as value in the
    new equality expression. The target is the name of the field used in the new equality
    expression. If the target is not provided, the field is reused in the equality expression.
    As an example, the following config will replace ``endsWith(process.executable, "\\test.exe")``
    with ``process.name == "test.exe"``.

    .. code-block: yaml

        - type: endswith
          expression: endswith
          field: process.executable
          pattern: "\\\\(.*)"
          target: process.name
    """

    class Schema(Transformation.Schema):
        """Configuration schema for this transformation"""

        type: Literal["match_replace"]
        expression: ExpressionType
        field: str
        pattern: Pattern
        target: Optional[str]

        class Config:
            extra = "forbid"

            schema_extra = {
                "examples": [
                    {
                        "type": "match_replace",
                        "expression": "endswith",
                        "field": "process.executable",
                        "pattern": r"\\(.*)",
                        "target": "process.name",
                    }
                ]
            }

    # map above expression types to expression classes
    VALID_TYPES: Dict[str, Type[Expression]] = {
        ExpressionType.ENDSWITH: FieldEndsWith,
        ExpressionType.STARTSWITH: FieldStartsWith,
        ExpressionType.CONTAINS: FieldContains,
    }

    def __init__(self, schema: Schema):
        super().__init__(schema)

        self.type = self.VALID_TYPES[schema.expression]
        self.field = schema.field
        self.pattern = schema.pattern
        self.target = schema.target or schema.field

    def transform_expression(
        self, rule: Rule, expression: FieldComparison
    ) -> Expression:
        """Transform the given expression"""

        # Only transform the requested expression type
        if not isinstance(expression, self.type):
            return expression

        # Test if the value matches the regular expression
        match = self.pattern.fullmatch(expression.value)

        # Don't modify the expression if it doesn't match
        if match is None:
            return expression

        # Replace this expression with a simple equality using
        # the regular expression matching group.
        new_expression = FieldEquality(
            field=self.target, value=match.group(1)
        ).postprocess(rule, expression.parent)

        return new_expression


class FieldMap(Transformation):
    """Transform sigma rule expressions to replace field names. Transformation
    configuration is a mapping between built-in field names and custom field names.

    :param config: a mapping between built-in field names and custom field names
    :type config: Dict[str, str]
    """

    class Schema(Transformation.Schema):
        """Field mapping configuration definition"""

        type: Literal["field_map"]
        mapping: Dict[str, str]
        """ Field name mappings """

        class Config:
            extra = "forbid"

            schema_extra = {
                "examples": [
                    {
                        "type": "field_map",
                        "mapping": {
                            "CommandLine": "process.command_line",
                            "Image": "process.executable",
                        },
                    }
                ]
            }

    def __init__(self, schema: Schema):
        super().__init__(schema)

        self.mapping = schema.mapping

    def transform_expression(self, rule: Rule, expression: Expression) -> Expression:
        """Replace any field names based on the provided mapping. If the expression
        is not a field comparison, this method simply returns the expression unaltered."""

        if isinstance(expression, FieldComparison) and expression.field in self.mapping:
            expression.field = self.mapping[expression.field]

        return expression


class FieldFuzzyMap(Transformation):
    """Replace field names with an explicit mapping. The configuration for this
    transformation is a mapping between Sigma field names and your backend field
    names. This version of a field map will replace field names ignoring case and
    also test against snake_case and CamelCase versions of the given fields. All
    source fields in the mapping should be in snake_case.
    """

    class Schema(Transformation.Schema):
        """Field mapping configuration definition"""

        type: Literal["field_fuzy_map"]
        mapping: Dict[str, str]
        """ Field name mappings """

        class Config:
            extra = "forbid"

            schema_extra = {
                "examples": [
                    {
                        "type": "field_map",
                        "mapping": {
                            "command_line": "process.command_line",
                            "image": "process.executable",
                        },
                    }
                ]
            }

    def __init__(self, schema: Schema):
        super().__init__(schema)

        self.mapping = {key.lower(): value for key, value in schema.mapping.items()}
        self.mapping.update(
            {key.replace("_", ""): value for key, value in schema.mapping.items()}
        )

    def transform_expression(self, rule: Rule, expression: Expression) -> Expression:
        """Replace any field names based on the provided mapping. If the expression
        is not a field comparison, this method simply returns the expression unaltered."""

        if (
            isinstance(expression, FieldComparison)
            and expression.field.lower() in self.mapping
        ):
            expression.field = self.mapping[expression.field.lower()]

        return expression


BUILTIN_TRANSFORMS: Dict[str, Tuple[Type[Transformation], str]] = {
    "field_map": (FieldMap, "Map Sigma field names to custom field names"),
    "field_fuzzy_map": (
        FieldFuzzyMap,
        "Map Sigma fields names to custom field names with fuzzy matching",
    ),
    "match_replace": (
        FieldMatchReplace,
        "Replace wildcard matching with strict equality based on regex patterns",
    ),
}


class TransformationSchema(BaseModel):
    """Schema for loading a transformation from a dictionary.

    :param type: type of transformation (either a built-in name from BUILTIN_TRANSFORMS
                 or a fully-qualified python module/class name like ``package:class``)
    :type type: str
    :param config: transformation configuration, specific to the transform type.
    """

    type: str
    """ The transformation type to use """
    config: Dict[str, Any]
    """ A dictionary containing configuration specific to the transform type """

    def build(self) -> Transformation:
        """Construct a transformation instance from the schema."""

        if self.type in BUILTIN_TRANSFORMS:
            return BUILTIN_TRANSFORMS[self.type][0](self.config)
        else:
            try:
                module_name, class_name = self.type.split(":", maxsplit=1)
                module = importlib.import_module(module_name)
                transform_type: Type[Transformation] = getattr(module, class_name)

                return transform_type(self.config)
            except (ValueError, ModuleNotFoundError) as exc:
                raise UnknownTransform(self.type) from exc
