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
import re
import importlib
from abc import ABC
from typing import Any, Dict, Type, Tuple

from pydantic.main import BaseModel

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


class Transformation(ABC):
    """Base transformation class for inline modification during rule serialization

    :param config: a dictionary of transform configurations which only have meaning
                   in the context of a specific transform type.
    :type config: Dict[str, Any]
    """

    def __init__(self, config: Dict[str, Any]):
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
          config:
            type: endswith
            field: process.executable
            pattern: "\\\\(.*)"
            target: process.name
    """

    VALID_TYPES: Dict[str, Type[Expression]] = {
        "endswith": FieldEndsWith,
        "startswith": FieldStartsWith,
        "contains": FieldContains,
    }

    def __init__(self, config: Dict[str, str]):
        super().__init__(config)

        for key in ["field", "pattern", "type"]:
            if key not in config:
                raise SigmaError(f"missing pattern transform config: {key}")

        if config["type"] not in self.VALID_TYPES:
            raise SigmaError(
                f"invalid pattern transform type: {config['type']} (expected on of {list(self.VALID_TYPES.keys())})"
            )

        self.type = self.VALID_TYPES[config["type"]]
        self.field = config["field"]
        self.pattern = re.compile(config["pattern"])
        self.target = config.get("target", self.field)

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

    def __init__(self, config: Dict[str, str]):
        super().__init__(config)

        self.mapping = config

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

    def __init__(self, config: Dict[str, str]):
        super().__init__(config)

        self.mapping = {key.lower(): value for key, value in config.items()}
        self.mapping.update(
            {key.replace("_", ""): value for key, value in config.items()}
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
