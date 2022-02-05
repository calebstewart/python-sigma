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
from typing import Any, Dict, Type

from pydantic.main import BaseModel

from sigma.schema import Rule
from sigma.grammar import Expression, FieldComparison


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


class FieldTransform(Transformation):
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


BUILTIN_TRANSFORMS: Dict[str, Type[Transformation]] = {"field": FieldTransform}


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
            return BUILTIN_TRANSFORMS[self.type](self.config)
        else:
            module_name, class_name = self.type.split(":", maxsplit=1)
            module = importlib.import_module(module_name)
            transform_type: Type[Transformation] = getattr(module, class_name)

            return transform_type(self.config)
