""" Base transformation class for inline modification during rule serialization """


from abc import ABC, abstractmethod
from typing import Any, Dict, Type

from pydantic.main import BaseModel

from sigma.schema import Rule
from sigma.grammar import Expression, FieldComparison


class Transformation(ABC):
    """Base transformation class for inline modification during rule serialization"""

    def __init__(self, config: Dict[str, Any]):
        pass

    @abstractmethod
    def transform_rule(self, rule: Rule) -> Rule:
        """Transform the given rule by either modifying it inline or returning an
        entirely new rule."""

    @abstractmethod
    def transform_expression(self, rule: Rule, expression: Expression) -> Expression:
        """Transform the given parsed condition expression"""

    @classmethod
    @abstractmethod
    def from_dict(cls, definition: Dict[str, Any]):
        """Construct a transformation instance from a definition (usually from yaml)"""


class FieldTransform(Transformation):
    """Transformation which replacing field names from an explicit map"""

    def __init__(self, mapping: Dict[str, str]):
        super().__init__(mapping)

        self.mapping = mapping

    def transform_rule(self, rule: Rule) -> Rule:
        """We don't provide any rule-level transforms, so just return unmodified"""
        return rule

    def transform_expression(self, rule: Rule, expression: Expression) -> Expression:
        """Replace all field comparisons based on the mapping"""

        if isinstance(expression, FieldComparison) and expression.field in self.mapping:
            expression.field = self.mapping[expression.field]

        return expression

    @classmethod
    def from_dict(cls, definition: Dict[str, Any]):
        """Construct a FieldTransform from a dictionary"""

        if any([not isinstance(v, str) for v in definition.values()]):
            raise ValueError("expected dict[str,str]")

        return cls(definition)


BUILTIN_TRANSFORMS: Dict[str, Type[Transformation]] = {"field": FieldTransform}


class TransformationSchema(BaseModel):
    """Schema for loading a transformation from a dict"""

    type: str
    """ The transformation type to use """
    config: Dict[str, Any]
    """ A dictionary containing configuration specific to the transform type """

    def build(self) -> Transformation:
        return BUILTIN_TRANSFORMS[self.type](self.config)
