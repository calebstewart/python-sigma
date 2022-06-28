""" Sigma specific errors and exceptions """


from typing import List, Type

from pydantic import ValidationError
from click.exceptions import ClickException
from pyparsing.exceptions import ParseException

from sigma import logger


class SigmaError(Exception):
    """Base generic sigma error. All other sigma errors are subclasses of this."""


class MultipleCorrelationError(SigmaError):
    """The given YAML file contained multiple correlation documents"""


class NoCorrelationDocument(SigmaError):
    """A YAML document contained multiple rules and no correlation"""


class MissingCorrelationRule(SigmaError):
    """A rule specified in a correlation document was not found"""


class DuplicateRuleNameError(SigmaError):
    """There one or more rules with duplicate names in the given YAML file"""

    def __init__(self, name):
        super().__init__(f"duplicate rule name/title: {name}")


class UnknownRuleNameError(SigmaError):
    """The specified rule name (most likely in a correlation) was not found
    in the document."""

    def __init__(self, name):
        super().__init__(f"{name}: rule not found")


class UnsupportedSerializerFormat(SigmaError):
    """An unsupported format argument was provided to the
    :py:meth:`~sigma.serializer.Serializer.dump` method."""

    def __init__(self, format: str):
        super().__init__(f"{format}: unsupported format")
        self.format = format


class ConditionSyntaxError(SigmaError):
    """The detection.condition field syntax was incorrect"""

    def __init__(
        self, parsing_error: ParseException, fmt: str = "detection condition: {}"
    ):
        self.error = parsing_error
        self.fmt = fmt

    @property
    def line(self) -> str:
        return self.error.line

    @property
    def lineno(self) -> int:
        return self.error.lineno

    @property
    def column(self) -> int:
        return self.error.column

    @property
    def message(self) -> str:
        return self.error.msg

    def __str__(self) -> str:
        return self.fmt.format(str(self.error))


class UnknownIdentifierError(SigmaError):
    """A requested identifier was not found in the detection."""


class UnknownModifierError(SigmaError):
    """Sigma rule specified an invalid field modifier"""

    def __init__(
        self,
        field: str,
        modifier: str,
        message: str = "detections: {field}: invalid modifier: {modifier}",
    ):
        super().__init__(message.format(field=field, modifier=modifier))

        self.field = field
        self.modifier = modifier


class UnsupportedFieldComparison(SigmaError):
    """A field comparison was unsupported by the serializer"""

    def __init__(
        self,
        field: str,
        type_: Type,
        message: str = "detections: {field}: invalid comparison: {type_}",
    ):
        super().__init__(message.format(field=field, type_=type_))


class InvalidModifierCombinationError(SigmaError):
    """The combination of modifiers was invalid"""

    def __init__(
        self,
        field: str,
        failed_modifier: str,
        completed_modifiers: List[str],
        message: str = "detections: {field}: {failed_modifier} invalid after {completed_modifiers}",
    ):
        super().__init__(
            message.format(
                field=field,
                failed_modifier=failed_modifier,
                completed_modifiers=completed_modifiers,
            )
        )

        self.field: str = field
        self.failed_modifiers: str = failed_modifier
        self.completed_modifiers: List[str] = completed_modifiers


class InvalidFieldValueError(SigmaError):
    """The value for a given field is invalid"""

    def __init__(
        self,
        field: str,
        expected: Type,
        found: Type,
        modifier: str = None,
    ):

        if modifier:
            message = f"detections: {field}: modifier: {modifier}: expected {expected} but found {found}"
        else:
            message = f"detections: {field}: expected {expected} but found {found}"

        super().__init__(message)


class UnknownTransform(SigmaError):
    def __init__(self, transform: str):
        super().__init__(f"unknown rule transform: {transform}")


class SerializerNotFound(SigmaError):
    def __init__(self, serializer: str):
        super().__init__(f"{serializer}: serializer not found")


class SigmaValidationError(SigmaError):
    def __init__(self, validation: ValidationError):
        super().__init__(str(validation))

        self.validation = validation


class RuleValidationError(SigmaValidationError):
    """Raised when a rule schema fails validation"""


class SerializerValidationError(SigmaValidationError):
    """Raised when a serializer config fails validation"""


class TransformValidationError(SigmaValidationError):
    """Raised when a transform config fails validation"""


class SkipRule(SigmaError):
    """Skip the currently processing rule. This is mainly used during conversion."""

    def log(self, rule):
        """Helper method to always log a skipped rule in the same way

        :param rule: the rule that was skipped
        :type rule: sigma.schema.Rule
        """

        logger.warn("skipping %s: %s", rule.title, self)
