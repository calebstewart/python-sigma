""" Sigma specific errors and exceptions """


from typing import List, Type

from pydantic import ValidationError
from click.exceptions import ClickException
from pyparsing.exceptions import ParseException

from sigma import logger


class SigmaError(Exception):
    """Base generic sigma error. All other sigma errors are subclasses of this."""


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
        return self.fmt.format(
            f"{self.error.msg} (line:{self.lineno} col:{self.column})"
        )


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
