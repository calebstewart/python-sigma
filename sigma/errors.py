""" Sigma specific errors and exceptions """


from typing import List, Type


class SigmaError(Exception):
    """Base generic sigma error. All other sigma errors are subclasses of this."""


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
