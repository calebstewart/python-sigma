import pytest

from sigma.grammar import build_grammar_parser


@pytest.fixture()
def grammar_parser():
    return build_grammar_parser()
