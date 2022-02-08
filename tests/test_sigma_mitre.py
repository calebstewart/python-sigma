import pathlib
from typing import Union

import pytest

from sigma.mitre import Attack, Tactic, Technique


def test_update_and_load(tmp_path: pathlib.Path):
    """Test to make sure MITRE ATT&CK database download is working"""

    # Download and load the mitre data from github
    attack = Attack.download(tmp_path / "mitre.json")
    assert attack.tactics and attack.techniques

    # Reset singleton
    Attack.ATTACK_SINGLETON = None

    # Attempt to load an invalid path
    with pytest.raises(FileNotFoundError):
        attack = Attack.load(tmp_path / "doesnotexist.json")

    # Load the previously downloaded data
    attack = Attack.load(tmp_path / "mitre.json")

    # Should raise an exception
    with pytest.raises(FileNotFoundError):
        Attack.download("/path/does/not/exist")

    # Ensure this doesn't effect future tests
    Attack.ATTACK_SINGLETON = None


@pytest.mark.parametrize(
    "kind,ident,expected_title",
    [
        ("tactic", "TA0043", "Reconnaissance"),
        ("technique", "T1595", "Active Scanning"),
        ("technique", "T1595.001", "Active Scanning : Scanning IP Blocks"),
    ],
)
def test_lookup(kind, ident, expected_title):
    """Test that the default database loads properly"""

    # Load the default database of mitre tactics/techniques
    attack = Attack.load()

    # Calls either get_technique or get_tactic
    value: Union[Tactic, Technique] = getattr(attack, f"get_{kind}")(ident)

    # Ensure we found the correct values
    assert value is not None
    assert value.title == expected_title
