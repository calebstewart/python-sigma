import os
import json
import importlib.resources
from os import PathLike
from typing import List, Union, ClassVar, Optional
from pathlib import Path
from importlib.abc import Traversable

import requests
from pydantic.main import BaseModel
from pydantic.networks import AnyHttpUrl


class Technique(BaseModel):
    """MITRE Attack Technique Details"""

    id: str
    title: str
    tactics: Optional[List[str]]

    @property
    def url(self) -> str:
        return f"https://attack.mitre.org/techniques/{self.id}"


class Tactic(BaseModel):
    """MITRE Attack Tactit Details"""

    id: str
    title: str

    @property
    def url(self) -> str:
        return f"https://attack.mitre.org/tactics/{self.id}"


class Attack(BaseModel):
    """MITRE Attack framework abstraction"""

    ATTACK_URLS: ClassVar[List[str]] = [
        "https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json",
        "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
    ]
    SOURCE_TYPES: ClassVar[List[str]] = [
        "mitre-pre-attack",
        "mitre-attack",
        "mitre-mobile-attack",
    ]
    ATTACK_SINGLETON: ClassVar[Optional["Attack"]] = None

    techniques: List[Technique]
    tactics: List[Tactic]

    def get_tactic(self, id: str) -> Optional[Tactic]:
        """Lookup a tactic by ID"""

        id = id.lower()

        for tactic in self.tactics:
            if tactic.id.lower() == id:
                return tactic

    def get_technique(self, id: str) -> Optional[Technique]:
        """Lookup a technique by ID"""

        id = id.lower()

        for technique in self.techniques:
            if technique.id.lower() == id:
                return technique

    @classmethod
    def load(
        cls,
        path: Optional[Union[str, Path, Traversable]] = None,
    ) -> "Attack":
        """Load the attack data"""

        if cls.ATTACK_SINGLETON is None:
            if path is None:
                path = (
                    Path(os.environ.get("XDG_DATA_HOME", "~/.local/share"))
                    / "sigma"
                    / "mitre.json"
                )

                if not path.is_file():
                    path = importlib.resources.files("sigma") / "data" / "mitre.json"

            if isinstance(path, str):
                path = Path(path)

            with path.open() as filp:
                cls.ATTACK_SINGLETON = cls.parse_obj(json.load(filp))

        return cls.ATTACK_SINGLETON

    @classmethod
    def download(cls, path: Optional[Union[str, Path]]) -> "Attack":
        """Download up-to-date attack data and save to the specified location"""

        if path is None:
            path = (
                Path(os.environ.get("XDG_DATA_HOME", "~/.local/share"))
                / "sigma"
                / "mitre.json"
            )

        if isinstance(path, str):
            path = Path(path)

        path = path.expanduser()

        attack = Attack(techniques=[], tactics=[])
        tactic_map = {}
        technique_map = {}

        for url in cls.ATTACK_URLS:
            r = requests.get(url)
            data = r.json()

            for entry in data.get("objects", []):
                # Revoked or deprecated object
                if entry.get("revoked") or entry.get("x_mitre_deprecated"):
                    continue

                if entry.get("type") == "x-mitre-tactic":
                    for ref in entry.get("external_references", []):
                        if ref.get("source_name") not in cls.SOURCE_TYPES:
                            continue

                        tactic_map[entry.get("x_mitre_shortname")] = ref.get(
                            "external_id"
                        )
                        attack.tactics.append(
                            Tactic(
                                id=ref.get("external_id"),
                                title=entry.get("name", ""),
                            )
                        )
                        break

            for entry in data.get("objects", []):
                # Revoked or deprecated object
                if entry.get("revoked") or entry.get("x_mitre_deprecated"):
                    continue

                if entry.get("type") == "attack-pattern" and not entry.get(
                    "x_mitre_is_subtechnique"
                ):
                    for ref in entry.get("external_references"):
                        if ref.get("source_name") not in cls.SOURCE_TYPES:
                            continue

                        sub_tactics = []
                        for tactic in entry.get("kill_chain_phases", []):
                            if tactic.get("kill_chain_name") in cls.SOURCE_TYPES:
                                sub_tactics.append(tactic_map[tactic.get("phase_name")])

                        technique_map[ref.get("external_id")] = entry.get("name")
                        attack.techniques.append(
                            Technique(
                                id=ref.get("external_id"),
                                title=entry.get("name"),
                                tactics=sub_tactics,
                            )
                        )

                        break

            for entry in data.get("objects", []):
                # Revoked or deprecated object
                if entry.get("revoked") or entry.get("x_mitre_deprecated"):
                    continue

                if entry.get("type") == "attack-pattern" and entry.get(
                    "x_mitre_is_subtechnique"
                ):
                    for ref in entry.get("external_references", []):
                        if ref.get("source_name") not in cls.SOURCE_TYPES:
                            continue

                        parent_technique = technique_map[
                            ref.get("external_id").split(".")[0]
                        ]
                        attack.techniques.append(
                            Technique(
                                id=ref.get("external_id"),
                                title=f"{parent_technique} : {entry.get('name')}",
                                tactics=None,
                            )
                        )
                        break

        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w") as filp:
            filp.write(attack.json())

        # Override the attack data singleton
        cls.ATTACK_SINGLETON = attack

        return attack
