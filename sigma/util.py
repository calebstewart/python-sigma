import copy
from typing import Any, Dict


class CopyableSchema:
    schema_extra = {"examples": []}

    @classmethod
    def copy_schema(cls, example_extra: Dict[str, Any]):
        schema = copy.deepcopy(cls.schema_extra)

        for example in schema.get("examples", []):
            example.update(example_extra)

        return schema
