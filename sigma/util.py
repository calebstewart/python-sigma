import copy
from typing import Any, Dict, TypeVar, Sequence, Generator


class CopyableSchema:
    schema_extra = {"examples": []}

    @classmethod
    def copy_schema(cls, example_extra: Dict[str, Any]):
        schema = copy.deepcopy(cls.schema_extra)

        for example in schema.get("examples", []):
            example.update(example_extra)

        return schema


T = TypeVar("T")


def iter_chunked(seq: Sequence[T], size: int) -> Generator[Sequence[T], None, None]:
    yield from (seq[p : p + size] for p in range(0, len(seq), size))
