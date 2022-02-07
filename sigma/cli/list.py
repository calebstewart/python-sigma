from sigma.cli import cli
from sigma.transform import BUILTIN_TRANSFORMS
from sigma.serializer import get_builtin_serializers


@cli.group()
def list():
    """List built-in transforms and serializers"""


@list.command()
def serializers():
    """List built-in serializers"""

    for name, description in get_builtin_serializers():
        print(f"{name} - {description}")


@list.command()
def transforms():
    """List built-in transforms"""

    for name, (_, description) in BUILTIN_TRANSFORMS.items():
        print(f"{name} - {description}")
