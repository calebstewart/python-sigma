import importlib.metadata

from sigma.cli import cli
from sigma import logger


def entrypoint():

    # Fix compatability with pre-python-3.10 importlib
    eps = importlib.metadata.entry_points()
    if isinstance(eps, dict):
        plugins = eps.get("sigma.cli", [])
    else:
        plugins = eps.select(group="sigma.cli")

    for plugin in plugins:
        try:
            plugin.load()
        except Exception as exc:
            logger.warning("failed to load plugin: %s: %s", plugin.name, exc)

    cli()
