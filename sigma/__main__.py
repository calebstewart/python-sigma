import importlib.metadata

from sigma.cli import cli
from sigma import logger


def entrypoint():

    plugins = importlib.metadata.entry_points(group="sigma.cli")
    for plugin in plugins:
        try:
            plugin.load()
        except Exception as exc:
            logger.warning("failed to load plugin: %s: %s", plugin.name, exc)

    cli()
