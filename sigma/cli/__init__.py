import logging
from typing import TextIO, Optional

import click
import fuzzywuzzy.process
from rich.console import Console
from rich.logging import RichHandler
from click.exceptions import ClickException

from sigma import logger
from sigma.mitre import Attack

console = Console(log_path=False)
error_console = Console(log_path=False, stderr=True)


class CommandWithVerbosity(click.Command):
    """A command that automatically adds the verbosity and traceback
    arguments, sets up logging prior to invocation, and catches any
    unhandled exceptions/logs them according to the logging configuration."""

    def __init__(self, *args, **kwargs):

        # This shouldn't happen, but :shrug:
        if not kwargs.get("params"):
            kwargs["params"] = []

        # Add extra arguments to this command for logging setup
        kwargs["params"].append(
            click.Option(
                ["--verbose", "-v"], count=True, help="Increase logging verbosity."
            )
        )
        kwargs["params"].append(
            click.Option(
                ["--traceback", "-t"], is_flag=True, help="Dump a traceback on errors."
            )
        )

        super().__init__(*args, **kwargs)

    def invoke(self, ctx: click.Context):

        # Setup logging according to the --verbose argument
        logging.basicConfig(
            level=logging.WARNING
            - ctx.params["verbose"] * (logging.CRITICAL - logging.ERROR),
            format="%(message)s",
            handlers=[
                RichHandler(
                    rich_tracebacks=True,
                    tracebacks_width=None,
                    show_path=False,
                    console=error_console,
                )
            ],
        )

        # Store the traceback state in the context object in case
        # a command needs to use it directly
        if ctx.obj is None:
            ctx.obj = {}
        ctx.obj["traceback"] = ctx.params["traceback"]

        # Remove the traceback and logging parameters
        # to ensure they aren't passed to the command
        # functions.
        del ctx.params["traceback"]
        del ctx.params["verbose"]

        try:
            # Invoke the command
            super().invoke(ctx)
        except ClickException:
            # Click exceptions handled normally to maintain
            # the look/feel of help and usage output.
            raise
        except Exception as exc:
            # All other exceptions handled through logging.
            if ctx.obj["traceback"]:
                logger.exception(str(exc))
            else:
                logger.error(str(exc))


class FuzzyAliasedGroup(click.Group):
    """Click group with fuzzy sub-command matching
    provided by FuzzyWuzzy."""

    def get_command(self, ctx, cmd_name):
        rv = click.Group.get_command(self, ctx, cmd_name)
        if rv is not None:
            return rv

        match = [m for m in self.list_commands(ctx) if m.startswith(cmd_name)]
        if len(match) > 1 or len(match) == 0:
            match = None
        else:
            match = match[0]

        if match is None and len(cmd_name) >= 2:
            match = fuzzywuzzy.process.extractOne(cmd_name, self.list_commands(ctx))
            if match is not None and match[1] < 70:
                match = None
            elif match is not None:
                match = match[0]

        if match is None:
            ctx.fail(f"Ambiguous command: {cmd_name}")
            return

        return click.Group.get_command(self, ctx, match)

    def command(self, *args, **kwargs):

        if "cls" not in kwargs:
            kwargs["cls"] = CommandWithVerbosity

        return super().command(*args, **kwargs)


def aliased_group(parent=None, **attrs):
    """Decorator for creating sub-command groups with fuzzy matching

    :param parent: the parent command
    :param attrs: keyword arguments passed directly to ``parent.command``
    """
    if parent is None:
        parent = click
    return parent.command(cls=FuzzyAliasedGroup, **attrs)


@aliased_group()
@click.option(
    "--mitre-data",
    type=click.File("r"),
    help="Override default MITRE ATT&CK data file (downloaded with 'sigma mitre update')",
)
@click.version_option()
@click.pass_context
def cli(ctx: click.Context, mitre_data: Optional[TextIO]):
    """Sigma Rule conversion and validation CLI."""

    if mitre_data is not None:
        Attack.load(mitre_data.name)
        mitre_data.close()

    pass


from sigma.cli import list, mitre, schema, validate, converter, transform
