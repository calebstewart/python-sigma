import click
import fuzzywuzzy.process
from rich.console import Console

console = Console(log_path=False)


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


def aliased_group(parent=None, **attrs):
    """Decorator for creating sub-command groups with fuzzy matching

    :param parent: the parent command
    :param attrs: keyword arguments passed directly to ``parent.command``
    """
    if parent is None:
        parent = click
    return parent.command(cls=FuzzyAliasedGroup, **attrs)


@aliased_group()
def cli():
    """Sigma Rule conversion and validation CLI."""
    pass


from sigma.cli import list, schema, validate, converter
