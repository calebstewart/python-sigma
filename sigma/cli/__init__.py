import click


@click.group()
def cli():
    """Sigma Rule conversion and validation CLI."""
    pass


from sigma.cli import list, schema, validate, converter
