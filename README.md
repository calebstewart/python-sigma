# Python Sigma Rule Parsing Library

This library attempts to abstract the handling of Sigma rules in Python.
The rules are parsed using a schema defined with `pydantic`, and can be
easily loaded from YAML files into a structured Python object.

```py
from sigma.schema import Rule

# Load a rule into a python object
rule = Rule.from_yaml("test-rule.yml")
    
# Simple properties are accessible directly
print(rule.title)
print(rule.author)

# Detection conditions are also available unchanged
print(rule.detection.condition)
print(rule.detection.my_condition_name)

# Parsed/unified grammar from the condition is easy!
print(rule.detection.expression)
```

This project is under active development, and this readme may or may not
reflect the most up-to-date documentation. In general, you should refer
to the generated documentation (instructions for building below) and the
command-line help output for details until the library/tools reach a
stable state.

## Installation

The library and command line interface can be installed using `pip` from
github with:

``` sh
# Install directly from github
pip install git+git@github.com:calebstewart/python-sigma.git

# Checkout the repo, then install
git clone git@github.com:calebstewart/python-sigma.git
cd python-sigma
pip install .
```

If you would like to participate in development, you should use Python
Poetry to manage your virtual environment and dependencies. For more
information see [the Poetry documentation](https://python-poetry.org/docs/).

``` sh
# Setup Python development environment
git clone git@github.com:calebstewart/python-sigma.git
cd python-sigma
poetry install

# Enter the virtual environment to interact with the package
poetry shell

# Type "exit" to leave the poetry virtual environment
```

## Documentation

Documentation can be built using Sphinx from this repository. First,
install the package with the documentation dependencies, then run
`make html` from the `docs/` directory:

``` sh
# Install with the docs extras
poetry install -E docs

# Enter the poetry virtual environment
poetry shell

# Build the documentation
cd docs
make html

# Open the documentation in docs/_build/index.html
```

At this time, documentation is built automatically from docstrings and
type-hinting in the project code itself. The plan is to eventually augment
this auto-generated documentation, but that is a project for later after
the API and CLI interfaces solidify. That being said, extensive examples
and documentation have been added where appropriate using module docstrings
throughout the project, so the documentation should at least be usable.

## Command Line Interface

There is a command line interface exposed by the entrpoint `sigma` which
is installed with this package. The `sigma` command provides subcommands
for inspecting rule and configuration schema, viewing/updating the MITRE
ATT&CK database cache, validating serializer or rule configurations, and
converting rules using built-in or custom serializers.

This project is still under active development, and the interface could
change at any time. You should check the built-in help by running 
`sigma --help` at the command line, however for completeness sake, the
current help output/list of subcommands is:

``` sh
$ sigma --help
Usage: sigma [OPTIONS] COMMAND [ARGS]...

  Sigma Rule conversion and validation CLI.

Options:
  --help  Show this message and exit.

Commands:
  convert    Convert Sigma rules to various formats using built-in or...
  list       List built-in transforms and serializers
  mitre      Browse and update the MITRE ATT&CK data cache
  schema     Dump the schema for rules, serializers, and transforms
  transform  Transform a list of rules using a list of transforms in a...
  validate   Validate Sigma rule or serializer schema
```

## But... why?

The official Sigma repository contains the `sigmac` tool for converting
sigma rules from sigma format to a variety of backend detection systems.
However, this tool has aged poorly. The code is messy and hard to follow
and documentation is limited. The Sigma team tried to update the converter
with the `pySigma` repository, but this project seems stalled. The last
I checked, there were no changes in the last ~6 months. Further, this
project also suffers from little-to-no documentation, which makes submitting
PRs painful.

Also, the processing of sigma rules simply seems overly complex in both
cases. This may be a "grass is greener" problem on my part, but the worst
case for me doing this is that I better understand the problems inherent
in building a Sigma rule API/converter, and can hopefully give back to the
community in some way in the future.

Lastly, I wanted to build this tool with a focus on modern API interfaces
and aggressive documentation. I plan to utilize `pydantic` heavily to make
validation of fields and values more straightforward and pythonic as well
as provide a simple interface for others to ingest Sigma rules directly.
For example, being able to load, inspect and possibly modify sigma rules
from Python without using the conversion tool would be a great feature for
teams trying to work Sigma into their automation pipeline.
