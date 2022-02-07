# Python Sigma Rule Parsing Library

This library attempts to abstract the handling of Sigma rules in Python.
The rules are parsed using a schema defined with `pydantic`, and can be
loaded easily with the `parse_obj` method of the `pydantic` module.

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

## Command Line Interface

There is a basic command line interface implemented for interfacing with the
serialization classes. The package installs the `sigma-convert` entrypoint
which provides the ability to use built-in or customized serializers to convert
Sigma rules to various formats.

``` sh
usage: sigma-convert [-h] [--list-builtin] [--dump-schema {yaml,json,yml}] [--validate] [--ignore-errors]
                     [--serializer SERIALIZER]
                     [rules ...]

Convert or validate Sigma rules. During validation, only errors for rules which fail validation are output. During
conversion, rule serializations are printed one-per-line for every rule provided, and stop at the first failed rule,
unless the --ignore-errors option is used. A non-zero exit code indicates at least one rule failure.

positional arguments:
  rules                 Path to a sigma rule for conversion

options:
  -h, --help            show this help message and exit
  --list-builtin, -l    List built-in serializer names and exit
  --dump-schema {yaml,json,yml}
                        Dump the sigma rule schema in the selected format
  --validate            Validate the provided rule schema (do not perform conversion)
  --ignore-errors, -i   Ignore errors when converting rules (default: stop processing after first failure)
  --serializer SERIALIZER, -s SERIALIZER
                        Name, path or fully-qualified class name of the serializer to use
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
