"""
A python Sigma Rule parsing and conversion API. This package abstracts the interaction with
sigma rules in order to make loading, modifying and converting rules easier.

The core functionality of this package comes from the :py:mod:`sigma.schema` module which
handles parsing sigma rule files into Python-native objects. A majority of the parsing and
validation comes from pydantic. The conditional language and detection field mappings are
parsed using a grammar constructed with the pyparsing module. Loading a rule into memory is
as easy as using the :py:meth:`Rule.from_yaml <sigma.schema.Rule.from_yaml>` method to load a rule file.

Along with the ingestion of rules, you can also modify sigma rules and save them back to
disk. Modifications to the in-memory rule can be saved using the :py:meth:`~Rule.to_sigma`
method which returns a JSON and YAML-serializable dictionary.

Lastly, a framework for transformation and serialization of rules is also implemented
to assist in ingesting sigma rules into a variety of platforms. Serializers can be defined
in Python classes or through YAML configuration files. A serializer configuration also
contains a list of transformations which can make inline modifications to the rule and/or
it's detection conditions during serialization (such as field re-mapping). For more details
on serializers, see :py:mod:`sigma.serializer`. For more details on transformations, see
:py:mod:`sigma.transform`.

.. code-block:: python
    :caption: Loading a Rule and Converting to EQL and KQL

    from sigma.schema import Rule
    from sigma.serializer import Serializer

    # Construct serializers for EQL and KQL languages
    eql = Serializer.from_yaml("eql.yml")
    kql = Serializer.from_yaml("kql.yml")

    # Load a rule
    rule = Rule.from_yaml("/path/to/sigma/repo/rules/windows/process_creation/win_susp_net_execution.yml")

    # Dump the rule
    print(f"======== {rule.title} by {rule.author} ========")
    print(f"EQL Query: {eql.serialize(rule)}")
    print(f"KQL Query: {kql.serialize(rule)}")

Command Line Interface
----------------------

This package also provides a command line interface for validating and converting sigma rules
using defined serializers. A script named ``sigma-convert`` is installed with the module.

.. code-block::
    :caption: sigma-convert usage

    $ sigma-convert --help
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

.. code-block:: bash
    :caption: Examples of sigma-convert usage

    # Dump the serialized rule to stdout using a standard serializer
    $ sigma-convert -s eql ./rule.yml
    $ sigma-convert -s kql ./rule.yml

    # Dump the serialized rule to stdout using a custom serializer definition
    $ sigma-convert -s ./custom.yml ./rule.yml

    # Dump the serialized rule to stdout using a custom serializer class
    $ sigma-convert -s package.module:ClassName ./rule.yml

    # Validate a rule format and conditionals
    $ sigma-convert --validate ./rule.yml

    # Dump the JSON Schema specification for Sigma rules in JSON or YAML format
    $ sigma-convert --dump-schema json
    $ sigma-convert --dump-schema yaml

    # List built-in serializer names
    $ sigma-convert --list-builtin

"""

__version__ = "0.1.0"
