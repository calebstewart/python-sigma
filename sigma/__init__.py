"""
The core functionality of this package comes from the :py:mod:`sigma.schema` module which
handles parsing sigma rule files into Python-native objects. A majority of the parsing and
validation comes from pydantic. The conditional language and detection field mappings are
parsed using a grammar constructed with the pyparsing module. Loading a rule into memory is
as easy as using the :py:meth:`Rule.from_yaml <sigma.schema.Rule.from_yaml>` method to load a rule file.

Along with the ingestion of rules, you can also modify sigma rules and save them back to
disk. Modifications to the in-memory rule can be saved using the :py:meth:`~sigma.schema.Rule.to_sigma`
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
    # using built-in serializers
    eql = Serializer.from_yaml("eql")
    kql = Serializer.from_yaml("kql")

    # Load a rule
    rule = Rule.from_yaml("rules/windows/process_creation/win_susp_net_execution.yml")

    # Dump the rule
    print(f"======== {rule.title} by {rule.author} ========")
    print(f"EQL Query: {eql.serialize(rule)}")
    print(f"KQL Query: {kql.serialize(rule)}")


"""

import logging

__version__ = "0.1.0"

# Construct the module logger
logger = logging.getLogger(__name__)
