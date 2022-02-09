.. Python Sigma documentation master file, created by
   sphinx-quickstart on Tue Feb  8 20:30:35 2022.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Python Sigma's documentation!
========================================

Python Sigma is a package which provides an abstract interface for loading and
interacting with Sigma detection rules as well as the ability to construct and
combine serializers and rule transformations to convert rules between common
formats for ingestion into your backend detection systems.

Installation
------------

The :py:mod:`sigma` package can be installed directly from GitHub with ``pip``.

.. code-block:: sh
   :caption: python-sigma installation

   pip install git+https://github.com/calebstewart/python-sigma.git

For development environments, you should clone the repository and use Python Poetry
to manage your virtual environment.

.. code-block:: sh
   :caption: Development Environment Setup

   # Clone the repository
   git clone git@github.com:calebstewart/python-sigma.git
   cd python-sigma

   # Setup and enter virtual environment (optionally with documentation extras)
   poetry install -E docs
   poetry shell

Command Line Interface
----------------------

Along with the Python API for loading, modifying, transforming and converting rules, this
package provides a command line interface for interacting with Sigma rules. The project is
under active development, so this interface may change in the future. With this in mind,
you should defer to the built-in documentation with ``--help`` arguments when using the
command.

.. code-block:: bash
   :caption: Examples of command line interface

   $ sigma --help
   Usage: sigma [OPTIONS] COMMAND [ARGS]...

      Sigma Rule conversion and validation CLI.

   Options:
      --mitre-data FILENAME  Override default MITRE ATT&CK data file (downloaded
                             with 'sigma mitre update')
      --help                 Show this message and exit.

   Commands:
      convert    Convert Sigma rules to various formats using built-in or...
      list       List built-in transforms and serializers
      mitre      Browse and update the MITRE ATT&CK data cache.
      schema     Dump the schema for rules, serializers, and transforms
      transform  Transform a list of rules using a list of transforms in a...
      validate   Validate Sigma rule or serializer schema

   # Dump the serialized rule to stdout using a standard serializer
   $ sigma convert -s eql ./rule.yml
   $ sigma convert -s kql ./rule.yml

   # Dump the serialized rule to stdout using a custom serializer definition
   $ sigma convert -s ./custom.yml ./rule.yml

   # Dump the serialized rule to stdout using a custom serializer class
   # This could be from another third-party package implementing it's own
   # serialization interface.
   $ sigma convert -s package.module:ClassName ./rule.yml

   # Validate a given rule and condition grammar
   $ sigma validate rule ./rule.yml

   # Dump the JSON Schema specification for Sigma rules in JSON or YAML format
   $ sigma schema rule
   $ sigma schema serializer es-eql
   $ sigma schema transform field_map

   # Dump example data from schema
   $ sigma schema rule --examples -o json
   $ sigma schema rule -e -o yaml
   $ sigma schema transform -e field_map

   # List built-in serializers or transforms
   $ sigma list serializer
   $ sigma list transform

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   serializer-definition
   serializers
   transformations
   API Documentation <api/sigma.rst>

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
