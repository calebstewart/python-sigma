Serializer Configurations
=========================

Serializers are defined in Python, but can be configured via YAML (or other
data source compatible with Python ``dict`` objects). The schema for
serializer configurations is defined by each serializer, but all serializers
inherit a common base schema.

When writing serializer configurations, you can validate the definition using
the ``sigma validate`` command, which will utilize the schema against both
the common serializer configuration and the configuration specific to your
serializer base type.

.. code-block:: yaml
    :caption: Example Configuration with no Custom Configuration

    name: "A sample serializer"
    description: "Description for the serializer"
    base: package.module:CustomSerializer
    logsource:
      rules:
        - name: windows_process_creation
          product: windows
          category: process_creation
          index:
            - my-index-*
    transforms:
      - type: field_map
        mapping:
          CommandLine: my_command_line_field
          Image: my_image

Base Class Definition
---------------------

Serializer configurations must specify a base class in order to construct the
serializer in memory. The ``base`` field is a string which can take on a few
different meanings in the following order:

- The name of a built-in serializer (as returned by ``sigma list serializers``).
- The path to another serializer configuration YAML file.
- A fully-qualified python class name in the format ``package.module:ClassName``.

When specifying an explicit class, the given class is instantiated and your
configuration definition is passed directly to this class. However, if you provide
the name of another serializer configuration file, then that serializer is
first constructed, and then it's configuration is updated based on the new
configuration file. You can use this to create pseudo-inheritence without
touching code.

This is especially useful when creating serializers which output to a specific
rule format, but the rule format does not define specific field names. You can
construct a serializer configuration which inherits from the root serializer
and provide extra transforms to perform the field mapping.

Log Source Definition
---------------------

A ``logsource`` field in the serializer configuration is optional, but
may be necessary depending on your target format. The log source defines rules
for matching specific ``logsource`` fields within rules, and then applying
extra conditions or defining an index for the query in the backend detection
system.

.. code-block:: yaml
   :caption: A full logsource field

   logsource:
     # If no below rules match, use this index (could also be a list)
     defaultindex: "logs-*"
     # How to merge conditions if multiple rules match
     merging: "or"
     # List of logsource rules to match against sigma rules
     rules:
       - name: "match windows process_creation logs"
         # If any of the three below are missing, it is not compared.
         # Any of the below that are defined *must* match the sigma rule.
         product: "windows"
         category: "process_creation"
         service: "service"
         # Define indices used when converting the sigma rule
         index: "other-logs-*"
         # Define extra conditions which are Logical AND-joined to
         # the final matching rule (if multiple logsource rules match,
         # the logsource conditions are joined according to the above
         # merging field)
         conditions:
           CommandLine|contains: "cmd.exe"

Transformation Definitions
--------------------------

A serializer can define a list transformations which will be applied prior to
serialing the rule to the target format. Each transformation type can define
an arbitrary structure for their configuration, but each transformation definition
requires at least a ``type`` field which can take on a few different meanings
in the following order:

- A built-in transformation (as returned by ``sigma list transforms``).
- A fully-qualified python class name in the format ``package.module:ClassName``.

You can utilize the ``sigma schema transform`` command to view the JSON schema
specification or examples defined by a specific transform type.
