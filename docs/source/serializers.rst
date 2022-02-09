Creating Rule Serializers
=========================

Rule serializers are simple classes which inherit from :py:class:`~sigma.serializer.Serializer`
and implement the :py:meth:`~sigma.serializer.Serializer.serialize` method. This method takes
a rule or list of rules, and returns arbitrary data which represents some transformed and
converted rule.

Configuration
-------------

Serializer configuration is defined through the ``SerializerClass.Schema`` class. This class
must inherit from :py:class:`~sigma.serializer.CommonSerializerSchema`, which is a pydantic
model.

.. code-block:: python
    :caption: Defining serializer configuration schema

    from typing import List

    from sigma.serializer import CommonSerializerSchema, Serializer

    class CustomSerializer(Serializer):
        class Schema(CommonSerializerSchema):
            my_config: str
            other_config: List[int]

            class Config:
                schema_extra = {
                    "examples": [CommonSerializerSchema.Config.schema_extra["examples"][0].copy()],
                }
                schema_extra["examples"][0].update({
                    "my_config": "hello world",
                    "other_config": [1,2,3,4,5],
                })

.. warning::

    The definition of a ``Config.schema_extra`` is optional, but recommended. Defining examples
    allows users to utilize the ``sigma schema serializer`` command to view examples for your
    schema configuration.

After defining your schema, you can access the active configuration at runtime via the ``self.schema``
property which will be an instance of your custom schema class.

Configured Transformations
--------------------------

The :py:class:`~sigma.serializer.CommonSerializerSchema` configuration contains a list of optional
transformations which should be applied prior to serialization. You can access the list of loaded
transformations with ``self.transforms`` and apply transformations in your
:py:meth:`~sigma.serializer.Serializer.serialize` method with the :py:meth:`Rule.transform <sigma.schema.Rule.transform>`
method. You should only apply rule transformations if the ``transform`` argument is ``True``.
This is to enable easier chaining of serializers through inheritence.

Example Serializer
------------------

The following is an extremely basic (and mostly useless) serializer. It will apply
any configured transformations, and then return a simple ``repr`` of the conditional
expression.

.. code-block:: python

    from typing import Union, List

    from sigma.serializer import Serializer
    from sigma.schema import Rule

    class CustomSerializer(Serializer):
        def serialize(self, rule: Union[Rule, List[Rule]], transform: bool = True):
            if isinstance(rule, list):
                return [self.serialize(r) for  r in rule]

            if transform:
                rule = rule.transform(self.transforms)

            return repr(rule.detection.expression)
