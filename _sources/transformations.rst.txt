Creating Rule Transformations
=============================

Rule transformations are implemented by defined a class which inherits from the
:py:class:`~sigma.transform.Transformation` class. A transformation defines two
methods for making modifications to the rule as a whole and/or individual
condition expressions.

A single transformation can be used to transform both rules and their internal
conditional expressions.

Configuration
-------------

Transformations can define custom configuration which must be provided when
instantiating the transformation class. This normally looks like key-value
pairs alongside the transformation type in the serializer configuration:

.. code-block:: yaml
    :caption: Example serializer configuration

    transforms:
      - type: package.module:CustomTransform
        title_format: "{} - MODIFIED"
        extra_tags:
          - custom_tag

The exact format and types for this configuration is defined by the ``Schema``
class within your transformation. The below example shows how to setup a
configuration schema which matches the above YAML.

.. code-block:: python
    :caption: Custom transformation with required configuration

    from typing import List

    from sigma.transform import Transformation
    from sigma.schema import RuleTag

    class CustomTransform(Transformation):

        class Schema(Transformation.Schema):
            title_format: str
            extra_tags: List[RuleTag]

            class Config:
                schema_extra = {
                    "examples": Transformation.Schema.Config.schema_extra["examples"].copy()
                }
                schema_extra["examples"][0].update({
                    "title_format": "My Title Format: {}",
                    "extra_tags": [ "attack.t12345", "custom tag" ]
                })

The ``Schema`` class must inherit from :py:class:`Transformation.Schema <sigma.transform.Transformation.Schema>`
which is a ``pydantic`` model. Defining ``Config.schema_extra`` is not required, but doing
so allows users to utilize the ``sigma schema transform --examples`` command/options to
view example configuration for your custom transformation.

You can access the configuration values at runtime via the :py:attr:`Transformation.schema <sigma.transform.Transformation.schema>`
property (i.e. in either ``transform_expression`` or ``transform_rule``, you can use ``self.schema``
which will be an instance of your custom ``Schema`` class)

.. note::

   Defining a custom ``Schema`` class is not required. You can omit this class
   if your transformation does not require any special configuration.

Rule Transformation
-------------------

Modifying high-level rule properties is relatively straightforward. You define the
:py:meth:`~sigma.transform.Transformation.transform_rule` method, which takes
a :py:class:`~sigma.schema.Rule` object, and return a modified version of the
the rule. This modified version can either be a reference to the same rule with
modified properties or an entirely different rule.

.. code-block:: python
    :caption: A transformation which modifies the rule title and tags

    from sigma.transform import Transformation
    from sigma.schema import Rule

    class CustomTransform(Transformation):

        def transform_rule(rule: Rule) -> Rule:
            """ Modify the rule by changing the title and adding a new tag """

            rule.title = f"MODIFIED: {rule.title}"
            rule.tags.append(RuleTag("attack.t12345"))

            return rule

Expression Transformation
-------------------------

To modify the conditional expression, you must define the
:py:meth:`~sigma.transform.Transformation.transform_expression` method. This
method takes a reference to the rule being modified as well as the specific
expression. For a given rule, this method is called for each expression
recursively. See :py:mod:`sigma.grammar` for a list of possible grammar classes
and their meaning. As with the rule transformation, you must return a reference
to a modified expression. This returned expression can be the same expression
object with modified properties, or a completely new expression.

.. code-block:: python
    :caption: A transformation which swaps all AND/OR statements (don't do this)

    from sigma.transform import Transformation
    from sigma.schema import Rule
    from sigma.grammar import Expression, LogicalOr, LogicalAnd

    class CustomTransform(Transformation):

        def transform_expression(rule: Rule, expression: Expression) -> Expression:
            """ Modify the rule by changing the title and adding a new tag """

            if isinstance(expression, LogicalOr):
                return LogicalAnd(args=expression.args)
            elif isinstance(expression, LogicalAnd):
                return LogicalOr(args=expression.args)
            else:
                # Don't modify non AND/OR expressions
                return expression
