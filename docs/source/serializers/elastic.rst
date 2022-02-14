Elastic Serializers
===================

There are two built-in Elastic related serializers: ``eql`` and ``es-rule``. Both
serializers generate a query in the Event Query Language (EQL) format. The former
generates a bare string with the EQL query while the latter produces a JSON object
suitable for uploading as an Elastic Security Alert rule (see
`Create Rule <https://www.elastic.co/guide/en/security/8.1/rules-api-create.html#actions-object-schema>`_).

Event Query Language (EQL)
--------------------------

The EQL serializer does not require any extra configuration beyond the default
serializer options (e.g. ``logsource`` or ``transforms``). It can be used
directly to produce valid EQL query strings.

.. code-block:: bash
    :caption: Converting a rule to EQL

    sigma convert -s eql ./rule.yml

As with other serializers, you can combine the EQL serializer with custom transformations
to produce a modified version of the Sigma rule with a serializer configuration file.

Elastic Security Rule
---------------------

The ``es-rule`` serializer is built on-top of the EQL serializer. It first serializes
the raw conditional to an EQL query and then utilizes the other Sigma details to produce
a JSON object suitable for uploading to Elastic as an alert rule. There are a few extra
configuration options which you can use when configuring your ``es-rule`` serializers.

``enable_rule``
    If set to true, the generated rule will be enabled. By default, generated rules
    are disabled.

``interval``
    Control the time interval for the generated rule. The syntax for this field is
    the same as the interval field in the Elastic REST API specification (see
    `here <https://www.elastic.co/guide/en/elasticsearch/reference/8.1/common-options.html#date-math>`_).
    The default interval is ``5m``.

``output_index``
    Control the output index for alerts. The default index is ``.siem-signals-default``.

``max_signals``
    The maximum number of alerts the rule can create during a single execution. The
    default is ``100``.

``risk_map``
    A dictionary mapping Sigma rule levels to risk integers. By default low, medium,
    high and critical are mapped to ``5``, ``35``, ``65``, ``95`` respectively.

``risk_default``
    If a Sigma rule level does not match an item in the above dictionary, this value
    will be used instead. The default is ``35``.

``severity_map``
    A dictionary mapping Sigma rule levels to Elastic severity values. By default,
    low, medium, high, and critical are mapped to themselves while informational
    is mapped to ``low``.

``severity_default``
    If a Sigma rule level does not match an item in the above dictionary, this value
    will be used instead. The default is ``medium``.

``timestamp_override``
    This field directly sets the corresponding field in the output rule. It can be used
    to adjust where the rule timestamp comes from within Elastic. This is not added
    to the rule by default. For example, you could set this value to ``event.timestamp``
    to use that custom field for the event time instead of the ingested time.

``actions``
    List of actions to perform if a rule fires. This is a list of
    :py:data:`~sigma.serializer.elastic.ElasticSecurityAction` objects, which are described
    below. By default, no actions are added to the rule.

Elastic Security Actions
------------------------

As described by the `Create Rule API docs <https://www.elastic.co/guide/en/security/8.1/rules-api-create.html#actions-object-schema>`_,
there are a few different action types which can be specified.

- ``.slack``
- ``.email``
- ``.pagerduty``
- ``.webhook``

Instead of allowing free-form dictionary objects in the ``actions`` field of a serializer,
each of these different types define their own schema, which enables validation prior to
serialization. Further, each action defined in your serializer can optionally define a list
of tags which must match a rule for the action to be applied. For example, the following
action would only be applied to rules with the ``custom`` tag.

.. code-block:: yaml

    actions:
      - type: slack
        id: my-connector-id
        tags:
          - custom
        message: "my slack message"

If no tags are provided, the action is applied to every rule. The configuration fields are
mostly the same as the official Elastic REST API, but have been morphed slightly to conform
with the format of the serializer configuration. Their usage should be relatively straight
forward. The following is an example of all possible properties for all available Elastic actions.

.. code-block:: yaml

    actions:
      - type: slack
        id: my-connector-id
        tags:
          - custom
        message: "my slack message"
      # At least one of to, cc, bcc must be provided.
      # The subject is optional.
      - type: email
        id: my-connector-id
        to:
          - security@company.com
        cc:
          - someone@company.com
        bcc:
          - someoneelse@company.com
        subject: "ALERT"
        message: "MESSAGE"
      # The body field is JSON serialized per the elastic documentation
      - type: webhook
        id: my-connector-id
        body:
          my: custom
          object: 3.14
      - type: pagerduty
        id: my-connector-id
        severity: "Critical"
        event_action: "trigger"
        # Rest are optional
        dedup_key: "something"
        timestamp: "2020-03-20T14:28:23.382748"
        component: "security-solution"
        group: "logical-group"
        source: ":shrug:"
        summary: "my alert summary"
        # This was renamed due to python conflicts with 'class'
        clazz: "class/type of event"
