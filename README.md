# Python Sigma Rule Parsing Library

This library attempts to abstract the handling of Sigma rules in Python.
The rules are parsed using a schema defined with `pydantic`, and can be
loaded easily with the `parse_obj` method of the `pydantic` module.

```py
import yaml

from sigma.schema import Rule

# Load a rule into a python object
with open("test-rule.yml") as filp:
    rule = Rule.parse_obj(yaml.safe_load(filp))
    
# Simple properties are accessible directly
print(rule.title)
print(rule.author)

# Detection conditions are also available unchanged
print(rule.detection.condition)
print(rule.detection.my_condition_name)

# Parsed/unified grammar from the condition is easy!
print(rule.detection.parse_grammar())
```

## State of the Project

Currently, this is an early attempt at parsing the rules and conditional
grammar only. Eventually, I will work on a pipeline for converting rules
to other formats, but I want to focus on correctly parsing and handling
all facets of the Sigma rule specification first.

For now, this means there is no command line interface for interacting
with rules. That will be the final step after the rest of the plumbing/
framework is built out.

I've take some inspiration from [pySigma](https://github.com/SigmaHQ/pySigma.git)
for parsing the condition rules to hopefully speed some of the logic parsing
up a bit, and this appears to be mostly working.

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
