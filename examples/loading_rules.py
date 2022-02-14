#!/usr/bin/env python3
import textwrap

from rich.console import Console

from sigma.schema import Rule

if __name__ == "__main__":

    console = Console()

    # Loading the sigma rule
    rule = Rule.from_yaml("rule.yml")

    console.print(
        f"---- [italic]{rule.title}[/italic] by [blue]{rule.author or 'Unknown'}[/blue] ----"
    )

    if rule.description:
        console.print(textwrap.fill(rule.description or ""))
        console.print()

    if rule.tags:
        console.print("[cyan]Tags[/cyan]")
        console.print(
            "\n".join(
                [f"  - [italic magenta]{tag}[/italic magenta]" for tag in rule.tags]
            )
        )
        console.print()

    console.print("[cyan]Condition[/cyan]")
    if isinstance(rule.detection.condition, str):
        console.print(f"  - {rule.detection.condition}")
    else:
        console.print("\n".join([f"  {c}" for c in rule.detection.condition]))
    console.print()

    console.print("[cyan]Parsed Expression Tree[/cyan]")
    console.print(f"  {repr(rule.detection.expression)}")
    console.print()
