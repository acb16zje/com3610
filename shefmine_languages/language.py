"""
Programming languages of ShefMine
"""

import re


class RuleOverlapError(Exception):
    """Raised when the same rule occurred more than once in the rule set"""

    def __init__(self, rule: str, newrule: str) -> None:
        self.rule = rule
        self.newrule = newrule


class Language:
    """
    A class for programming languages
    """

    def __init__(self, rule_set: dict, extensions: list, comments: re) -> None:
        """
        Constructor for Language class
        """

        self.rule_set = self._expand_rule_set(rule_set)
        self.extensions = extensions
        self.comments = comments
        language_list.append(self)


    def _expand_rule_set(self, rule_set):
        # Rulesets can have compressed sets of rules
        # (multiple function names separated by "|".
        # Expand the given ruleset.
        # Note that this "for" loop modifies the ruleset while it's iterating,
        # so we *must* convert the keys into a list before iterating.
        try:
            for rule in list(rule_set.keys()):
                if "|" in rule:  # We found a rule to expand.
                    for newrule in rule.split("|"):
                        if newrule in rule_set:
                            raise RuleOverlapError
                        rule_set[newrule] = rule_set[rule]
                    del rule_set[rule]
        except RuleOverlapError as e:
            print(f"Error: Rule '{e.rule}', when expanded, overlaps '{e.newrule}'")


language_list = []


def is_comment(line: str) -> bool:
    return True
