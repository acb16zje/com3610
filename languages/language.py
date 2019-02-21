"""
Programming languages class for ShefMine
"""

import re


class RuleOverlapError(Exception):
    """Raised when the same rule occurred more than once in the rule set"""

    def __init__(self, rule: str, newrule: str) -> None:
        """
        Storing the string of 'rule' and 'newrule' for
        debugging purpose

        :param rule: An existing rule in the rule set
        :param newrule: A new rule after being expanded
        """

        self.rule = rule
        self.newrule = newrule


class Language(object):
    """
    A class for programming languages
    """

    def __init__(self, rule_set: dict, extensions: list, comments: re) -> None:
        """
        Constructor for Language class

        :param rule_set: The compressed rule set (separated by '|')
        :param extensions: The file extensions of the programming language
        :param comments: The comment format of the programming language
        """

        self.rule_set = _expand_rule_set(rule_set)
        self.extensions = extensions
        self.comments = comments
        language_list.append(self)

    def is_not_comment(self, line: str) -> bool:
        """
        Returns True if a line is not a comment

        :param line: The line of code
        :return: True if the line of code is not a comment
        """

        return not self.comments.match(line.strip())


language_list = []


def _expand_rule_set(rule_set: dict) -> dict:
    """
    Rule sets can have compressed sets of rules (multiple function names separated by '|'.
    Expand the given ruleset. Note that this "for" loop modifies the ruleset while it's iterating,
    so we *must* convert the keys into a list before iterating.

    :param rule_set: The compressed rule set (separated by '|')
    :return: The expanded rule set (without '|')
    """

    try:
        for rule in list(rule_set.keys()):
            if '|' in rule:  # We found a rule to expand.
                for newrule in rule.split('|'):
                    if newrule in rule_set:
                        raise RuleOverlapError
                    rule_set[newrule] = rule_set[rule]
                del rule_set[rule]

        return rule_set
    except RuleOverlapError as e:
        print(f"Error: Rule '{e.rule}', when expanded, overlaps '{e.newrule}'")
