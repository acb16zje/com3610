"""
Programming languages class for Shefmine
"""

import re


class Language(object):
    """
    A class for programming languages
    """

    def __init__(self, rule_set: dict, extensions: list, non_context: re = None) -> None:
        """
        Constructor for Language class

        :param rule_set: The rule set with un-compiled regular expression
        :param extensions: The file extensions of the programming language
        :param non_context: The non-context line format of the programming language
        """

        self.rule_set = rule_set
        self.extensions = extensions
        self.non_content = non_context
        language_list.append(self)
        supported_extensions.extend(self.extensions)

    def is_context(self, line: str) -> bool:
        """
        Returns True if a line contains context

        :param line: The line of code
        :return: True if the line of code contains context
        """

        return not self.non_content.match(line.strip())


language_list = []
supported_extensions = []
