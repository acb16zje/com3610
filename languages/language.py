"""
Programming languages class for Shefmine
"""

import re


class Language(object):
    """
    A class for programming languages
    """

    def __init__(self, rule_set: dict, extensions: list, comments=None) -> None:
        """
        Constructor for Language class

        :param rule_set: The rule set with un-compiled regular expression
        :param extensions: The file extensions of the programming language
        :param comments: The comment format of the programming language
        """

        self.rule_set = rule_set
        self.extensions = extensions
        self.comments = comments
        language_list.append(self)
        supported_extensions.extend(self.extensions)

    def is_not_comment(self, line: str) -> bool:
        """
        Returns True if a line is not a comment

        :param line: The line of code
        :return: True if the line of code is not a comment
        """

        return not self.comments.match(line.strip())


language_list = []
supported_extensions = []
