"""
Python Programming Language
Bandit is used to analyse Python files
"""

from .language import Language

py_extensions = ['.py']

# Bandit has built-in ruleset and comment check
Language({}, py_extensions)
