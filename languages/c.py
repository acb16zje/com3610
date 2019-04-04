"""
C/C++ Programming Language
Flawfinder is used to analyse C/C++ files
"""

from .language import Language

c_extensions = ['.c', '.cc', '.cpp', '.cxx', '.c++', '.mm', '.h', '.hh', '.hpp', '.hxx', '.h++']

# Flawfinder has built-in ruleset and comment check
Language({}, c_extensions)
