"""
Python Programming Language
Bandit is used to analyse Python files
"""

import re

py_extensions = ['.py']
py_comments = re.compile(r'^#.*', re.S)
