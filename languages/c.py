"""
C/C++ Programming Language
Flawfinder is used to analyse C/C++ files
"""

import re

c_extensions = ['.c', '.cc', '.cpp', '.cxx', '.c++', '.mm', '.h', '.hh', '.hpp', '.hxx', '.h++']
c_comments = re.compile(r'^(/\*|\*|\*/|//)', re.S)
