#!/bin/python3
"""
Shefstat: A tool for analysing the results produced by Shefmine
"""

import argparse
import json


def analyse_result(result: dict) -> None:
    """
    Analyse the result file to show
    1. The number of issues found
    2. THe number of commits that matched the vulnerability RegExp
    3. The number of commits that do not match the vulnerability RegExp,
       but, have vulnerable lines changed
    4. Both 2. and 3.

    :param result: The result file produced by Shefmine
    """

    total_commits = len(result)

    regexp_only = sum(1 for commit_hash in result
                      if 'vulnerabilities' in result[commit_hash]
                      and 'files_changed' not in result[commit_hash])

    lines_only = sum(1 for commit_hash in result
                     if 'vulnerabilities' not in result[commit_hash]
                     and 'files_changed' in result[commit_hash])

    both = sum(1 for commit_hash in result
                     if 'vulnerabilities' in result[commit_hash]
                     and 'files_changed' in result[commit_hash])

    print(f'{"Total commits found":<54}: {total_commits}')
    print(f'{"Commits with vulnerability RegExp match ONLY":<54}: {regexp_only}')
    print(f'{"Commits with vulnerable lines changed ONLY":<54}: {lines_only}')
    print(f'{"Commits with RegExp match and vulnerable lines changed":<54}: {both}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('file', type=str, help='Path of the output JSON file')

    args = parser.parse_args()

    try:
        with open(args.file) as file:
            result = json.load(file)

        analyse_result(result)
    except FileNotFoundError:
        print(f"shefstat.py: FileNotFoundError, no such file '{args.file}'")
    except json.JSONDecodeError:
        print(f"shefstat.py: JSONDecodeError, '{args.file}' is not a valid JSON file")
