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

    lines_add_only = sum(1 for commit_hash in result
                         if 'vulnerabilities' not in result[commit_hash]
                         and 'files_changed' in result[commit_hash]
                         and all('added' in f
                                 and 'deleted' not in f
                                 and 'unchanged' not in f
                                 for f in result[commit_hash]['files_changed']))

    lines_delete_only = sum(1 for commit_hash in result
                            if 'vulnerabilities' not in result[commit_hash]
                            and 'files_changed' in result[commit_hash]
                            and all('added' not in f
                                    and 'deleted' in f
                                    and 'unchanged' not in f
                                    for f in result[commit_hash]['files_changed']))

    lines_unchange_only = sum(1 for commit_hash in result
                              if 'vulnerabilities' not in result[commit_hash]
                              and 'files_changed' in result[commit_hash]
                              and all('added' not in f
                                      and 'deleted' not in f
                                      and 'unchanged' in f
                                      for f in result[commit_hash]['files_changed']))

    # RegExp match and vulnerable lines changed
    both = sum(1 for commit_hash in result
               if 'vulnerabilities' in result[commit_hash]
               and 'files_changed' in result[commit_hash])

    both_add_only = sum(1 for commit_hash in result
                        if 'vulnerabilities' in result[commit_hash]
                        and 'files_changed' in result[commit_hash]
                        and all('added' in f
                                and 'deleted' not in f
                                and 'unchanged' not in f
                                for f in result[commit_hash]['files_changed']))

    both_delete_only = sum(1 for commit_hash in result
                           if 'vulnerabilities' in result[commit_hash]
                           and 'files_changed' in result[commit_hash]
                           and all('added' not in f
                                   and 'deleted' in f
                                   and 'unchanged' not in f
                                   for f in result[commit_hash]['files_changed']))

    both_unchange_only = sum(1 for commit_hash in result
                             if 'vulnerabilities' in result[commit_hash]
                             and 'files_changed' in result[commit_hash]
                             and all('added' not in f
                                     and 'deleted' not in f
                                     and 'unchanged' in f
                                     for f in result[commit_hash]['files_changed']))

    print(f'{"Total commits found":<53}: {total_commits}')
    print(f'{"":>2}{"├── ONLY Vulnerability RegExp match":<51}: {regexp_only}')
    print(f'{"":>2}{"├── ONLY Vulnerable lines changed":<51}: {lines_only}')
    print(f'{"":>2}│{"":>5}{"├── ONLY Added lines":<50}: {lines_add_only}')
    print(f'{"":>2}│{"":>5}{"├── ONLY Deleted lines":<50}: {lines_delete_only}')
    print(f'{"":>2}│{"":>5}{"└── ONLY Unchanged lines":<50}: {lines_unchange_only}')
    print(f'{"":>2}{"└── BOTH RegExp match and vulnerable lines changed":<51}: {both}')
    print(f'{"":>8}{"├── ONLY Added lines":<50}: {both_add_only}')
    print(f'{"":>8}{"├── ONLY Deleted lines":<50}: {both_delete_only}')
    print(f'{"":>8}{"└── ONLY Unchanged lines":<50}: {both_unchange_only}')


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
