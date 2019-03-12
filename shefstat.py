#!/bin/python3
"""
Shefstat: A tool for analysing the results produced by Shefmine
"""

import argparse
import collections
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

    vulnerabilities_list = (vuln['name']
                            for commit_hash in result
                            if 'vulnerabilities' in result[commit_hash]
                            for vuln in result[commit_hash]['vulnerabilities'])
    # print(collections.Counter(vulnerabilities_list))

    for k, v in collections.Counter(vulnerabilities_list).items():
        print(k)

    regexp_only = sum(1 for commit_hash in result
                      if 'vulnerabilities' in result[commit_hash]
                      and 'files_changed' not in result[commit_hash])

    # Vulnerable lines changed only
    lines_only_dict = {commit_hash: v for commit_hash, v in result.items()
                       if 'vulnerabilities' not in result[commit_hash]
                       and 'files_changed' in result[commit_hash]}

    lines_only = len(lines_only_dict)

    lines_add_only = sum(1 for commit_hash in lines_only_dict
                         if all('added' in f
                                and 'deleted' not in f
                                and 'unchanged' not in f
                                for f in lines_only_dict[commit_hash]['files_changed']))

    lines_delete_only = sum(1 for commit_hash in lines_only_dict
                            if all('added' not in f
                                   and 'deleted' in f
                                   and 'unchanged' not in f
                                   for f in lines_only_dict[commit_hash]['files_changed']))

    lines_unchange_only = sum(1 for commit_hash in lines_only_dict
                              if all('added' not in f
                                     and 'deleted' not in f
                                     and 'unchanged' in f
                                     for f in lines_only_dict[commit_hash]['files_changed']))

    lines_add_and_delete = sum(1 for commit_hash in lines_only_dict
                               if all('added' in f
                                      and 'deleted' in f
                                      and 'unchanged' not in f
                                      for f in lines_only_dict[commit_hash]['files_changed']))

    lines_add_and_unchange = sum(1 for commit_hash in lines_only_dict
                                 if all('added' in f
                                        and 'deleted' not in f
                                        and 'unchanged' in f
                                        for f in lines_only_dict[commit_hash]['files_changed']))

    lines_delete_and_unchange = sum(1 for commit_hash in lines_only_dict
                                    if all('added' not in f
                                           and 'deleted' in f
                                           and 'unchanged' in f
                                           for f in lines_only_dict[commit_hash]['files_changed']))

    # RegExp match and vulnerable lines changed
    both_dict = {commit_hash: v for commit_hash, v in result.items()
                 if 'vulnerabilities' in result[commit_hash]
                 and 'files_changed' in result[commit_hash]}

    both = len(both_dict)

    both_add_only = sum(1 for commit_hash in both_dict
                        if all('added' in f
                               and 'deleted' not in f
                               and 'unchanged' not in f
                               for f in both_dict[commit_hash]['files_changed']))

    both_delete_only = sum(1 for commit_hash in both_dict
                           if all('added' not in f
                                  and 'deleted' in f
                                  and 'unchanged' not in f
                                  for f in both_dict[commit_hash]['files_changed']))

    both_unchange_only = sum(1 for commit_hash in both_dict
                             if all('added' not in f
                                    and 'deleted' not in f
                                    and 'unchanged' in f
                                    for f in both_dict[commit_hash]['files_changed']))

    both_add_and_delete = sum(1 for commit_hash in both_dict
                              if all('added' in f
                                     and 'deleted' in f
                                     and 'unchanged' not in f
                                     for f in both_dict[commit_hash]['files_changed']))

    both_add_and_unchange = sum(1 for commit_hash in both_dict
                                if all('added' in f
                                       and 'deleted' not in f
                                       and 'unchanged' in f
                                       for f in both_dict[commit_hash]['files_changed']))

    both_delete_and_unchange = sum(1 for commit_hash in both_dict
                                   if all('added' not in f
                                          and 'deleted' in f
                                          and 'unchanged' in f
                                          for f in both_dict[commit_hash]['files_changed']))

    print(f'{"Total commits found":<53}: {total_commits}')
    print(f'{"":>2}{"├── ONLY Vulnerability RegExp match":<51}: {regexp_only}')
    print(f'{"":>2}│')
    print(f'{"":>2}{"├── ONLY Vulnerable lines changed":<51}: {lines_only}')
    print(f'{"":>2}│{"":>5}{"├── ONLY Added lines":<50}: {lines_add_only}')
    print(f'{"":>2}│{"":>5}{"├── ONLY Deleted lines":<50}: {lines_delete_only}')
    print(f'{"":>2}│{"":>5}{"├── ONLY Unchanged lines":<50}: {lines_unchange_only}')
    print(f'{"":>2}│{"":>5}│')
    print(f'{"":>2}│{"":>5}{"├── ONLY Added AND Delete lines":<50}: {lines_add_and_delete}')
    print(f'{"":>2}│{"":>5}{"├── ONLY Added AND Unchanged lines":<50}: {lines_add_and_unchange}')
    print(f'{"":>2}│{"":>5}{"└── ONLY Delete AND Unchanged lines":<50}: {lines_delete_and_unchange}')
    print(f'{"":>2}│')
    print(f'{"":>2}{"└── BOTH RegExp match and vulnerable lines changed":<51}: {both}')
    print(f'{"":>8}{"├── ONLY Added lines":<50}: {both_add_only}')
    print(f'{"":>8}{"├── ONLY Deleted lines":<50}: {both_delete_only}')
    print(f'{"":>8}{"├── ONLY Unchanged lines":<50}: {both_unchange_only}')
    print(f'{"":>8}│')
    print(f'{"":>8}{"├── ONLY Added AND Delete lines":<50}: {both_add_and_delete}')
    print(f'{"":>8}{"├── ONLY Added AND Unchanged lines":<50}: {both_add_and_unchange}')
    print(f'{"":>8}{"└── ONLY Delete AND Unchanged lines":<50}: {both_delete_and_unchange}')


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
