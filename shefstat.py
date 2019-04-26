#!/bin/python3
"""
Shefstat: A tool for analysing the results produced by Shefmine
"""

import argparse
import collections
import json

from datetime import datetime
from typing import Union


def show_regex_and_lines(result: dict):
    """
    Analyse the result file to show
    1. The number of issues found
    2. THe number of commits that matched the vulnerability RegExp
    3. The number of commits that do not match the vulnerability RegExp,
       but, have vulnerable lines changed
    4. Both 2. and 3.

    :param result: The result file produced by Shefmine
    """

    regexp_only = sum(1 for commit in result
                      if 'vulnerabilities' in result[commit]
                      and 'files_changed' not in result[commit])

    # Vulnerable lines changed only
    lines_only_dict = {commit: v for commit, v in result.items()
                       if 'vulnerabilities' not in result[commit]
                       and 'files_changed' in result[commit]}

    lines_only = len(lines_only_dict)

    lines_add_only = sum(1 for commit in lines_only_dict
                         if all('added' in f
                                and 'deleted' not in f
                                and 'unchanged' not in f
                                for f in lines_only_dict[commit]['files_changed']))

    lines_delete_only = sum(1 for commit in lines_only_dict
                            if all('added' not in f
                                   and 'deleted' in f
                                   and 'unchanged' not in f
                                   for f in lines_only_dict[commit]['files_changed']))

    lines_unchange_only = sum(1 for commit in lines_only_dict
                              if all('added' not in f
                                     and 'deleted' not in f
                                     and 'unchanged' in f
                                     for f in lines_only_dict[commit]['files_changed']))

    lines_add_and_delete = sum(1 for commit in lines_only_dict
                               if all('added' in f
                                      and 'deleted' in f
                                      and 'unchanged' not in f
                                      for f in lines_only_dict[commit]['files_changed']))

    lines_add_and_unchange = sum(1 for commit in lines_only_dict
                                 if all('added' in f
                                        and 'deleted' not in f
                                        and 'unchanged' in f
                                        for f in lines_only_dict[commit]['files_changed']))

    lines_delete_and_unchange = sum(1 for commit in lines_only_dict
                                    if all('added' not in f
                                           and 'deleted' in f
                                           and 'unchanged' in f
                                           for f in lines_only_dict[commit]['files_changed']))

    # RegExp match and vulnerable lines changed
    both_dict = {commit: v for commit, v in result.items()
                 if 'vulnerabilities' in result[commit]
                 and 'files_changed' in result[commit]}

    both = len(both_dict)

    both_add_only = sum(1 for commit in both_dict
                        if all('added' in f
                               and 'deleted' not in f
                               and 'unchanged' not in f
                               for f in both_dict[commit]['files_changed']))

    both_delete_only = sum(1 for commit in both_dict
                           if all('added' not in f
                                  and 'deleted' in f
                                  and 'unchanged' not in f
                                  for f in both_dict[commit]['files_changed']))

    both_unchange_only = sum(1 for commit in both_dict
                             if all('added' not in f
                                    and 'deleted' not in f
                                    and 'unchanged' in f
                                    for f in both_dict[commit]['files_changed']))

    both_add_and_delete = sum(1 for commit in both_dict
                              if all('added' in f
                                     and 'deleted' in f
                                     and 'unchanged' not in f
                                     for f in both_dict[commit]['files_changed']))

    both_add_and_unchange = sum(1 for commit in both_dict
                                if all('added' in f
                                       and 'deleted' not in f
                                       and 'unchanged' in f
                                       for f in both_dict[commit]['files_changed']))

    both_delete_and_unchange = sum(1 for commit in both_dict
                                   if all('added' not in f
                                          and 'deleted' in f
                                          and 'unchanged' in f
                                          for f in both_dict[commit]['files_changed']))

    pad = f'{"":>2}'
    nested_pad = pad + f'│{"":>5}'
    final_pad = f'{"":>8}'

    print(f'{pad}{"├── ONLY Vulnerability RegExp match":<51}: {regexp_only}')
    print(f'{pad}│')
    print(f'{pad}{"├── ONLY Vulnerable lines changed":<51}: {lines_only}')
    print(f'{nested_pad}{"├── ONLY Added lines":<50}: {lines_add_only}')
    print(f'{nested_pad}{"├── ONLY Deleted lines":<50}: {lines_delete_only}')
    print(f'{nested_pad}{"├── ONLY Unchanged lines":<50}: {lines_unchange_only}')
    print(f'{nested_pad}│')
    print(f'{nested_pad}{"├── ONLY Added AND Deleted lines":<50}: {lines_add_and_delete}')
    print(f'{nested_pad}{"├── ONLY Added AND Unchanged lines":<50}: {lines_add_and_unchange}')
    print(f'{nested_pad}{"└── ONLY Deleted AND Unchanged lines":<50}: {lines_delete_and_unchange}')
    print(f'{pad}│')
    print(f'{pad}{"└── BOTH RegExp match and vulnerable lines changed":<51}: {both}')
    print(f'{final_pad}{"├── ONLY Added lines":<50}: {both_add_only}')
    print(f'{final_pad}{"├── ONLY Deleted lines":<50}: {both_delete_only}')
    print(f'{final_pad}{"├── ONLY Unchanged lines":<50}: {both_unchange_only}')
    print(f'{final_pad}│')
    print(f'{final_pad}{"├── ONLY Added AND Deleted lines":<50}: {both_add_and_delete}')
    print(f'{final_pad}{"├── ONLY Added AND Unchanged lines":<50}: {both_add_and_unchange}')
    print(f'{final_pad}{"└── ONLY Deleted AND Unchanged lines":<50}: {both_delete_and_unchange}')


def severity_confidence_stats(severity_level: str, result: Union[list, dict], confidence_level: str = None):
    """
    Calculate the number of vulnerabilities with given severity and confidence level

    :param severity_level: Severity level
    :param result: Result dictionary
    :param confidence_level: Confidence level
    :return:
    """

    if hasattr(result, 'items'):
        for k, v in result.items():
            if k == 'severity' and v in severity_level:
                if confidence_level:
                    if result['confidence'] in confidence_level:
                        yield 1
                else:
                    yield 1
            if isinstance(v, dict):
                if confidence_level:
                    for result in severity_confidence_stats(severity_level, v, confidence_level):
                        yield result
                else:
                    for result in severity_confidence_stats(severity_level, v):
                        yield result
            elif isinstance(v, list):
                for d in v:
                    if confidence_level:
                        for result in severity_confidence_stats(severity_level, d, confidence_level):
                            yield result
                    else:
                        for result in severity_confidence_stats(severity_level, d):
                            yield result


def show_total_commits(result: dict):
    """
    Prints total commits found

    :param result: The result file produced by Shefmine
    """
    print(f'{"Total commits found":<53}: {len(result)}')


def show_commit_years(result: dict):
    """
    Prints a list of years

    :param result: The result file produced by Shefmine
    """
    date_list = (datetime.strptime(result[commit]['date'], '%Y-%m-%d %H:%M:%S%z').year for commit in result)

    [print(f'{"":>2}├── {k:<7}: {v}')
     for k, v in sorted(collections.Counter(date_list).items(), key=lambda item: item[0], reverse=True)]


def show_severity_confidence(result: dict):
    """
    Prints severity and confidence statistics

    :param result: The result file produced by Shefmine
    """
    pad = f'{"":>2}'
    nested_pad = pad + f'│{"":>5}'

    print(f'{pad}{"├── Severity: LOW":<51}: {sum(severity_confidence_stats("LOW", result))}')
    print(f'{nested_pad}{"├── Confidence: NONE":<49}: {sum(severity_confidence_stats("LOW", result, "NONE"))}')
    print(f'{nested_pad}{"├── Confidence: LOW":<49}: {sum(severity_confidence_stats("LOW", result, "LOW"))}')
    print(f'{nested_pad}{"├── Confidence: MEDIUM":<49}: {sum(severity_confidence_stats("LOW", result, "MEDIUM"))}')
    print(f'{nested_pad}{"└── Confidence: HIGH":<49}: {sum(severity_confidence_stats("LOW", result, "HIGH"))}')
    print(f'{pad}{"├── Severity: MEDIUM":<51}: {sum(severity_confidence_stats("MEDIUM", result))}')
    print(f'{nested_pad}{"├── Confidence: NONE":<49}: {sum(severity_confidence_stats("MEDIUM", result, "NONE"))}')
    print(f'{nested_pad}{"├── Confidence: LOW":<49}: {sum(severity_confidence_stats("MEDIUM", result, "LOW"))}')
    print(f'{nested_pad}{"├── Confidence: MEDIUM":<49}: {sum(severity_confidence_stats("MEDIUM", result, "MEDIUM"))}')
    print(f'{nested_pad}{"└── Confidence: HIGH":<49}: {sum(severity_confidence_stats("MEDIUM", result, "HIGH"))}')
    print(f'{pad}{"├── Severity: HIGH":<51}: {sum(severity_confidence_stats("HIGH", result))}')
    print(f'{nested_pad}{"├── Confidence: NONE":<49}: {sum(severity_confidence_stats("HIGH", result, "NONE"))}')
    print(f'{nested_pad}{"├── Confidence: LOW":<49}: {sum(severity_confidence_stats("HIGH", result, "LOW"))}')
    print(f'{nested_pad}{"├── Confidence: MEDIUM":<49}: {sum(severity_confidence_stats("HIGH", result, "MEDIUM"))}')
    print(f'{nested_pad}{"└── Confidence: HIGH":<49}: {sum(severity_confidence_stats("HIGH", result, "HIGH"))}')


def show_regex_vulnerabilities(result: dict):
    """
    Prints vulnerabilities found by RegExp

    :param result: The result file produced by Shefmine
    """
    vulnerabilities_list = (vuln['name'] for commit in result
                            if 'vulnerabilities' in result[commit]
                            for vuln in result[commit]['vulnerabilities'])

    [print(f'{"":>2}├── {k:<51}: {v}')
     for k, v in collections.Counter(vulnerabilities_list).most_common()]


def get_random_commits(result: dict, size: int, seed: int, severity_level: str = 'LOW,MEDIUM,HIGH',
                       confidence_level: str = 'NONE,LOW,MEDIUM,HIGH'):
    """
    Prints random commits for evaluation purposes

    :param result: The result file produced by Shefmine
    :param size: The sample size (number of commits to returned)
    :param seed: The seed used to get the random commits
    :param severity_level: The minimum severity level
    :param confidence_level: The minimum confidence level
    """

    print('ONLY Vulnerability RegExp match \n================================')
    get_samples([commit for commit in result
                 if 'vulnerabilities' in result[commit]
                 and 'files_changed' not in result[commit]], size, seed)

    # Vulnerable lines changed only
    lines_only_dict = {commit: v for commit, v in result.items()
                       if 'vulnerabilities' not in v
                       and 'files_changed' in v
                       and sum(severity_confidence_stats(severity_level, v, confidence_level))}

    print('\nONLY Vulnerable lines changed \n================================')
    get_samples(list(lines_only_dict), size, seed)

    print('\nONLY Vulnerable lines changed: Added \n================================')
    get_samples([commit for commit in lines_only_dict
                 if all('added' in f
                        and 'deleted' not in f
                        and 'unchanged' not in f
                        for f in lines_only_dict[commit]['files_changed'])], size, seed)

    print('\nONLY Vulnerable lines changed: Deleted \n================================')
    get_samples([commit for commit in lines_only_dict
                 if all('added' not in f
                        and 'deleted' in f
                        and 'unchanged' not in f
                        for f in lines_only_dict[commit]['files_changed'])], size, seed)

    print('\nONLY Vulnerable lines changed: Unchanged \n================================')
    get_samples([commit for commit in lines_only_dict
                 if all('added' not in f
                        and 'deleted' not in f
                        and 'unchanged' in f
                        for f in lines_only_dict[commit]['files_changed'])], size, seed)

    print('\nONLY Vulnerable lines changed: Added and Deleted\n================================')
    get_samples([commit for commit in lines_only_dict
                 if all('added' in f
                        and 'deleted' in f
                        and 'unchanged' not in f
                        for f in lines_only_dict[commit]['files_changed'])], size, seed)

    print('\nBOTH RegExp match and vulnerable lines changed\n================================')
    get_samples([commit for commit in result
                 if 'vulnerabilities' in result[commit] and 'files_changed' in result[commit]], size, seed)

    exit(0)


def get_samples(samples: list, size: int, seed: int):
    """

    :param samples: List of filtered commits
    :param size: The sample size (number of commits to returned)
    :param seed: The seed used to get the random commits
    """
    import random

    sample_size = size
    r = random.Random(seed)

    try:
        [print(x) for x in r.sample(samples, sample_size)]
    except ValueError:
        [print(x) for x in r.sample(samples, len(samples))]


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('file', type=str, help='Path of the output JSON file')
    parser.add_argument('-e', '--evaluate', action='store_true', help='Get random commits for evaluation')
    parser.add_argument('--seed', type=int, help='Seed to get random commits (Default: 3243)', default=3243)
    parser.add_argument('--size', type=int, help='Sample size of random commits (Default: 4)', default=4)

    args = parser.parse_args()

    try:
        with open(args.file) as file:
            result = json.load(file)

        # Evaluation only
        if args.evaluate:
            get_random_commits(result, args.size, args.seed, severity_level='HIGH', confidence_level='NONE,HIGH')

        show_total_commits(result)
        print(f'{"":>2}│')
        show_commit_years(result)
        print(f'{"":>2}│')
        show_regex_vulnerabilities(result)
        print(f'{"":>2}│')
        show_severity_confidence(result)
        print(f'{"":>2}│')
        show_regex_and_lines(result)
    except FileNotFoundError:
        print(f"shefstat.py: FileNotFoundError, no such file '{args.file}'")
    except json.JSONDecodeError:
        print(f"shefstat.py: JSONDecodeError, '{args.file}' is not a valid JSON file")
