#!/bin/python3
"""
Shefmine: A tool for finding vulnerabilities in Git repositories
"""

import argparse
import bandit
import cchardet
import copy
import enum
import flawfinder
import git
import json
import languages.c as c_lang
import languages.python as py_lang
import languages.language as lang
import os
import pydriller as pd
import re
import subprocess
import tempfile
import vulnerability as vuln

from datetime import datetime
from tqdm import tqdm
from typing import Union


class Level(enum.Enum):
    """
    A class to represent the confidence and severity level of vulnerabilities
    """

    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    def __str__(self) -> str:
        return self.name

    @staticmethod
    def from_string(s):
        """
        Convert the argparse string into Level member

        :param s: The argparse string
        :return: The corresponding Level member
        """
        try:
            return Level[s]
        except KeyError:
            raise ValueError()


def search_repository(repo_mining: pd.RepositoryMining, severity: Level, confidence: Level):
    """
    Iterate through all commits of the given repository from the given revision (default: active branch)

    :param repo_mining: The RepositoryMining object
    :param severity: The minimum severity level of vulnerabilities
    :param confidence: The minimum confidence level of vulnerabilities
    """

    output = {}
    gitpython_repo = git.Repo(repo_mining._path_to_repo)
    commit_count = len(list(copy.copy(repo_mining).traverse_commits()))

    for commit in tqdm(repo_mining.traverse_commits(), total=commit_count):
        # Too many files changed will cause the program to hang
        if len(commit.modifications) > 100:
            continue

        commit_message = process_commit_message(commit.msg)
        output[commit.hash] = {'date': str(commit.author_date)}

        # Find matching vulnerabilities
        output[commit.hash]['vulnerabilities'] = [{'name': vulnerability.name, 'match': regex_match.group()}
                                                  for vulnerability in vuln.vulnerability_list
                                                  for regex_match in [vulnerability.regex.search(commit_message)]
                                                  if regex_match]
        if not output[commit.hash]['vulnerabilities']:
            output[commit.hash].pop('vulnerabilities')

        # Add files changed, each modification is a file changed
        for modification in commit.modifications:
            file = modification.old_path if modification.change_type.name is 'DELETE' else modification.new_path
            file_extension = os.path.splitext(file)[1].lower()

            # Skip this file if the file extension is not supported
            if file_extension not in lang.supported_extensions:
                continue

            source_code_dict = get_source_code_dict(gitpython_repo, commit.hash, file, modification.source_code)

            # Encoding will be None or not supported by decode() for some cases
            if not source_code_dict:
                continue

            diff = repo.parse_diff(modification.diff)

            # Run Flawfinder for C/C++ files
            if file_extension in c_lang.c_extensions:
                partial_output = run_flawfinder(diff, source_code_dict, severity, confidence)

            # Run bandit for Python files
            elif file_extension in py_lang.py_extensions:
                partial_output = run_bandit(diff, source_code_dict, severity, confidence)

            # Run 'grep'-like analysis for other languages files (very noisy)
            else:
                diff['unchanged'] = get_unchanged_lines(diff, source_code_dict)
                partial_output = process_diff(diff, file_extension, severity, confidence)

            # Only add the file if it has useful code changes (comments already removed)
            if partial_output:
                if 'files_changed' not in output[commit.hash]:
                    output[commit.hash]['files_changed'] = []

                output[commit.hash]['files_changed'].append({'file': file, **partial_output})

        # Remove the commit if regex doesnt match or no vulnerable lines of code are detected
        if 'vulnerabilities' not in output[commit.hash] and 'files_changed' not in output[commit.hash]:
            output.pop(commit.hash)

    return output


def process_commit_message(message: str) -> str:
    """
    Pre-process the commit message to remove non-content strings

    :param message: The commit message
    :return: The commit message after pre-processing
    """

    # refer to https://github.com/vmware/photon for more patterm to replace
    return re.sub(
        r'(git-svn-id|change-id).*|(acked|cc|reported|reviewed|signed([\s\-_]off)?|submitted|tested)[\s\-_]*(by|on)?:?.*',
        '', message, flags=re.I).strip()


def get_source_code_dict(gitpython_repo: git.Repo, commit_hash: str, file: str, b_source: str) -> dict:
    """
    Get the old and new source code of a file in a given commit

    :param gitpython_repo: The GitPython repository object
    :param commit_hash: The full commit hash
    :param file: The file
    :param b_source: The new source code of the file of the given commit
    :return: A dictionary containing the old and new source code of a given commit
    """

    gitpython_commit = gitpython_repo.commit(commit_hash)

    # First commit does not have parent commit
    if not gitpython_commit.parents:
        return {'new': b_source, 'old': ''}

    diff_item = next(diff_item for diff_item in gitpython_commit.parents[0].diff(gitpython_commit)
                     if diff_item.b_path == file)

    # a (LHS) is None for new file
    if diff_item.a_blob is None:
        a_source = ''
    else:
        a_stream = diff_item.a_blob.data_stream.read()

        # a (LHS) is empty bytes stream if the file has no changes (rare)
        if a_stream == b'':
            a_source = ''
        else:
            # Improve performance by trying UTF-8 codec first
            try:
                a_source = a_stream.decode('utf-8')
            except UnicodeDecodeError:
                a_encoding = cchardet.detect(a_stream)['encoding']

                if a_encoding is None:
                    return False

                try:
                    a_source = a_stream.decode(a_encoding, 'replace')
                except LookupError:
                    return False

    return {'new': b_source, 'old': a_source}


def process_diff(diff: dict, file_extension: str, severity: Level, confidence: Level) -> dict:
    """
    Given the diff of a file, check if any vulnerable lines of code are added or deleted

    :param diff: The diff dictionary containing added and deleted lines of the file
    :param file_extension: The file extension of the file
    :param severity: The minimum severity level of vulnerabilities
    :param confidence: The minimum confidence level of vulnerabilities
    :return: A partial output containing the vulnerable lines of code added or deleted
    """

    partial_output = {}

    # 'grep'-like analysis for other languages
    for language in lang.language_list:
        # Only analyse files that are supported
        if file_extension in language.extensions:
            diff = {k: ((num, line.strip()) for (num, line) in v if language.is_context(line))
                    for k, v in diff.items()}

            # Check if any vulnerable lines of code are added or deleted
            for key, value in diff.items():
                for num, line in value:
                    # Use the regular expressions of the ruleset
                    vulnerability = {rule: language.rule_set[rule] for rule in language.rule_set
                                     if re.compile(fr'\b{rule}\b', re.S).search(line)
                                     and (rule.startswith('import') or not line.strip().startswith('import'))
                                     and include_vulnerability(severity, confidence,
                                                               Level[language.rule_set[rule]['severity']],
                                                               Level[language.rule_set[rule]['confidence']])
                                     }

                    if vulnerability:
                        partial_output = append_vulnerability(partial_output, key, num, line, vulnerability)

            return partial_output


def get_unchanged_lines(diff: dict, source_code_dict) -> list:
    """
    Get the unchanged lines in the commit

    :param diff: The diff dictionary containing added and deleted lines of the file
    :param source_code_dict: The dictionary containing old and new source code
    :return: A list of unchanged lines
    """

    # The line numbers of added and deleted
    diff_line_nums = [line_num for k, v in diff.items() for (line_num, _) in v]

    unchanged_diff = [(index, line) for (index, line) in enumerate(source_code_dict['new'].split('\n'), start=1)
                      if index not in diff_line_nums and line]

    return unchanged_diff


def run_flawfinder(diff: dict, source_code_dict: dict, severity: Level, confidence: Level) -> dict:
    """
    Given the diff of a file in C/C++ extension, check if any vulnerable lines of code
    are added or delete using flawfinder (https://github.com/david-a-wheeler/flawfinder/)

    :param diff: The diff dictionary containing added and deleted lines of the file
    :param source_code_dict: The dictionary containing old and new source code
    :param severity: The minimum severity level of vulnerabilities
    :param confidence: The minimum confidence level of vulnerabilities
    :return: A partial output containing the vulnerable lines of code added or deleted
    """

    partial_output, a_hitlist, b_hitlist = {}, {}, {}

    # source_code_dict: {'new': str, 'old': str}
    for key, source in source_code_dict.items():
        with tempfile.NamedTemporaryFile(mode='w+t') as tmp:
            tmp.write(source)
            tmp.seek(0)

            # Reset hitlist for each file, then run flawfinder,
            flawfinder.hitlist = []
            flawfinder.process_c_file(tmp.name, None)

            # Remove hits that have warning level 0
            filtered_hitlist = {(hit.line, hit.context_text) for hit in flawfinder.hitlist if hit.level > 0}

            if key == 'new':
                # b_hitlist contains added hits
                b_hitlist = filtered_hitlist

                for line_num, line in (b_hitlist & set(diff['added'])):
                    name, vuln_severity_level = flawfinder_get_name_level(flawfinder.hitlist, line_num)

                    if include_vulnerability(severity, confidence, vuln_severity_level):
                        partial_output = append_vulnerability(
                            partial_output,
                            'added',
                            line_num,
                            line,
                            name,
                            severity=vuln_severity_level.__str__()
                        )
            else:
                # a_hitlist contains deleted hits and possible unchanged hits
                a_hitlist = filtered_hitlist

                hits_dict = {
                    'deleted': a_hitlist & set(diff['deleted']),
                    'unchanged': a_hitlist - (a_hitlist & set(diff['deleted']))
                }

                # Deleted and unchanged
                for category, hits in hits_dict.items():
                    for line_num, line in hits:
                        name, vuln_severity_level = flawfinder_get_name_level(flawfinder.hitlist, line_num)

                        if include_vulnerability(severity, confidence, vuln_severity_level):
                            partial_output = append_vulnerability(
                                partial_output,
                                category,
                                line_num,
                                line,
                                name,
                                severity=vuln_severity_level.__str__()
                            )

    return partial_output


def flawfinder_get_name_level(hitlist: list, line_num: int) -> (str, Level):
    """
    Get the name and the severity level of vulnerability found by flawfinder

    :param hitlist: The flawfinder hitlist
    :param line_num: The line number
    :return: A tuple containing the name and severity level
    """

    name, level = next((hit.name, hit.level) for hit in hitlist if hit.line == line_num)

    if level < 3:
        vuln_severity_level = Level.LOW
    elif level > 3:
        vuln_severity_level = Level.HIGH
    else:
        vuln_severity_level = Level.MEDIUM

    return name, vuln_severity_level


def run_bandit(diff: dict, source_code_dict: dict, severity: Level, confidence: Level):
    """
    Given the diff of a file in Python extension, check if any vulnerable lines of code
    are added or delete using bandit (https://github.com/PyCQA/bandit)

    :param diff: The diff dictionary containing added and deleted lines of the file
    :param source_code_dict: The dictionary containing old and new source code
    :param severity: The minimum severity level of vulnerabilities
    :param confidence: The minimum confidence level of vulnerabilities
    :return: A partial output containing the vulnerable lines of code added or deleted
    """

    partial_output, a_hitlist, b_hitlist = {}, {}, {}

    b_conf = bandit.config.BanditConfig()
    b_mgr = bandit.manager.BanditManager(config=b_conf, agg_type=None)

    # source_code_dict: {'new': str, 'old': str}
    for key, source in source_code_dict.items():
        with tempfile.NamedTemporaryFile(mode='w+t') as tmp:
            tmp.write(source)
            tmp.seek(0)

            # Reset results for each file, then run bandit
            b_mgr.results = []
            b_mgr.discover_files([tmp.name])
            b_mgr.run_tests()
            issues = b_mgr.get_issue_list()

            if key == 'new':
                for issue in issues:
                    # Skip the loop if the line is not in the added list
                    try:
                        added_vulnerable_line = next(line for num, line in diff['added'] if num == issue.lineno)

                        if added_vulnerable_line:
                            vuln_severity_level = Level[issue.severity]
                            vuln_confidence_level = Level[issue.confidence]

                            if include_vulnerability(severity, confidence, vuln_severity_level, vuln_confidence_level):
                                partial_output = append_vulnerability(
                                    partial_output, 'added', issue.lineno, added_vulnerable_line, issue.text,
                                    severity=issue.severity, confidence=issue.confidence
                                )
                    except StopIteration:
                        continue
            else:
                for issue in issues:
                    # Skip the loop if the line is not in the deleted list
                    try:
                        deleted_vulnerable_line = next(line for num, line in diff['deleted'] if num == issue.lineno)
                        vuln_severity_level = Level[issue.severity]
                        vuln_confidence_level = Level[issue.confidence]

                        # If the issue if not in diff['deleted'], then it's an unchanged issue
                        if deleted_vulnerable_line:
                            if include_vulnerability(severity, confidence, vuln_severity_level, vuln_confidence_level):
                                partial_output = append_vulnerability(
                                    partial_output, 'deleted', issue.lineno, deleted_vulnerable_line, issue.text,
                                    severity=issue.severity, confidence=issue.confidence
                                )
                        else:
                            unchanged_vulnerable_line = source.splitlines()[issue.lineno - 1]

                            if include_vulnerability(severity, confidence, vuln_severity_level, vuln_confidence_level):
                                partial_output = append_vulnerability(
                                    partial_output, 'unchanged', issue.lineno, unchanged_vulnerable_line, issue.text,
                                    severity=issue.severity, confidence=issue.confidence
                                )
                    except StopIteration:
                        continue

    return partial_output


def include_vulnerability(severity: Level, confidence: Level, vuln_severity: Level,
                          vuln_confidence: Level = Level.NONE) -> bool:
    """
    Check whether the vulnerability found should be included in the output

    :param severity: The minimum severity level of vulnerabilities
    :param confidence: The minimum confidence level of vulnerabilities
    :param vuln_severity: The severity level of the vulnerability
    :param vuln_confidence: The confidence level of the vulnerability
    :return: True if the severity and confidence level of the issue is higher than the minimum specified
    """

    return vuln_severity.value >= severity.value and vuln_confidence.value >= confidence.value


def append_vulnerability(partial_output: dict, key: str, line_num: int,
                         line: str, vulnerability: Union[str, dict], **kwargs) -> dict:
    """
    Append the vulnerability found to the partial output

    :param partial_output: The partial output dictionary
    :param key: The key (added, deleted, or unchanged)
    :param line_num: The line number of the vulnerability
    :param line: The actual code of the vulnerability
    :param vulnerability: The vulnerability description
    :return: The partial output with the vulnerability appended
    """

    if key not in partial_output:
        partial_output[key] = []

    if 'severity' in kwargs and 'confidence' in kwargs:
        partial_output[key].append({
            'line_num': line_num,
            'line': line.strip(),
            'vulnerability': vulnerability,
            'severity': kwargs['severity'],
            'confidence': kwargs['confidence'],
        })
    elif 'severity' in kwargs:
        # Flawfinder has no confidence level
        partial_output[key].append({
            'line_num': line_num,
            'line': line.strip(),
            'vulnerability': vulnerability,
            'severity': kwargs['severity'],
            'confidence': 'NONE'
        })
    else:
        partial_output[key].append({
            'line_num': line_num,
            'line': line.strip(),
            'vulnerability': vulnerability,
        })

    return partial_output


def output_result(output: dict, path: str):
    """
    Output the result into a JSON file

    :param output: The output dictionary
    :param path: Path (file name) of the output file
    """

    print(f'{"Total commits found":<20}: {len(output)}')

    with open(path, 'w') as outfile:
        json.dump(output, outfile, indent=2)

    print(f'{"Output location":<20}: {os.path.realpath(path)}')


def get_repo_name(path: str) -> str:
    """
    Get the name of the repository

    :param path: The path to the repository
    :return: The the
    """

    origin = subprocess.check_output(['git', 'config', '--get', 'remote.origin.url'], cwd=path).decode()
    repo_name, _ = os.path.splitext(os.path.basename(origin))

    return repo_name


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('repo', type=str, help='Path or URL of the Git repository')
    parser.add_argument('-b', '--branch', type=str, help='Only analyse the commits in this branch')
    parser.add_argument('-s', '--single', metavar='HASH', type=str, help='Only analyse the provided commit')
    parser.add_argument('--since', metavar='DATE', default=None,
                        help='Starting date, date included (format: YYYY/MM/DD)')
    parser.add_argument('--to', metavar='DATE', default=None,
                        help='Ending date, date excluded (format: YYYY/MM/DD)')
    parser.add_argument('--from-commit', metavar='HASH', type=str, default=None,
                        help='Starting commit (only if since is None)')
    parser.add_argument('--to-commit', metavar='HASH', type=str, default=None,
                        help='Ending commit (only if to is None)')
    parser.add_argument('--from-tag', metavar='TAG', type=str, default=None,
                        help='Start the analysis from specified tag (only if since and from-commit are None)')
    parser.add_argument('--to-tag', metavar='TAG', type=str, default=None,
                        help='End the analysis to specified tag (only if to and to-commit are None)')
    parser.add_argument('-o', '--output', type=str, help='Write the result to the specified file name and path '
                                                         '(Default: as output.json in current working directory)')
    parser.add_argument('--severity', type=Level.from_string, choices=list(Level), default=Level.NONE,
                        help='Only include vulnerabilities of given severity level or higher '
                             '(Default: NONE, include all)')
    parser.add_argument('--confidence', type=Level.from_string, choices=list(Level), default=Level.NONE,
                        help='Only include vulnerabilities of given confidence level or higher '
                             '(Default: NONE, include all)')
    parser.add_argument('--no-merge', action='store_true', help='Do not include merge commits')
    args = parser.parse_args()

    try:
        # Clone the repo if URL is provided
        self = pd.RepositoryMining(args.repo)
        if self._isremote(args.repo):
            tmp_folder = tempfile.TemporaryDirectory()
            args.repo = self._clone_remote_repos(tmp_folder.name, args.repo)

        repo = pd.GitRepository(args.repo)

        args.single = repo.get_commit(args.single).hash if args.single else None
        args.since = datetime.strptime(args.since, '%Y/%m/%d') if args.since else None
        args.to = datetime.strptime(args.to, '%Y/%m/%d') if args.to else None
        args.from_commit = repo.get_commit(args.from_commit).hash if args.from_commit else None
        args.to_commit = repo.get_commit(args.to_commit).hash if args.to_commit else None

        repo_mining = pd.RepositoryMining(args.repo,
                                          single=args.single,
                                          since=args.since,
                                          to=args.to,
                                          from_commit=args.from_commit,
                                          to_commit=args.to_commit,
                                          from_tag=args.from_tag,
                                          to_tag=args.to_tag,
                                          only_in_branch=args.branch,
                                          only_no_merge=args.no_merge,
                                          reversed_order=True)

        if args.output:
            output_name, output_extension = os.path.splitext(args.output)

            if output_extension:
                if output_extension == '.json':
                    output_path = args.output
                else:
                    print('shefmine.py: Output file extension has been automatically changed to .json')
                    output_path = output_name + '.json'
            else:
                output_path = output_name + '.json'
        else:
            output_path = f'{get_repo_name(args.repo)}.json'

        output_result(search_repository(repo_mining, args.severity, args.confidence), output_path)
    except git.NoSuchPathError:
        print(f"shefmine.py: '{args.repo}' is not a Git repository")
    except git.GitCommandError:
        print(f"shefmine.py: GitCommandError, bad revision '{args.branch}'")
    except git.InvalidGitRepositoryError:
        print(f"shefmine.py: InvalidGitRepositoryError, '{os.path.realpath(args.repo)}'")
