#!/bin/python3
"""
Shefmine main
"""

import argparse
import cchardet
import flawfinder
import git
import json
import languages.c as c_lang
import languages.language as lang
import os
import pydriller as pd
import re
import tempfile
import time
import vulnerability as vuln


def search_repository(repo: pd.GitRepository, repo_mining: pd.RepositoryMining):
    """
    Iterate through all commits of the given repository from the given revision (default: active branch)

    :param repo: The Git repository
    :param repo_mining: The RepositoryMining object
    """

    output = {}

    for commit in repo_mining.traverse_commits():
        for vulnerability in vuln.vulnerability_list:
            commit_message = process_commit_message(commit.msg)
            regex_match = vulnerability.regex.search(commit_message)

            if regex_match is not None and commit.hash not in output:
                output[commit.hash] = {}
                output[commit.hash]['message'] = commit.msg
                output[commit.hash]['vulnerabilities'] = []

                # Add vulnerabilities item
                output[commit.hash]['vulnerabilities'].append({
                    'name': vulnerability.name,
                    'match': regex_match.group()
                })

        # Add files changed
        if commit.hash in output:
            # Each modification is a file changed
            for modification in commit.modifications:
                file = modification.old_path if modification.change_type.name is 'DELETE' else modification.new_path
                _, file_extension = os.path.splitext(file)

                # Run Flawfinder for C/C++ files, and 'grep'-like analysis for other languages files
                if file_extension.lower() in c_lang.c_extensions:
                    gitpython_commit = git.Repo(commit.project_path).commit(commit.hash)
                    diff_item = (diff_item for diff_item in gitpython_commit.parents[0].diff(gitpython_commit)
                                 if diff_item.b_path == file).__next__()

                    # a (LHS) is None for new file
                    if diff_item.a_blob is None:
                        a_source = ''
                    else:
                        a_stream = diff_item.a_blob.data_stream.read()
                        a_encoding = cchardet.detect(a_stream)['encoding']
                        a_source = a_stream.decode(a_encoding)

                    b_source = modification.source_code
                    source_code_dict = {'new': b_source, 'old': a_source}

                    partial_output = run_flawfinder(repo.parse_diff(modification.diff), source_code_dict)
                else:
                    partial_output = process_diff(repo.parse_diff(modification.diff), file_extension)

                # Only add the file if it has useful code changes (comments already removed)
                if partial_output:
                    if 'files_changed' not in output[commit.hash]:
                        output[commit.hash]['files_changed'] = []

                    output[commit.hash]['files_changed'].append({'file': file, **partial_output})

            # Remove the commit if no changed files are found (no useful code changes)
            # if 'files_changed' not in output[commit.hash]:
            #     output.pop(commit.hash)

    return output


def process_commit_message(message: str) -> str:
    """
    Pre-process the commit message to remove non-content strings

    :param message: The commit message
    :return: The commit message after pre-processing
    """

    # refer to https://github.com/vmware/photon for more patterm to replace
    return re.sub(r'git-svn-id.*|(acked|cc|reported|reviewed|signed([\s\-_]off)?|submitted|tested)[\s\-_]*(by|on)?:.*',
                  '', message, flags=re.I).strip()


def process_diff(diff: dict, file_extension: str) -> dict:
    """
    Given the diff of a file, check if any vulnerable lines of code are added or deleted

    :param diff: The diff dictionary containing added and deleted lines of the file
    :param file_extension: The file extension of the file
    :return: A partial output containing the vulnerable lines of code added or deleted
    """

    partial_output = {}

    # 'grep'-like analysis for other languages
    for language in lang.language_list:
        # Only analyse files that are supported
        if file_extension.lower() in language.extensions:
            diff = {k: ((num, line.strip()) for (num, line) in v if line and language.is_not_comment(line))
                    for k, v in diff.items()}

            # Check if any vulnerable lines of code are added or deleted
            for key, value in diff.items():
                for num, line in value:
                    vulnerability = []

                    for type, rule_set in language.rule_set.items():
                        for rule in rule_set:
                            if re.compile(fr'\b{rule}\b', re.S).search(line):
                                vulnerability.append(rule)

                    if vulnerability:
                        if key not in partial_output:
                            partial_output[key] = []

                        partial_output[key].append({
                            'line_num': num,
                            'line': line.strip(),
                            'vulnerability': vulnerability
                        })
    return partial_output


def run_flawfinder(diff: dict, source_code_dict: dict) -> dict:
    """
    Given the diff of a file in C/C++ extension, check if any vulnerable lines of code
    are added or delete using flawfinder (https://github.com/david-a-wheeler/flawfinder/)

    :param diff: The diff dictionary containing added and deleted lines of the file
    :param source_code_dict: The dictionary containing old and new source code
    :return: A partial output containing the vulnerable lines of code added or deleted
    """

    partial_output, a_hitlist, b_hitlist = {}, {}, {}

    for key, source in source_code_dict.items():
        with tempfile.NamedTemporaryFile(mode='w+t') as tmp:
            # Reset hitlist as it is saved as global variable
            flawfinder.hitlist = []

            # Run flawfinder
            tmp.write(source)
            tmp.seek(0)
            flawfinder.process_c_file(tmp.name, None)

            # Remove hits that have warning level 0
            filtered_hitlist = {(hit.line, hit.context_text) for hit in flawfinder.hitlist if hit.level > 0}

            if key == 'new':
                # b_hitlist contains added hits
                b_hitlist = filtered_hitlist

                for line_num, line in (b_hitlist & set(diff['added'])):
                    if 'added' not in partial_output:
                        partial_output['added'] = []

                    partial_output['added'].append({
                        'line_num': line_num,
                        'line': line.strip(),
                        'vulnerability': (hit.name for hit in flawfinder.hitlist if hit.line == line_num).__next__()
                    })
            else:
                # a_hitlist contains deleted hits and possible hidden hits
                a_hitlist = filtered_hitlist

                hits_dict = {
                    'deleted': a_hitlist & set(diff['deleted']),
                    'hidden': a_hitlist - (a_hitlist & set(diff['deleted']))
                }

                for category, hits in hits_dict.items():
                    for line_num, line in hits:
                        if category not in partial_output:
                            partial_output[category] = []

                        partial_output[category].append({
                            'line_num': line_num,
                            'line': line.strip(),
                            'vulnerability': (hit.name for hit in flawfinder.hitlist if hit.line == line_num).__next__()
                        })
    return partial_output


def output_result(output: dict, path: str):
    """
    Output the result into a JSON file

    :param output: The output dictionary
    :param path: Path (file name) of the output file
    """

    print(f'{"Issues found":<16}: {len(output)}')

    if os.path.isdir(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, 'w') as outfile:
        json.dump(output, outfile, indent=2)

    print(f'{"Output location":<16}: {os.path.realpath(path)}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('repo', help='Path or URL of the Git repository')
    parser.add_argument('-b', '--branch', type=str, help='Only analyse the commits in this branch')
    parser.add_argument('-s', '--single', metavar='HASH', type=str, help='Only analyse the provided commit (full hash)')
    parser.add_argument('-o', '--output', type=str, help='Write the result to the specified file name and path '
                                                         '(Default: as output.json in current working directory)')
    parser.add_argument('--no-merge', action='store_true', help='Do not include merge commits')
    parser.add_argument('--reverse', action='store_false', help='Analyse the commits from oldest to newest')
    args = parser.parse_args()

    try:
        repo = pd.GitRepository(args.repo)
        repo_mining = pd.RepositoryMining(args.repo,
                                          single=args.single,
                                          only_in_branch=args.branch,
                                          only_no_merge=args.no_merge,
                                          reversed_order=args.reverse)

        if args.output:
            output_name, output_extension = os.path.splitext(args.output)

            if output_extension:
                if output_extension == '.json':
                    output_path = args.output
                else:
                    print('shefmine.py: Output file extension has been automatically changed to .json')
                    output_path = os.path.realpath(output_name + '.json')
            else:
                output_path = os.path.realpath(os.path.join(output_name, 'output.json'))
        else:
            output_path = 'output.json'

        start_time = time.time()

        output_result(search_repository(repo, repo_mining), output_path)

        print(f'{"Time taken":<16}: {(time.time() - start_time):.2f} seconds')
    except git.NoSuchPathError:
        print(f"shefmine.py: '{args.repo}' is not a Git repository")
    except git.GitCommandError:
        print(f"shefmine.py: GitCommandError, bad revision '{args.branch}'")
