#!/usr/bin/python3

import argparse
import git
import itertools
import json
import os
import pydriller as pd
import re
import time
import vulnerability as vuln

def process_commit_message(message: str) -> str:
    """
    Pre-process the commit message to remove non-content strings

    :param message: The commit message
    :return: The commit message after pre-processing
    """

    return re.sub('git-svn-id.*', '', message).strip()


def is_trivial_line(line: str) -> bool:
    return not line or line.startswith('//') or line.startswith('#') or line.startswith("/*") or \
               line.startswith("'''") or line.startswith('"""') or line.startswith("*")


def parse_diff(diff: object) -> (list, list):
    added, deleted = [], []

    for line in itertools.islice(diff, 2, None):
        if line.startswith('+'):
            raw_code = line[1:].strip()

            if not is_trivial_line(raw_code):
                added.append(raw_code)
        elif line.startswith('-'):
            raw_code = line[1:].strip()

            if not is_trivial_line(raw_code):
                deleted.append(raw_code)

    return added, deleted


def search_repository(repo: pd.GitRepository, repo_mining: pd.RepositoryMining) -> dict:
    """
    Iterate through all commits of the given repository from the given revision (default: active branch)

    :param repo: The Git repository
    :param repo_mining: The RepositoryMining object
    """

    output = {}

    for commit in repo_mining.traverse_commits():
        print(commit.hash)
        for vulnerability in vuln.vulnerability_list:
            commit_message = process_commit_message(commit.msg)
            regex_match = vulnerability.regex.search(commit_message)

            if regex_match is not None:
                if commit.hash not in output:
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
            for modification in commit.modifications:
                # SLOW: Uses lizard to analyse the function list in the file
                function_list = [method.name for method in modification.methods]

                if function_list:
                    diff = repo.parse_diff(modification.diff)

                    if 'files_changed' not in output[commit.hash]:
                        output[commit.hash]['files_changed'] = []

                    output[commit.hash]['files_changed'].append({
                        'file': modification.old_path,
                        'methods': function_list,
                        # 'added': [(num, line.strip()) for (num, line) in diff['added'] if line],
                        # 'deleted': [(num, line.strip()) for (num, line) in diff['deleted'] if line]
                    })

            # Remove the commit if no changed files are found (no useful code changes)
            if 'files_changed' not in output[commit.hash]:
                output.pop(commit.hash)
    return output


# forward / backward slicing
# try sequencematcher in difflib
# 89fd8d0353f6dc234bf026594c7b4f00caa8dbd8 httpd: this only changes comment
# locally detectable
# # dangerous function
# # # java math random() guessable
# # # strcpy(a, b)

def output_result(output: dict, path: str):
    """
    Output the result into a JSON file

    :param output: The output dictionary
    :param path: Path (file name) of the output file
    """

    print(len(output))

    if os.path.isdir(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, 'w') as outfile:
        json.dump(output, outfile, indent=2)

    print(f'Output result saved to {os.path.realpath(path)}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('repo', help='Path or URL of the Git repository')
    parser.add_argument('-b', '--branch', type=str, help='Only analyse the commits in this branch')
    parser.add_argument('-s', '--single', metavar='HASH', type=str, help='Only analyse the provided commit')
    parser.add_argument('-o', '--output', type=str, help='Write the result to the specified file name and path '
                                                         '(Default: as output.json in current working directory)')
    parser.add_argument('--no-merge', action='store_true', help='Do not include merge commits')
    parser.add_argument('--reverse', action='store_false', help='Analyse the commits from oldest to newest')
    args = parser.parse_args()

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

    try:
        repo = pd.GitRepository(args.repo)
        repo_mining = pd.RepositoryMining(args.repo,
                                          single=args.single,
                                          only_no_merge=args.no_merge,
                                          reversed_order=args.reverse)
        output_result(search_repository(repo, repo_mining), output_path)
    except git.NoSuchPathError:
        print(f"shefmine.py: '{args.repo}' is not a Git repository")
    except git.GitCommandError:
        print(f"shefmine.py: GitCommandError, bad revision '{args.revision}'")

    print(time.time() - start_time)
