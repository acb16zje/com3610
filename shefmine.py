import argparse
import cchardet as chardet
import difflib
import git
import json
import os
import re
import vulnerability as vuln


def process_commit_message(message: str) -> str:
    """
    Pre-process the commit message to remove non-content strings

    :param message: The commit message
    :return: The commit message after pre-processing
    """

    return re.sub('git-svn-id.*', '', message).strip()


def is_comment(line: str) -> bool:
    return line.startswith('/**') or line.startswith('*')


def parse_diff(diff):
    for line in diff:
        if line.startswith('+') and not line.startswith('+++'):
            if not is_comment(line[1:].strip()) and not difflib.IS_LINE_JUNK(line):
                print('\x1b[33m+' + line[1:].strip())
        elif line.startswith('-') and not line.startswith('---'):
            if not is_comment(line[1:].strip()) and not difflib.IS_LINE_JUNK(line):
                print('\x1b[1;31m-' + line[1:].strip())


def search_repository(repo: git.Repo, branch: str) -> dict:
    """
    Iterate through all commits of the given repository in the given branch (default: active branch)

    :param repo: The Git repository
    :param branch: The branch to search
    """

    output = {}

    # for commit in repo.iter_commits(branch):
        # return output
    commit = repo.commit('cd2b7a26c776b0754fb98426a67804fd48118708')
    for vulnerability in vuln.vulnerability_list:
        commit_message = process_commit_message(commit.message)
        regex_match = vulnerability.regex.search(commit_message)

        if regex_match is not None:
            if str(commit) not in output:
                output[str(commit)] = {}
                output[str(commit)]['message'] = commit.message
                output[str(commit)]['vulnerabilities'] = []

            # Add vulnerabilities item
            output[str(commit)]['vulnerabilities'].append({
                'name': vulnerability.name,
                'match': regex_match.group()
            })


    # Add files changed
    if str(commit) in output:
        for diff_item in commit.parents[0].diff(commit):
            if 'files_changed' not in output[str(commit)]:
                output[str(commit)]['files_changed'] = []

            # a (LHS) is None for new file
            if diff_item.a_blob is None:
                a = ''
            else:
                a_stream = diff_item.a_blob.data_stream.read()
                a_encoding = chardet.detect(a_stream)['encoding']

                # Encoding is None for binary files
                a = 'binary' if a_encoding is None else a_stream.decode(a_encoding, 'replace').splitlines(True)

            # b (RHS) is None for deleted file
            if diff_item.b_blob is None:
                b = ''
            else:
                b_stream = diff_item.b_blob.data_stream.read()
                b_encoding = chardet.detect(b_stream)['encoding']

                # Encoding is None for binary files
                b = 'binary' if b_encoding is None else b_stream.decode(b_encoding, 'replace').splitlines(True)

            diff = a if a is 'binary' and b is 'binary' else difflib.unified_diff(a, b)
            parse_diff(diff)

            # with open('test.txt', 'w') as outfile:
            #     outfile.writelines(diff)

            output[str(commit)]['files_changed'].append({
                'file': diff_item.a_path,
                # 'diff': ''.join(diff)
            })

    return output


# forward / backward slicing
# python ghdiff
# python cdiff
# python ydiff
# try sequencematcher in difflib
# 89fd8d0353f6dc234bf026594c7b4f00caa8dbd8 httpd: this only changes comment

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
    parser.add_argument('repo', help='Path to the Git repository')
    parser.add_argument('-r', '--revision', type=str, help='Select the starting revision '
                                                           '(Default: the active branch of the repository)')
    parser.add_argument('-o', '--output', type=str, help='Write the result to the specified file name and path '
                                                         '(Default: as output.json in current working directory)')
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

    try:
        output_result(search_repository(git.Repo(args.repo), args.revision), output_path)
    except git.NoSuchPathError:
        print(f"shefmine.py: '{args.repo}' is not a Git repository")
    except git.GitCommandError:
        print(f"shefmine.py: GitCommandError, bad revision '{args.revision}'")
