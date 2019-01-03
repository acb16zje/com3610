import argparse
import git
import re

class Vulnerability:
    def __init__(self, name, regex):
        self.name = name
        self.regex = regex

# Injection
injection = re.compile('(sql|http header|xxe|nosql|ldap|regex|xpath|xquery|code|queries|xml|html|(shell|os |oper.* sys|command|cmd)|e(-)?mail).*injec|(patch|fix|prevent|found|protect).*(injec| sqli | osci )|(injec|sqli |osci ).*(patch|fix|prevent|found|protect)|(sanitiz).* header(s)?|header(s)?( sanitiz)|quer.* parametriz|(parametriz).* quer')

# Broken Authentication and Session Management
auth = re.compile('brute.*force|sess.*hijack|broken auth|auth.* brok|auth.* bypass|sess.* fixation|(cred|pass|session( )?id|connect).*(plaintext|un(hash|salt|encrypt|safe))|(plaintext|un(hash|salt|encrypt|safe)).*(cred|pass|session( )?id|connect)|(weak|bad|unsafe).* pass.* verif|fix.* (url rewriting|rewriting url)|timeout.*(session|auth.* token)')

# Cross-Site Scripting
xss = re.compile('(fix|prevent|protect|found|patch).* (xss|cross.*(site|zone) script|script.* attack)|(xss|cross.*(site|zone) script|script.* attack).* (fix|prevent|protect|found|patch)|crlf injec|http resp.* split|(reflect|stored|dom).*xss|xss.*(reflect|stored|dom)|xss (vuln|attack|issue)|(validate|sanitize).* (un(trusted|safe)|malicious)')

# Broken Access Control
boa = re.compile('(fix|prevent|protect|patch|found).* ((impro.* (auth|access.* control))|url.* access)|((impro.* (auth|access.* control))|url.* access).* (fix|prevent|protect|patch|found)|insec.* direct obj.* ref.*|direct ref.*|auth.* bypass.* control')

# Security Misconfiguration
smis = re.compile('(fix|prevent|protect|patch|found).* ((impro.* (auth|access.* control))|url.* access)|((impro.* (auth|access.* control))|url.* access).* (fix|prevent|protect|patch|found)|insec.* direct obj.* ref.*|direct ref.*|auth.* bypass.* control')

# Sensitive Data Exposure
sde = re.compile('(fix|prevent|found|protect|patch).* (man.*in.*midle|mitm|bucket.*brig)|(un|not).*encrypt.* data|(weak|bad|unsafe).*(pass.* hash|key (gener|management))|(important|safe).* header(s)? miss|unsafe.* crypto|(change|update|add).* (https|sec.*cookie.* flag)|rem.* http|(fix|rem).* (secret.*key|hash collision)|(patch|fix|prevent|upgrade|protect).* (sha([- ])?1|md5|md2|md4|(3)?des|collision)')

# Insufficient Attack Protection
iap = re.compile('(detect|block|answer|respond|prevent).* (attack|expolit)|(attack|expolit).* (detect|block|answer|respond|prevent)')

# Cross-Site Request Forgery
csrf = re.compile('(fix|prevent|protect|found|patch).*(cross([- ])?site.*(req|ref).*forgery|csrf|sea.*surf|xsrf)|(cross([- ])?site.*(req|ref).*forgery|csrf|sea.*surf|xsrf).*(fix|prevent|protect|found|patch)|(one.*click|autom).*attack|sess.*riding|conf.*deput')

# Using Components with Known Vulnerabilities
component = re.compile('(vuln|(un|not )safe|malicious).* (version|dependenc|component|librar)')

# Underprotected APIs
upapi = re.compile('(fix|protect).* api|api.* (fix|protect)|secure.* commun')

# Path/Directory Traversal
pathtrav = re.compile('((path|dir.*) traver.*|(dot-dot-slash|directory traversal|directory climbing|backtracking).*(attack|vuln))')

# Distributed Denial-of-Service/Denial-of-Service
dos = re.compile('( dos |((distributed)? denial.*of.*service)| ddos |deadlocks)')

# sha-1 collision
sha1 = re.compile('(sha-1|sha 1|sha1) collision')

# Memory Leaks
ml = re.compile('(fix|rem|patch|found|prevent) mem.* leak|mem.* leak (fix|rem|patch|found|prevent)')

# Context Leaks
cl = re.compile('(fix|rem|patch|found|prevent).*context leak|context leak.*(fix|rem|patch|found|prevent)')

# Resource Leaks
rl = re.compile('(fix|rem|patch|found|prevent).* resource.* leaks|resource.* leaks (fix|rem|patch|found|prevent)')

# Overflow
over = re.compile('(fix|rem|patch|found|prevent).* overflow|overflow.* (fix|rem|patch|found|prevent)')

# Miscellaneous
misc = re.compile('(fix|found|prevent|protect|patch).*sec.*(bug|vulnerab|problem|defect|warning|issue|weak|attack|flaw|fault|error)|sec.* (bug|vulnerab|problem|defect|warning|issue|weak|attack|flaw|fault|error).*(fix|found|prevent|protect|patch)|vulnerab|attack|cve-|nvd-|cwe-')

# Buffer overflow
bufover = re.compile('buff.* overflow')

# Full path disclosure
fpd = re.compile('(full)? path discl')

# Null pointers
nullp = re.compile('null pointers')

# Encryption issues
encrypt = re.compile('encrypt.* (bug|vulnerab|problem|defect|warning|issue|weak|attack|flaw|fault|error)')

parser = argparse.ArgumentParser()
parser.add_argument('repo', help='Path to the Git repository')
parser.add_argument('-b', '--branch', help="Select the branch (Default: the active branch of the repository)")
args = parser.parse_args()

repo = git.Repo(args.repo)
branch = repo.active_branch if args.branch is None else 'master'

test_commits = list(repo.iter_commits(args.branch))
for commit in test_commits:
    test = misc.search(commit.message)

    if test is not None:
        print(commit.message)

