from .language import Language
import re

# "c_ruleset": the rules for identifying "hits" in C (potential warnings).
# It's a dictionary, where the key is the function name causing the hit,
# and the value is a tuple with the following format:
#  (warning, suggestion, category)
# See the definition for class "Hit".
# The key can have multiple values separated with "|".

# For more information on Microsoft banned functions, see:
# http://msdn.microsoft.com/en-us/library/bb288454.aspx

c_ruleset = {
    "strcpy":
        ("Does not check for buffer overflows when copying to destination [MS-banned] (CWE-120)",
         "Consider using snprintf, strcpy_s, or strlcpy (warning: strncpy easily misused)",
         "buffer"),
    "strcpyA|strcpyW|StrCpy|StrCpyA|lstrcpyA|lstrcpyW|_tccpy|_mbccpy|_ftcscpy|_mbsncpy|StrCpyN|StrCpyNA|StrCpyNW|StrNCpy|strcpynA|StrNCpyA|StrNCpyW|lstrcpynA|lstrcpynW":
    # We need more info on these functions; I got their names from the
    # Microsoft "banned" list.  For now, just use "normal" to process them
    # instead of "c_buffer".
        ("Does not check for buffer overflows when copying to destination [MS-banned] (CWE-120)",
         "Consider using snprintf, strcpy_s, or strlcpy (warning: strncpy easily misused)",
         "buffer"),
    "lstrcpy|wcscpy|_tcscpy|_mbscpy":
        ("Does not check for buffer overflows when copying to destination [MS-banned] (CWE-120)",
         "Consider using a function version that stops copying at the end of the buffer",
         "buffer"),
    "memcpy|CopyMemory|bcopy":
        ("Does not check for buffer overflows when copying to destination (CWE-120)",
         "Make sure destination can always hold the source data",
         "buffer"),
    "strcat":
        ("Does not check for buffer overflows when concatenating to destination [MS-banned] (CWE-120)",
         "Consider using strcat_s, strncat, strlcat, or snprintf (warning: strncat is easily misused)",
         "buffer"),
    "lstrcat|wcscat|_tcscat|_mbscat":
        ("Does not check for buffer overflows when concatenating to destination [MS-banned] (CWE-120)",
         "",
         "buffer"),
    # TODO: Do more analysis.  Added because they're in MS banned list.
    "StrCat|StrCatA|StrcatW|lstrcatA|lstrcatW|strCatBuff|StrCatBuffA|StrCatBuffW|StrCatChainW|_tccat|_mbccat|_ftcscat|StrCatN|StrCatNA|StrCatNW|StrNCat|StrNCatA|StrNCatW|lstrncat|lstrcatnA|lstrcatnW":
        ("Does not check for buffer overflows when concatenating to destination [MS-banned] (CWE-120)",
         "",
         "buffer"),
    "strncpy":
        ("Easily used incorrectly; doesn't always \\0-terminate or check for invalid pointers [MS-banned] (CWE-120)",
         "",
         "buffer"),
    "lstrcpyn|wcsncpy|_tcsncpy|_mbsnbcpy":
        ("Easily used incorrectly; doesn't always \\0-terminate or check for invalid pointers [MS-banned] (CWE-120)",
         "",
         "buffer"),
    "strncat":
        ("Easily used incorrectly (e.g., incorrectly computing the correct maximum size to add) [MS-banned] (CWE-120)",
         "Consider strcat_s, strlcat, snprintf, or automatically resizing strings",
         "buffer"),
    "lstrcatn|wcsncat|_tcsncat|_mbsnbcat":
        ("Easily used incorrectly (e.g., incorrectly computing the correct maximum size to add) [MS-banned] (CWE-120)",
         "Consider strcat_s, strlcat, or automatically resizing strings",
         "buffer"),
    "strccpy|strcadd":
        ("Subject to buffer overflow if buffer is not as big as claimed (CWE-120)",
         "Ensure that destination buffer is sufficiently large",
         "buffer"),
    "char|TCHAR|wchar_t":  # This isn't really a function call, but it works.
        ("Statically-sized arrays can be improperly restricted, " +
         "leading to potential overflows or other issues (CWE-119!/CWE-120)",
         "Perform bounds checking, use functions that limit length, " +
         "or ensure that the size is larger than the maximum possible length",
         "buffer"),

    "gets|_getts":
        ("Does not check for buffer overflows (CWE-120, CWE-20)",
         "Use fgets() instead", "buffer"),

    # The "sprintf" hook will raise "format" issues instead if appropriate:
    "sprintf|vsprintf|swprintf|vswprintf|_stprintf|_vstprintf":
        ("Does not check for buffer overflows (CWE-120)",
         "Use sprintf_s, snprintf, or vsnprintf",
         "buffer"),

    "printf|vprintf|vwprintf|vfwprintf|_vtprintf|wprintf":
        ("If format strings can be influenced by an attacker, they can be exploited (CWE-134)",
         "Use a constant for the format specification",
         "format"),

    "fprintf|vfprintf|_ftprintf|_vftprintf|fwprintf|fvwprintf":
        ("If format strings can be influenced by an attacker, they can be exploited (CWE-134)",
         "Use a constant for the format specification",
         "format"),

    # The "syslog" hook will raise "format" issues.
    "syslog":
        ("If syslog's format strings can be influenced by an attacker, they can be exploited (CWE-134)",
         "Use a constant format string for syslog",
         "format"),

    "snprintf|vsnprintf|_snprintf|_sntprintf|_vsntprintf":
        ("If format strings can be influenced by an attacker, they can be " +
         "exploited, and note that sprintf variations do not always \\0-terminate (CWE-134)",
         "Use a constant for the format specification",
         "format"),

    "scanf|vscanf|wscanf|_tscanf|vwscanf":
        ("The scanf() family's %s operation, without a limit specification, permits buffer overflows (CWE-120, CWE-20)",
         "Specify a limit to %s, or use a different input function",
         "buffer"),

    "fscanf|sscanf|vsscanf|vfscanf|_ftscanf|fwscanf|vfwscanf|vswscanf":
        ("The scanf() family's %s operation, without a limit specification, permits buffer overflows (CWE-120, CWE-20)",
         "Specify a limit to %s, or use a different input function",
         "buffer"),

    "strlen|wcslen|_tcslen|_mbslen":
        ("Does not handle strings that are not \\0-terminated; " +
         "if given one it may perform an over-read (it could cause a crash if unprotected) (CWE-126)",
         "",
         "buffer"),

    "MultiByteToWideChar":  # Windows
        ("Requires maximum length in CHARACTERS, not bytes (CWE-120)",
         "",
         "buffer"),

    "streadd|strecpy":
        ("This function does not protect against buffer overflows (CWE-120)",
         "Ensure the destination has 4 times the size of the source, to leave room for expansion",
         "buffer"),

    "strtrns":
        ("This function does not protect against buffer overflows (CWE-120)",
         "Ensure that destination is at least as long as the source",
         "buffer"),

    "realpath":
        ("This function does not protect against buffer overflows, " +
         "and some implementations can overflow internally (CWE-120/CWE-785!)",
         "Ensure that the destination buffer is at least of size MAXPATHLEN, and" +
         "to protect against implementation problems, the input argument " +
         "should also be checked to ensure it is no larger than MAXPATHLEN",
         "buffer"),

    "getopt|getopt_long":
        ("Some older implementations do not protect against internal buffer overflows (CWE-120, CWE-20)",
         "Check implementation on installation, or limit the size of all string inputs",
         "buffer"),

    "getwd":
        ("This does not protect against buffer overflows "
         "by itself, so use with caution (CWE-120, CWE-20)",
         "Use getcwd instead",
         "buffer"),

    # fread not included here; in practice I think it's rare to mistake it.
    "getchar|fgetc|getc|read|_gettc":
        ("Check buffer boundaries if used in a loop including recursive loops (CWE-120, CWE-20)",
         "",
         "buffer"),

    "access":  # ???: TODO: analyze TOCTOU more carefully.
        ("This usually indicates a security flaw.  If an attacker can change anything along the path between the " +
         "call to access() and the file's actual use (e.g., by moving files), "
         "the attacker can exploit the race condition (CWE-362/CWE-367!)",
         "Set up the correct permissions (e.g., using setuid()) and " +
         "try to open the file directly",
         "race"),
    "chown":
        ("This accepts filename arguments; if an attacker can move those files, a race condition results. (CWE-362)",
         "Use fchown( ) instead",
         "race"),
    "chgrp":
        ("This accepts filename arguments; if an attacker can move those files, a race condition results. (CWE-362)",
         "Use fchgrp( ) instead",
         "race"),
    "chmod":
        ("This accepts filename arguments; if an attacker can move those files, a race condition results. (CWE-362)",
         "Use fchmod( ) instead",
         "race"),
    "vfork":
        ("On some old systems, vfork() permits race conditions, and it's very difficult to use correctly (CWE-362)",
         "Use fork() instead",
         "race"),
    "readlink":
        ("This accepts filename arguments; if an attacker can move those files or change the link content, " +
         "a race condition results. Also, it does not terminate with ASCII NUL. (CWE-362, CWE-20)",
         # This is often just a bad idea, and it's hard to suggest a
         # simple alternative:
         "Reconsider approach",
         "race"),

    "tmpfile":
        ("Function tmpfile() has a security flaw on some systems (e.g., older System V systems) (CWE-377)",
         "",
         "tmpfile"),
    "tmpnam|tempnam":
        ("Temporary file race condition (CWE-377)",
         "",
         "tmpfile"),

    # TODO: Detect GNOME approach to mktemp and ignore it.
    "mktemp":
        ("Temporary file race condition (CWE-377)",
         "",
         "tmpfile"),

    "mkstemp":
        ("Potential for temporary file vulnerability in some circumstances.  Some older Unix-like systems create temp files with permission to write by all by default, so be sure to set the umask to override this. Also, some older Unix systems might fail to use O_EXCL when opening the file, so make sure that O_EXCL is used by the library (CWE-377)",
         "",
         "tmpfile"),

    "fopen|open":
        ("Check when opening files - can an attacker redirect it (via symlinks), force the opening of special file type (e.g., device files), move things around to create a race condition, control its ancestors, or change its contents? (CWE-362)",
         "",
         "misc"),

    "umask":
        ("Ensure that umask is given most restrictive possible setting (e.g., 066 or 077) (CWE-732)",
         "",
         "access"),

    # Windows.  TODO: Detect correct usage approaches and ignore it.
    "GetTempFileName":
        ("Temporary file race condition in certain cases (e.g. if run as SYSTEM in many versions of Windows) (CWE-377)",
         "",
         "tmpfile"),

    # TODO: Need to detect varying levels of danger.
    "execl|execlp|execle|execv|execvp|system|popen|WinExec|ShellExecute":
        ("This causes a new program to execute and is difficult to use safely (CWE-78)",
         "Try using a library call that implements the same functionality if available",
         "shell"),

    # TODO: Be more specific.  The biggest problem involves "first" param NULL,
    # second param with embedded space. Windows.
    "CreateProcessAsUser|CreateProcessWithLogon":
        ("This causes a new process to execute and is difficult to use safely (CWE-78)",
         "Especially watch out for embedded spaces",
         "shell"),

    # TODO: Be more specific.  The biggest problem involves "first" param NULL,
    # second param with embedded space. Windows.
    "CreateProcess":
        ("This causes a new process to execute and is difficult to use safely (CWE-78)",
         "Specify the application path in the first argument, NOT as part of the second, " +
         "or embedded spaces could allow an attacker to force a different program to run",
         "shell"),

    "atoi|atol|_wtoi|_wtoi64":
        ("Unless checked, the resulting number can exceed the expected range (CWE-190)",
         "If source untrusted, check both minimum and maximum, even if the" +
         " input had no minus sign (large numbers can roll over into negative" +
         " number; consider saving to an unsigned value if that is intended)",
         "integer"),

    # Random values.  Don't trigger on "initstate", it's too common a term.
    "drand48|erand48|jrand48|lcong48|lrand48|mrand48|nrand48|random|seed48|setstate|srand|strfry|srandom|g_rand_boolean|g_rand_int|g_rand_int_range|g_rand_double|g_rand_double_range|g_random_boolean|g_random_int|g_random_int_range|g_random_double|g_random_double_range":
        ("This function is not sufficiently random for security-related functions such as key and nonce creation (CWE-327)",
         "Use a more secure technique for acquiring random values",
         "random"),

    "crypt|crypt_r":
        ("The crypt functions use a poor one-way hashing algorithm; " +
         "since they only accept passwords of 8 characters or fewer " +
         "and only a two-byte salt, they are excessively vulnerable to " +
         "dictionary attacks given today's faster computing equipment (CWE-327)",
         "Use a different algorithm, such as SHA-256, with a larger, non-repeating salt",
         "crypto"),

    # OpenSSL EVP calls to use DES.
    "EVP_des_ecb|EVP_des_cbc|EVP_des_cfb|EVP_des_ofb|EVP_desx_cbc":
        ("DES only supports a 56-bit keysize, which is too small given today's computers (CWE-327)",
         "Use a different patent-free encryption algorithm with a larger keysize, such as 3DES or AES",
         "crypto"),

    # Other OpenSSL EVP calls to use small keys.
    "EVP_rc4_40|EVP_rc2_40_cbc|EVP_rc2_64_cbc":
        ("These keysizes are too small given today's computers (CWE-327)",
         "Use a different patent-free encryption algorithm with a larger keysize, such as 3DES or AES",
         "crypto"),

    "chroot":
        ("chroot can be very helpful, but is hard to use correctly (CWE-250, CWE-22)",
         "Make sure the program immediately chdir(\"/\"), closes file descriptors," +
         " and drops root privileges, and that all necessary files (and no more!) are in the new root",
         "misc"),

    "getenv|curl_getenv":
        ("Environment variables are untrustable input if they can be" +
         " set by an attacker.  They can have any content and" +
         " length, and the same variable can be set more than once (CWE-807, CWE-20)",
         "Check environment variables carefully before using them",
         "buffer"),

    "g_get_home_dir":
        ("This function is synonymous with 'getenv(\"HOME\")';" +
         "it returns untrustable input if the environment can be" +
         "set by an attacker.  It can have any content and length, " +
         "and the same variable can be set more than once (CWE-807, CWE-20)",
         "Check environment variables carefully before using them",
         "buffer"),

    "g_get_tmp_dir":
        ("This function is synonymous with 'getenv(\"TMP\")';" +
         "it returns untrustable input if the environment can be" +
         "set by an attacker.  It can have any content and length, " +
         "and the same variable can be set more than once (CWE-807, CWE-20)",
         "Check environment variables carefully before using them",
         "buffer"),

    # These are Windows-unique:

    # TODO: Should have lower risk if the program checks return value.
    "RpcImpersonateClient|ImpersonateLoggedOnUser|CoImpersonateClient|" +
    "ImpersonateNamedPipeClient|ImpersonateDdeClientWindow|ImpersonateSecurityContext|" +
    "SetThreadToken":
        ("If this call fails, the program could fail to drop heightened privileges (CWE-250)",
         "Make sure the return value is checked, and do not continue if a failure is reported",
         "access"),

    "InitializeCriticalSection":
        ("Exceptions can be thrown in low-memory situations",
         "Use InitializeCriticalSectionAndSpinCount instead",
         "misc"),

    "EnterCriticalSection":
        ("On some versions of Windows, exceptions can be thrown in low-memory situations",
         "Use InitializeCriticalSectionAndSpinCount instead",
         "misc"),

    "LoadLibrary|LoadLibraryEx":
        ("Ensure that the full path to the library is specified, or current directory may be used (CWE-829, CWE-20)",
         "Use registry entry or GetWindowsDirectory to find library path, if you aren't already",
         "misc"),

    "SetSecurityDescriptorDacl":
        ("Never create NULL ACLs; an attacker can set it to Everyone (Deny All Access), " +
         "which would even forbid administrator access (CWE-732)",
         "",
         "misc"),

    "AddAccessAllowedAce":
        ("This doesn't set the inheritance bits in the access control entry (ACE) header (CWE-732)",
         "Make sure that you set inheritance by hand if you wish it to inherit",
         "misc"),

    "getlogin":
        ("It's often easy to fool getlogin.  Sometimes it does not work at all, because some program messed up the utmp file.  Often, it gives only the first 8 characters of the login name. The user currently logged in on the controlling tty of our program need not be the user who started it.  Avoid getlogin() for security-related purposes (CWE-807)",
         "Use getpwuid(geteuid()) and extract the desired information instead",
         "misc"),

    "cuserid":
        ("Exactly what cuserid() does is poorly defined (e.g., some systems use the effective uid, like Linux, while others like System V use the real uid). Thus, you can't trust what it does. It's certainly not portable (The cuserid function was included in the 1988 version of POSIX, but removed from the 1990 version).  Also, if passed a non-null parameter, there's a risk of a buffer overflow if the passed-in buffer is not at least L_cuserid characters long (CWE-120)",
         "Use getpwuid(geteuid()) and extract the desired information instead",
         "misc"),

    "getpw":
        ("This function is dangerous; it may overflow the provided buffer. It extracts data from a 'protected' area, but most systems have many commands to let users modify the protected area, and it's not always clear what their limits are.  Best to avoid using this function altogether (CWE-676, CWE-120)",
         "Use getpwuid() instead",
         "buffer"),

    "getpass":
        ("This function is obsolete and not portable. It was in SUSv2 but removed by POSIX.2.  What it does exactly varies considerably between systems, particularly in where its prompt is displayed and where it gets its data (e.g., /dev/tty, stdin, stderr, etc.). In addition, some implementations overflow buffers. (CWE-676, CWE-120, CWE-20)",
         "Make the specific calls to do exactly what you want.  If you continue to use it, or write your own, be sure to zero the password as soon as possible to avoid leaving the cleartext password visible in the process' address space",
         "misc"),

    "gsignal|ssignal":
        ("These functions are considered obsolete on most systems, and very non-portable (Linux-based systems handle them radically different, basically if gsignal/ssignal were the same as raise/signal respectively, while System V considers them a separate set and obsolete) (CWE-676)",
         "Switch to raise/signal, or some other signalling approach",
         "obsolete"),

    "memalign":
        ("On some systems (though not Linux-based systems) an attempt to free() results from memalign() may fail. This may, on a few systems, be exploitable.  Also note that memalign() may not check that the boundary parameter is correct (CWE-676)",
         "Use posix_memalign instead (defined in POSIX's 1003.1d).  Don't switch to valloc(); it is marked as obsolete in BSD 4.3, as legacy in SUSv2, and is no longer defined in SUSv3.  In some cases, malloc()'s alignment may be sufficient",
         "free"),

    "ulimit":
        ("This C routine is considered obsolete (as opposed to the shell command by the same name, which is NOT obsolete) (CWE-676)",
         "Use getrlimit(2), setrlimit(2), and sysconf(3) instead",
         "obsolete"),

    "usleep":
        ("This C routine is considered obsolete (as opposed to the shell command by the same name).   The interaction of this function with SIGALRM and other timer functions such as sleep(), alarm(), setitimer(), and nanosleep() is unspecified (CWE-676)",
         "Use nanosleep(2) or setitimer(2) instead",
         "obsolete"),

    # Input functions, useful for -I
    "recv|recvfrom|recvmsg|fread|readv":
        ("Function accepts input from outside program (CWE-20)",
         "Make sure input data is filtered, especially if an attacker could manipulate it",
         "input"),

    # Unsafe STL functions that don't check the second iterator
    "equal|mismatch|is_permutation":
        ("Function does not check the second iterator for over-read conditions (CWE-126)",
         "This function is often discouraged by most C++ coding standards in favor of its safer alternatives provided since C++14. Consider using a form of this function that checks the second iterator before potentially overflowing it",
         "buffer"),
}

c_extensions = ['.c', '.cc', '.cpp', '.cxx', '.c++', '.mm', '.h', '.hh', '.hpp', '.hxx', '.h++']

c_comments = re.compile(r'^(/\*|\*|\*/|//)', re.S)

c_language = Language(c_ruleset, c_extensions, c_comments)