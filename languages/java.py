"""
Java Programming Language
Ruleset adapted from https://github.com/wireghoul/graudit/tree/master/signatures
"""

from .language import Language
import re

java_ruleset = {
    'Java Specific Security Related Exceptions': [
        'AccessControlException',
        'BindException',
        'ConcurrentModificationException',
        'DigestException',
        'FileNotFoundException',
        'GeneralSecurityException',
        'InsufficientResourcesException',
        'InvalidAlgorithmParameterException',
        'InvalidKeyException',
        'InvalidParameterException',
        'JarException',
        'KeyException',
        'KeyManagementException',
        'KeyStoreException',
        'NoSuchAlgorithmException',
        'NoSuchProviderException',
        'NotOwnerException',
        'NullPointerException',
        'OutOfMemoryError',
        'PriviledgedActionException',
        'ProviderException',
        'SignatureException',
        'SQLException',
        'StackOverflowError',
        'UnrecoverableEntryException',
        'UnrecoverableKeyException',
        'AccessController',
        'addHeader',
        'CallableStatement',
        'Cipher',
        'createRequest',
        'doPrivileged',
        'exec',
        'executeQuery',
        'executeUpdate',
        'getParameter',
        'getProperty',
        'getQueryString',
        'getSession',
        'HTTPCookie',
        'HttpServletRequest',
        'HttpServletResponse',
        'HttpsURLConnection',
        'invalidate',
        'IS_SUPPORTING_EXTERNAL_ENTITIES',
        'KeyManagerFactory',
        'PreparedStatement',
        'random',
        'SecureRandom',
        'SecurityException',
        'SecurityManager',
        'sendRedirect',
        'setAllowFileAccess',
        'setHeader',
        'setJavaScriptEnabled',
        'setPluginState',
        'setStatus',
        'SSLContext',
        'SSLSocketFactory',
        'Statement',
        'SUPPORT_DTD',
        'suppressAccessChecks',
        'TrustManager',
        'XMLReader',
        'request.getQueryString',
        'exec\s *\(.* \)',
        'Runtime\.',
        'getRuntime\s*\(.*\)(\.|\s*;)',
        'getRequest',
        '[Rr]equest.getParameter',
        'getProperty\s*\(',
        'java.security.acl.acl',
        'response.sendRedirect\s*\(.*(Request|request).*\)',
        'print[Ss]tack[Tt]race',
        'out\.print(ln)?.*[Rr]equest\.',
    ],
    'Database rules': [
        'jdbc:.*',
        'createStatement\s*\(.*\)',
        'executeQuery\s*\(.*\)'
    ],
    'Network': ['Socket\s*\(']
}

java_extensions = ['.java']
java_comments = re.compile(r'^(/\*|\*|\*/|//)', re.S)

java_language = Language(java_ruleset, java_extensions, java_comments)
