"""
Java Programming Language
Ruleset adapted from https://github.com/wireghoul/graudit/tree/master/signatures
"""

from .language import Language
import re

java_ruleset = {
    # Java Specific Security Related Exceptions
    'AccessControlException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'BindException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'ConcurrentModificationException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'DigestException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'FileNotFoundException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'GeneralSecurityException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'InsufficientResourcesException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'InvalidAlgorithmParameterException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'InvalidKeyException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'InvalidParameterException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'JarException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'KeyException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'KeyManagementException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'KeyStoreException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'NoSuchAlgorithmException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'NoSuchProviderException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'NotOwnerException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'NullPointerException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'OutOfMemoryError': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'PriviledgedActionException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'ProviderException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'SignatureException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'SQLException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'StackOverflowError': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'UnrecoverableEntryException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'UnrecoverableKeyException': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'AccessController': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    'addHeader': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'CallableStatement': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'Cipher': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    'createRequest': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'doPrivileged': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    'exec': {
        'severity': 'HIGH',
        'confidence': 'MEDIUM'
    },
    'executeQuery': {
        'severity': 'HIGH',
        'confidence': 'MEDIUM'
    },
    'executeUpdate': {
        'severity': 'HIGH',
        'confidence': 'MEDIUM'
    },
    'getParameter': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'getProperty': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    'getQueryString': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'getSession': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'HTTPCookie': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    'HttpServletRequest': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'HttpServletResponse': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'HttpsURLConnection': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    'invalidate': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    'IS_SUPPORTING_EXTERNAL_ENTITIES': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'KeyManagerFactory': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    'PreparedStatement': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    'random': {
        'severity': 'MEDIUM',
        'confidence': 'MEDIUM'
    },
    'SecureRandom': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    'SecurityException': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    'SecurityManager': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    'sendRedirect': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'setAllowFileAccess': {
        'severity': 'HIGH',
        'confidence': 'LOW'
    },
    'setHeader': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'setJavaScriptEnabled': {
        'severity': 'HIGH',
        'confidence': 'LOW'
    },
    'setPluginState': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    'setStatus': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'SSLContext': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    'SSLSocketFactory': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    'Statement': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'SUPPORT_DTD': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'suppressAccessChecks': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'TrustManager': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    'XMLReader': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    'request.getQueryString': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'exec\s *\(.* \)': {
        'severity': 'HIGH',
        'confidence': 'LOW'
    },
    'Runtime\.': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    'getRuntime\s*\(.*\)(\.|\s*;)': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    'getRequest': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    '[Rr]equest.getParameter': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'getProperty\s*\(': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    'import java.security.acl.acl': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    'response.sendRedirect\s*\(.*(Request|request).*\)': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    'print[Ss]tack[Tt]race': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    'out\.print(ln)?.*[Rr]equest\.': {
        'severity': 'HIGH',
        'confidence': 'LOW'
    },
    # Database rules
    'jdbc:.*': {
        'severity': 'LOW',
        'confidence': 'LOW'
    },
    'createStatement\s*\(.*\)': {
        'severity': 'HIGH',
        'confidence': 'LOW'
    },
    'executeQuery\s*\(.*\)': {
        'severity': 'HIGH',
        'confidence': 'LOW'
    },
    # Network
    'Socket\s*\(': {
        'severity': 'MEDIUM',
        'confidence': 'LOW'
    },
    # Java Crypto Insecure List
    'ISO10126Padding': {
        'severity': 'HIGH',
        'confidence': 'MEDIUM'
    },
    'Cipher.getInstance("AES")': {
        'severity': 'HIGH',
        'confidence': 'MEDIUM'
    },
    'getInstance("DES")': {
        'severity': 'HIGH',
        'confidence': 'MEDIUM'
    },
    'MD2': {
        'severity': 'HIGH',
        'confidence': 'MEDIUM'
    },
    'MD4': {
        'severity': 'HIGH',
        'confidence': 'MEDIUM'
    },
    'MD5': {
        'severity': 'HIGH',
        'confidence': 'MEDIUM'
    },
    'SHA1': {
        'severity': 'HIGH',
        'confidence': 'MEDIUM'
    },
    'ECB': {
        'severity': 'HIGH',
        'confidence': 'MEDIUM'
    },
    'AES/ECB/NoPadding': {
        'severity': 'HIGH',
        'confidence': 'MEDIUM'
    },
    'AES/CBC/PKCS5Padding': {
        'severity': 'HIGH',
        'confidence': 'MEDIUM'
    },
    'getInstance("SSL")': {
        'severity': 'HIGH',
        'confidence': 'MEDIUM'
    },
    'DefaultHttpClient()': {
        'severity': 'HIGH',
        'confidence': 'MEDIUM'
    },
}

java_extensions = ['.java']
java_non_context = re.compile(
    r'(^(/\*|\*|\*/|//)|'
    r'^[{}()\'\";]|(\s*|(}\s*)?(do|try|else|finally)\s*{?|'
    r'@(Override|Deprecated|SuppressWarnings|Inherited)|'
    r'(return|break|continue)\s*;)$)',
    re.S)

Language(java_ruleset, java_extensions, java_non_context)
