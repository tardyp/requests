# -*- coding: utf-8 -*-

"""
requests.auth
~~~~~~~~~~~~~

This module contains the authentication handlers for Requests.
"""

import os
import re
import time
import threading
import hashlib

from base64 import b64encode

from .compat import urlparse, str
from .cookies import extract_cookies_to_jar
from .utils import parse_dict_header, to_native_string

CONTENT_TYPE_FORM_URLENCODED = 'application/x-www-form-urlencoded'
CONTENT_TYPE_MULTI_PART = 'multipart/form-data'


def _basic_auth_str(username, password):
    """Returns a Basic Auth string."""

    authstr = 'Basic ' + to_native_string(
        b64encode(('%s:%s' % (username, password)).encode('latin1')).strip()
    )

    return authstr


class AuthBase(object):
    """Base class that all auth implementations derive from"""

    def __call__(self, r):
        raise NotImplementedError('Auth hooks must be callable.')


class HTTPBasicAuth(AuthBase):
    """Attaches HTTP Basic Authentication to the given Request object."""
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __call__(self, r):
        r.headers['Authorization'] = _basic_auth_str(self.username, self.password)
        return r


class HTTPProxyAuth(HTTPBasicAuth):
    """Attaches HTTP Proxy Authentication to a given Request object."""
    def __call__(self, r):
        r.headers['Proxy-Authorization'] = _basic_auth_str(self.username, self.password)
        return r


class HTTPDigestAuth(AuthBase):

    """Attaches HTTP Digest Authentication to the given Request object."""

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.thd = threading.local()

    def initForThread(self):
        if not hasattr(self.thd, "init"):
            self.thd.init = True
            self.thd.last_nonce = ''
            self.thd.nonce_count = 0
            self.thd.chal = {}
            self.thd.pos = None
            self.thd.num_401_calls = 0

    def build_digest_header(self, method, url):

        realm = self.thd.chal['realm']
        nonce = self.thd.chal['nonce']
        qop = self.thd.chal.get('qop')
        algorithm = self.thd.chal.get('algorithm')
        opaque = self.thd.chal.get('opaque')

        if algorithm is None:
            _algorithm = 'MD5'
        else:
            _algorithm = algorithm.upper()
        # lambdas assume digest modules are imported at the top level
        if _algorithm == 'MD5' or _algorithm == 'MD5-SESS':
            def md5_utf8(x):
                if isinstance(x, str):
                    x = x.encode('utf-8')
                return hashlib.md5(x).hexdigest()
            hash_utf8 = md5_utf8
        elif _algorithm == 'SHA':
            def sha_utf8(x):
                if isinstance(x, str):
                    x = x.encode('utf-8')
                return hashlib.sha1(x).hexdigest()
            hash_utf8 = sha_utf8

        KD = lambda s, d: hash_utf8("%s:%s" % (s, d))

        if hash_utf8 is None:
            return None

        # XXX not implemented yet
        entdig = None
        p_parsed = urlparse(url)
        path = p_parsed.path
        if p_parsed.query:
            path += '?' + p_parsed.query

        A1 = '%s:%s:%s' % (self.username, realm, self.password)
        A2 = '%s:%s' % (method, path)

        HA1 = hash_utf8(A1)
        HA2 = hash_utf8(A2)

        if nonce == self.thd.last_nonce:
            self.thd.nonce_count += 1
        else:
            self.thd.nonce_count = 1
        ncvalue = '%08x' % self.thd.nonce_count
        s = str(self.thd.nonce_count).encode('utf-8')
        s += nonce.encode('utf-8')
        s += time.ctime().encode('utf-8')
        s += os.urandom(8)

        cnonce = (hashlib.sha1(s).hexdigest()[:16])
        if _algorithm == 'MD5-SESS':
            HA1 = hash_utf8('%s:%s:%s' % (HA1, nonce, cnonce))

        if qop is None:
            respdig = KD(HA1, "%s:%s" % (nonce, HA2))
        elif qop == 'auth' or 'auth' in qop.split(','):
            noncebit = "%s:%s:%s:%s:%s" % (
                nonce, ncvalue, cnonce, 'auth', HA2
            )
            respdig = KD(HA1, noncebit)
        else:
            # XXX handle auth-int.
            return None

        self.thd.last_nonce = nonce

        # XXX should the partial digests be encoded too?
        base = 'username="%s", realm="%s", nonce="%s", uri="%s", ' \
               'response="%s"' % (self.username, realm, nonce, path, respdig)
        if opaque:
            base += ', opaque="%s"' % opaque
        if algorithm:
            base += ', algorithm="%s"' % algorithm
        if entdig:
            base += ', digest="%s"' % entdig
        if qop:
            base += ', qop="auth", nc=%s, cnonce="%s"' % (ncvalue, cnonce)

        return 'Digest %s' % (base)

    def handle_redirect(self, r, **kwargs):
        """Reset num_401_calls counter on redirects."""
        if r.is_redirect:
            self.thd.num_401_calls = 1

    def handle_401(self, r, **kwargs):
        """Takes the given response and tries digest-auth, if needed."""

        if self.thd.pos is not None:
            # Rewind the file position indicator of the body to where
            # it was to resend the request.
            r.request.body.seek(self.thd.pos)
        num_401_calls = self.thd.num_401_calls
        s_auth = r.headers.get('www-authenticate', '')

        if 'digest' in s_auth.lower() and num_401_calls < 2:

            self.thd.num_401_calls += 1
            pat = re.compile(r'digest ', flags=re.IGNORECASE)
            self.thd.chal = parse_dict_header(pat.sub('', s_auth, count=1))

            # Consume content and release the original connection
            # to allow our new request to reuse the same one.
            r.content
            r.raw.release_conn()
            prep = r.request.copy()
            extract_cookies_to_jar(prep._cookies, r.request, r.raw)
            prep.prepare_cookies(prep._cookies)

            prep.headers['Authorization'] = self.build_digest_header(
                prep.method, prep.url)
            _r = r.connection.send(prep, **kwargs)
            _r.history.append(r)
            _r.request = prep

            return _r

        self.thd.num_401_calls = 1
        return r

    def __call__(self, r):
        self.initForThread()
        # If we have a saved nonce, skip the 401
        if self.thd.last_nonce:
            r.headers['Authorization'] = self.build_digest_header(r.method, r.url)
        try:
            self.thd.pos = r.body.tell()
        except AttributeError:
            # In the case of HTTPDigestAuth being reused and the body of
            # the previous request was a file-like object, pos has the
            # file position of the previous body. Ensure it's set to
            # None.
            self.thd.pos = None
        r.register_hook('response', self.handle_401)
        r.register_hook('response', self.handle_redirect)
        self.thd.num_401_calls = 1

        return r
