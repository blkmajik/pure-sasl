import base64
import hashlib
import hmac
import random
import struct
import sys
import os

from puresasl import SASLError, SASLProtocolException, QOP

try:
    import kerberos
    _have_kerberos = True
except ImportError:
    _have_kerberos = False

PY3 = sys.version_info[0] == 3
if PY3:
    def _b(s):
        return s.encode("utf-8")
else:
    def _b(s):
        return s


class Mechanism(object):
    """
    The base class for all mechanisms.
    """

    name = None
    """ The IANA registered name for the mechanism. """

    score = 0
    """ A relative security score where higher scores correspond
    to more secure mechanisms. """

    allows_anonymous = True
    """ True if the mechanism allows for anonymous logins. """

    uses_plaintext = True
    """ True if the mechanism transmits sensitive information in plaintext. """

    active_safe = False
    """ True if the mechanism is safe against active attacks. """

    dictionary_safe = False
    """ True if the mechanism is safe against passive dictionary attacks. """


    def __init__(self, sasl, **props):
        self.qops = [QOP.AUTH]      # QOPs supported by the Mechanism
        self.qop = QOP.AUTH         # Selected QOP
        self.complete = False       # Set to True when SASL negotiation has
                                    # completed succesfully.
        self.sasl = sasl

        # Set properties that are passed in
        for key, value in props.iteritems():
            super(Mechanism, self).__setattr__(key, value)

    def __setattr__(self, key, value):
        super(Mechanism, self).__setattr__(key, value)

    def process(self, challenge=None):
        """
        Process a challenge request and return the response.

        :param challenge: A challenge issued by the server that
                          must be answered for authentication.
        """
        raise NotImplementedError()

    def wrap(self, outgoing):
        """
        Wrap an outgoing message intended for the SASL server. Depending
        on the negotiated quality of protection, this may result in the
        message being signed, encrypted, or left unaltered.
        """
        raise NotImplementedError()

    def unwrap(self, incoming):
        """
        Unwrap a message from the SASL server. Depending on the negotiated
        quality of protection, this may check a signature, decrypt the message,
        or leave the message unaltered.
        """
        raise NotImplementedError()

    def dispose(self):
        """
        Clear all sensitive data, such as passwords.
        """
        pass

    def _fetch_properties(self, *properties):
        """
        Ensure this mechanism has the needed properties. If they haven't
        been set yet, the registered callback function will be called for
        each property to retrieve a value.
        """
        needed = [p for p in properties if getattr(self, p, None) is None]
        if needed and not self.sasl.callback:
            raise SASLError('The following properties are required, but a '
                            'callback has not been set: %s' % ', '.join(needed))

        for prop in needed:
            setattr(self, prop, self.sasl.callback(prop))

    def _pick_qop(self, server_qop_set):
        """
        Choose a quality of protection based on the user's requirements,
        what the server supports, and what the mechanism supports.
        """
        user_qops = set(_b(qop) if isinstance(qop, str) else qop for qop in self.sasl.qops)  # normalize user-defined config
        supported_qops = set(self.qops)
        available_qops = user_qops & supported_qops & server_qop_set
        if not available_qops:
            user = b', '.join(user_qops).decode('ascii')
            supported = b', '.join(supported_qops).decode('ascii')
            offered = b', '.join(server_qop_set).decode('ascii')
            raise SASLProtocolException("Your requested quality of "
                                        "protection is one of (%s), the server is "
                                        "offering (%s), and %s supports (%s)" % (user, offered, self.name, supported))
        else:
            for qop in (QOP.AUTH_CONF, QOP.AUTH_INT, QOP.AUTH):
                if qop in available_qops:
                    self.qop = qop
                    break


class AnonymousMechanism(Mechanism):
    """
    An anonymous user login mechanism.
    """
    name = 'ANONYMOUS'
    score = 0
    uses_plaintext = False

    def __init__(self, sasl, **props):
        super(AnonymousMechanism, self).__init__(sasl, **props)

    def process(self, challenge=None):
        self.complete = True
        return b'Anonymous, None'


class PlainMechanism(Mechanism):
    """
    A plaintext user/password based mechanism.
    """
    name = 'PLAIN'
    score = 1
    allows_anonymous = False


    def __init__(self, sasl, username=None, password=None, identity='', **props):
        super(PlainMechanism, self).__init__(sasl, **props)

        self.identity = identity
        self.username = username
        self.password = password

    def wrap(self, outgoing):
        return outgoing

    def unwrap(self, incoming):
        return incoming

    def process(self, challenge=None):
        self._fetch_properties('username', 'password')
        self.complete = True
        auth_id = self.sasl.authorization_id or self.identity
        return b''.join((_b(auth_id), b'\x00', _b(self.username), b'\x00', _b(self.password)))

    def dispose(self):
        self.password = None


class CramMD5Mechanism(PlainMechanism):
    name = "CRAM-MD5"
    score = 20

    allows_anonymous = False
    uses_plaintext = False

    def __init__(self, sasl, username=None, password=None, **props):
        super(CramMD5Mechanism, self).__init__(sasl, **props)

        self.username = username
        self.password = password

    def process(self, challenge=None):
        if challenge is None:
            return None

        self._fetch_properties('username', 'password')
        mac = hmac.HMAC(key=_b(self.password), digestmod=hashlib.md5)
        mac.update(challenge)
        return b''.join((_b(self.username), b' ', _b(mac.hexdigest())))

    def dispose(self):
        self.password = None


# functions used in DigestMD5 which were originally defined in the now-removed util module

def bytes(text):
    """
    Convert Unicode text to UTF-8 encoded bytes.

    Since Python 2.6+ and Python 3+ have similar but incompatible
    signatures, this function unifies the two to keep code sane.

    :param text: Unicode text to convert to bytes
    :rtype: bytes (Python3), str (Python2.6+)
    """
    if sys.version_info < (3, 0):
        import __builtin__
        return __builtin__.bytes(text)
    else:
        import builtins
        if isinstance(text, builtins.bytes):
            # We already have bytes, so do nothing
            return text
        if isinstance(text, list):
            # Convert a list of integers to bytes
            return builtins.bytes(text)
        else:
            # Convert UTF-8 text to bytes
            return builtins.bytes(str(text), encoding='utf-8')


def quote(text):
    """
    Enclose in quotes and escape internal slashes and double quotes.

    :param text: A Unicode or byte string.
    """
    text = bytes(text)
    return b'"' + text.replace(b'\\', b'\\\\').replace(b'"', b'\\"') + b'"'


class DigestMD5Mechanism(Mechanism):
    name = "DIGEST-MD5"
    score = 30
    allows_anonymous = False
    uses_plaintext = False


    def __init__(self, sasl, username=None, password=None, **props):
        # Variables that can be overridden as properties
        self.nonce = "dummy"
        self.cnonce = "dummy"
        self.nc = 0
        self.charset = "utf-8"
        self.authzid = None
        super(DigestMD5Mechanism, self).__init__(sasl, **props)
        self.username = username
        self.password = password
        self.max_buffer = 65536

        self._rspauth_okay = False
        self._digest_uri = None
        self._a1 = None

    def dispose(self):
        self._rspauth_okay = None
        self._digest_uri = None
        self._a1 = None

        self.password = None
        self.realm = None
        self.nonce = None
        self.cnonce = None
        self.nc = 0

    def wrap(self, outgoing):
        return outgoing

    def unwrap(self, incoming):
        return incoming

    def response(self):
        required_props = ['username', 'password']
        self._fetch_properties(*required_props)

        if self.nc == 0:
            self.cnonce = bytes(base64.b64encode(os.urandom(30)))

        resp = {}
        resp['charset'] = self.charset
        resp['username'] = quote(bytes(self.username))
        if getattr(self, 'realm', None) is not None:
            resp['realm'] = quote(self.realm)
        resp['nonce'] = quote(self.nonce)
        self.nc += 1
        resp['nc'] = bytes('%08x' % self.nc)
        resp['cnonce'] = quote(self.cnonce)

        self._digest_uri = (
            bytes(self.sasl.service) + b'/' + bytes(self.realm))
        resp['digest-uri'] = quote(self._digest_uri)
        resp['maxbuf'] = bytes(str(self.max_buffer))

        a2 = b'AUTHENTICATE:' + self._digest_uri
        if self.qop != b'auth':
            a2 += b':00000000000000000000000000000000'
        resp['response'] = self.gen_hash(a2)

        resp['qop'] = self.qop
        if self.authzid:
            resp['authzid'] = quote(bytes(self.authzid))


        return b','.join([bytes(k) + b'=' + bytes(v) for k, v in resp.items()])

    @staticmethod
    def parse_challenge(challenge):
        ret = {}
        var = ''
        val = ''
        in_var = True
        in_quotes = False
        new = False
        escaped = False
        for c in challenge:
            if in_var:
                if c.isspace():
                    continue
                if c == '=':
                    in_var = False
                    new = True
                else:
                    var += c
            else:
                if new:
                    if c == '"':
                        in_quotes = True
                    else:
                        val += c
                    new = False
                elif in_quotes:
                    if escaped:
                        escaped = False
                        val += c
                    else:
                        if c == '\\':
                            escaped = True
                        elif c == '"':
                            in_quotes = False
                        else:
                            val += c
                else:
                    if c == ',':
                        if var:
                            ret[var] = bytes(val)
                        var = ''
                        val = ''
                        in_var = True
                    else:
                        val += c
        if var:
            ret[var] = val
        return ret

    def gen_hash(self, a2):
        user = bytes(self.username)
        password = bytes(self.password)
        realm = bytes(self.realm)

        a1p1 = hashlib.md5(user + b":" + realm + b":" + password).digest()
        if self.authzid:
            a1p2 = b':' + self.nonce + b':' + self.cnonce + b':' + self.authzid
        else:
            a1p2 = b':' + self.nonce + b':' + self.cnonce

        a1 = a1p1 + a1p2

        kdp1 = hashlib.md5(a1).hexdigest()
        kdp2 = self.nonce + \
                b':' + bytes('%08x' % self.nc) + \
                b':' + self.cnonce  + \
                b':' + self.qop + \
                b':' + hashlib.md5(a2).hexdigest()

        response = hashlib.md5(kdp1 + b':' + kdp2).hexdigest()
        return bytes(response)

    # untested
    def authenticate_server(self, cmp_hash):
        a2 = b':' + self._digest_uri
        if self.qop != b'auth':
            a2 += b':00000000000000000000000000000000'
        if self.gen_hash(a2) == cmp_hash:
            self.complete = True
        else:
            raise SASLError("Authentication failed")

    def process(self, challenge):
        challenge_dict = self.parse_challenge(challenge)
        if 'rspauth' in challenge_dict:
            self.authenticate_server(challenge_dict['rspauth'])
        if self.complete:
            return None


        if 'realm' not in challenge_dict:
            self._fetch_properties('realm')
            challenge_dict['realm'] = self.realm

        for key in ('nonce', 'realm'):
            if key in challenge_dict:
                setattr(self, key, challenge_dict[key])

        self.nc = 0
        if 'qop' in challenge_dict:
            server_offered_qops = [x.strip() for x in challenge_dict['qop'].split(b',')]
        else:
            server_offered_qops = ['auth']
        self._pick_qop(set(server_offered_qops))

        if 'maxbuf' in challenge_dict:
            self.max_buffer = min(
                self.sasl.max_buffer, int(challenge_dict['maxbuf']))
        return self.response()


class GSSAPIMechanism(Mechanism):
    name = 'GSSAPI'
    score = 100
    qops = QOP.all

    allows_anonymous = False
    uses_plaintext = False
    active_safe = True

    def __init__(self, sasl, principal=None, **props):
        super(GSSAPIMechanism, self).__init__(sasl, **props)
        self.user = None
        self._have_negotiated_details = False
        self.host = self.sasl.host
        self.service = self.sasl.service
        self.principal = principal
        self._fetch_properties('host', 'service')

        krb_service = '@'.join((self.service, self.host))
        try:
            _, self.context = kerberos.authGSSClientInit(service=krb_service,
                                                         principal=self.principal)
        except TypeError:
            if self.principal is not None:
                raise Exception("Error: kerberos library does not support principal.")
            _, self.context = kerberos.authGSSClientInit(service=krb_service)

    def process(self, challenge=None):
        if not self._have_negotiated_details:
            kerberos.authGSSClientStep(self.context, '')
            _negotiated_details = kerberos.authGSSClientResponse(self.context)
            self._have_negotiated_details = True
            return base64.b64decode(_negotiated_details)

        challenge = base64.b64encode(challenge).decode('ascii')  # kerberos methods expect strings, not bytes
        if self.user is None:
            ret = kerberos.authGSSClientStep(self.context, challenge)
            if ret == kerberos.AUTH_GSS_COMPLETE:
                self.user = kerberos.authGSSClientUserName(self.context)
                return b''
            else:
                response = kerberos.authGSSClientResponse(self.context)
                if response:
                    response = base64.b64decode(response)
                else:
                    response = b''
            return response

        kerberos.authGSSClientUnwrap(self.context, challenge)
        data = kerberos.authGSSClientResponse(self.context)
        plaintext_data = base64.b64decode(data)
        if len(plaintext_data) != 4:
            raise SASLProtocolException("Bad response from server")  # todo: better message

        word, = struct.unpack('!I', plaintext_data)
        qop_bits = word >> 24
        max_length = word & 0xffffff
        server_offered_qops = QOP.names_from_bitmask(qop_bits)
        self._pick_qop(server_offered_qops)

        self.max_buffer = min(self.sasl.max_buffer, max_length)

        """
        byte 0: the selected qop. 1==auth, 2==auth-int, 4==auth-conf
        byte 1-3: the max length for any buffer sent back and forth on
            this connection. (big endian)
        the rest of the buffer: the authorization user name in UTF-8 -
            not null terminated.
        """
        auth_id = self.sasl.authorization_id or self.user
        l = len(auth_id)
        fmt = '!I' + str(l) + 's'
        word = QOP.flag_from_name(self.qop) << 24 | self.max_buffer
        out = struct.pack(fmt, word, _b(auth_id),)

        encoded = base64.b64encode(out).decode('ascii')

        kerberos.authGSSClientWrap(self.context, encoded)
        response = kerberos.authGSSClientResponse(self.context)
        self.complete = True
        return base64.b64decode(response)

    def wrap(self, outgoing):
        if self.qop != 'auth':
            outgoing = base64.b64encode(outgoing)
            if self.qop == 'auth-conf':
                protect = 1
            else:
                protect = 0
            kerberos.authGSSClientWrap(self.context, outgoing, None, protect)
            return base64.b64decode(kerberos.authGSSClientResponse(self.context))
        else:
            return outgoing

    def unwrap(self, incoming):
        if self.qop != 'auth':
            incoming = base64.b64encode(incoming)
            kerberos.authGSSClientUnwrap(self.context, incoming)
            conf = kerberos.authGSSClientResponseConf(self.context)
            if 0 == conf and self.qop == 'auth-conf':
                raise Exception("Error: confidentiality requested, but not honored by the server.")
            return base64.b64decode(kerberos.authGSSClientResponse(self.context))
        else:
            return incoming

    def dispose(self):
        kerberos.authGSSClientClean(self.context)


#: Global registry mapping mechanism names to implementation classes.
mechanisms = dict((m.name, m) for m in (
    AnonymousMechanism,
    PlainMechanism,
    CramMD5Mechanism,
    DigestMD5Mechanism))

if _have_kerberos:
    mechanisms[GSSAPIMechanism.name] = GSSAPIMechanism
