
import ConfigParser
import errno
import os
import time
import urllib

import urltools
import scitokens
import _scitokens_xrootd

g_authorized_issuers = {}

class InvalidAuthorization(object):
    """
    Exception representing cases where the token's authorizations are invalid,
    such as providing a `read` authorization with no `path` claim.
    """

class AclGenerator(object):

    def __init__(self, base_path="/"):
        self.aops = set()
        self.paths = set()
        self.cache_expiry = 60
        self.subject = ""
        self.base_path = base_path
        self.issuer = None

    def validate_authz(self, values):
        if isinstance(values, str) or isinstance(values, unicode):
            values = [values]
        for value in values:
            if value == "read":
                self.aops.add(_scitokens_xrootd.AccessOperation.Read)
            elif value == "write":
                self.aops.add(_scitokens_xrootd.AccessOperation.Update)
                self.aops.add(_scitokens_xrootd.AccessOperation.Create)
            else:
                return False
        return True

    def validate_path(self, values):
        if isinstance(values, str) or isinstance(values, unicode):
            values = [values]
        for value in values:
            if not value.startswith("/"):
                return False
            self.paths.add(urltools.normalize(value))
        return True

    def validate_exp(self, value):
        self.cache_expiry = value - time.time()
        if self.cache_expiry <= 0:
            return False
        return True

    def validate_sub(self, value):
        self.subject = value
        return True

    def validate_iss(self, value):
        self.issuer = value
        return True

    def validate_iat(self, value):
        return time.time() > int(value)

    def generate_acls(self):
        if self.aops and not self.paths:
            raise InvalidAuthorization("If a filesystem authorization is provided, a path must also be set")

        for aop in self.aops:
            for path in self.paths:
                # Note that in validate_path we verified `path` starts with '/'
                path = str(os.path.normpath(self.base_path + path))
                while path.startswith("//"):
                    path = path[1:]
                yield (aop, path)


def config(fname):
    print "Trying to load configuration from %s" % fname
    cp = ConfigParser.SafeConfigParser()
    try:
        with open(fname, "r") as fp:
            cp.readfp(fp)
    except IOError as ie:
        if ie.errno == errno.ENOENT:
            return
        raise
    for section in cp.sections():
        if not section.lower().startswith("issuer "):
            continue
        if 'issuer' not in cp.options(section):
            print "Ignoring section %s as it has no `issuer` option set." % section
        if 'base_path' not in cp.options(section):
            print "Ignoring section %s as it has no `base_path` option set." % section
        issuer = cp.get(section, 'issuer')
        base_path = cp.get(section, 'base_path')
        base_path = urltools.normalize(base_path)
        issuer_info = g_authorized_issuers.setdefault(issuer, {})
        issuer_info['base_path'] = base_path
        if 'map_subject' in cp.options(section):
            issuer_info['map_subject'] = cp.getboolean(section, 'map_subject')
        print "Configured token access for %s (issuer %s): %s" % (section, issuer, str(issuer_info))

def init(parms=None):
    print "SciTokens module configuration parameters:", parms
    found_config = False

    if parms:
        for parm in parms.split():
            info = parm.split('=', 2)
            if len(info) != 2:
               print "Ignoring unknown parameter:", parm
               continue
            key, val = info
            if key == "config":
                config(val)
                found_config = True
    if not found_config:
        config("/etc/xrootd/scitokens.cfg")


def generate_acls(header):
    """
    Generate a list of ACLs and the ACL timeut
    """
    orig_header = urllib.unquote(header)
    if not orig_header.startswith("Bearer "):
        return 60, [], ""
    token = orig_header[7:]
    try:
        scitoken = scitokens.SciToken.deserialize(token)
    except Exception as e:
        # Uncomment below to test ACLs even when valid tokens aren't available.
        #print "Token deserialization failed", str(e)
        #return 60, [(_scitokens_xrootd.AccessOperation.Read, "/home/cse496/bbockelm")], "bbockelm"
        raise

    claims = dict(scitoken.claims())
    issuer = claims['iss']
    if issuer not in g_authorized_issuers:
        print "Token issuer (%s) not configured." % issuer
        return 60, [], ""
    base_path = g_authorized_issuers[issuer]['base_path']

    ag = AclGenerator(base_path)

    validator = scitokens.Validator()
    validator.add_validator("authz", ag.validate_authz)
    validator.add_validator("path", ag.validate_path)
    validator.add_validator("exp", ag.validate_exp)
    validator.add_validator("sub", ag.validate_sub)
    validator.add_validator("iss", ag.validate_iss)
    validator.add_validator("iat", ag.validate_iss)
    validator.add_validator("nbf", ag.validate_iss)
    validator.validate(scitoken)

    subject = ""
    if g_authorized_issuers[issuer].get('map_subject'):
        subject = ag.subject
    return int(ag.cache_expiry), list(ag.generate_acls()), str(subject)

