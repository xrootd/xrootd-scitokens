
import time
import urllib
import urltools
import scitokens
import _scitokens_xrootd

class InvalidAuthorization(object):
    """
    Exception representing cases where the token's authorizations are invalid,
    such as providing a `read` authorization with no `path` claim.
    """

class AclGenerator(object):

    def __init__(self):
        self.aops = set()
        self.paths = set()
        self.cache_expiry = 60
        self.subject = ""

    def validate_authz(self, values):
        if isinstance(values, str):
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
        if instance(values, str):
            values = [values]
        for value in values:
            self.paths.add(urltools.normalize(value))

    def validate_exp(self, value):
        self.cache_expiry = value - time.time()
        if self.cache_expiry <= 0:
            return False

    def generate_acls(self):
        if self.aops and not self.paths:
            raise InvalidAuthorization("If a filesystem authorization is provided, a path must also be set")

        for aop in self.aops:
            for path in self.paths:
                yield (aop, path)


def generate_acls(header):
    """
    Generate a list of ACLs and the ACL timeut
    """
    orig_header = urllib.unquote(header)
    if not orig_header.startswith("Bearer "):
        return []
    token = orig_header[7:]
    try:
        token = scitokens.SciToken.deserialize(token)
    except Exception as e:
        # Uncomment below to test ACLs even when valid tokens aren't available.
        #print "Token deserialization failed", str(e)
        #return 60, [(_scitokens_xrootd.AccessOperation.Read, "/home/cse496/bbockelm")], "bbockelm"
        raise

    ag = AclGenerator()

    validator = scitokens.Validator()
    validator.add_validator("authz", ag.validate_authz)
    validator.add_validator("path", ag.validate_path)
    validator.add_validator("exp", ag.validate_exp)
    validator.validate()

    return ag.cache_expiry, list(ag.generate_acls()), ag.subject

