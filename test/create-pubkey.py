import urllib2

import scitokens

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def main():
    
    private_key = None
    with open('private.pem', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
        
    token = scitokens.SciToken(key=private_key)
    token["scope"] = "read:/"
    
    token_str = token.serialize(issuer="https://localhost")
    headers = {"Authorization": "Bearer {0}".format(token_str)}
    #print token_str
    request = urllib2.Request("http://localhost:8080/tmp/random.txt", headers=headers)
    contents = urllib2.urlopen(request).read()
    print contents,
    
    #request = urllib2.Request("http://localhost:8080/tmp/random.txt")
    #contents = urllib2.urlopen(request).read()
    #print contents,
    


if __name__ == "__main__":
    main()

