import urllib2
import argparse

import scitokens

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def main():
    
    parser = argparse.ArgumentParser(description='Create token and test endpoint.')
    parser.add_argument('--aud', dest='aud', help="Insert an audience")
    args = parser.parse_args()
    
    private_key = None
    with open('private.pem', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
        
    token = scitokens.SciToken(key=private_key, key_id="test-id")
    token["scope"] = "read:/"
    
    if 'aud' in args and args.aud is not None:
        token["aud"] = args.aud
    
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

