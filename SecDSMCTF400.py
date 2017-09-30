#!/usr/bin/python3

import string
import random
import sys
from Crypto.Hash import *


def random_string(length, characters=string.digits):
    return ''.join(random.choice(characters) for _ in range(length))


def hash_hmac(string):
    secret = random_string(4)
    print('Secret: ' + secret)
    h = HMAC.new(key=secret.encode(), msg=string, digestmod=MD5)
    # h.update(string)
    print(secret + "#" + h.hexdigest())
    return [h.hexdigest(), ""]


if __name__ == "__main__":
    help_message = "Usage: python3 SecDSMCTF_400.py data_to_hash\n"
    if len(sys.argv) < 2:
        print('Usage: python3 ' + sys.argv[0] + ' data_to_hash')
        sys.exit(0)
    data = sys.argv[1]
    if data:
        data = data.encode('utf-8')
        hmac_ret = hash_hmac(data)
        print('HMAC of: ', data.decode(), ' is ' + hmac_ret[0])
    else:
        print(help_message)
