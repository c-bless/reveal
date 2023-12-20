import string
import secrets


def gen_initial_pw():
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for i in range(0,32))
    return password

def gen_api_token():
    return secrets.token_hex(64)


