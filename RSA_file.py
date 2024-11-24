# @Author:Haina Dong
# @Date: 2024-11-23
# Description: Core implementation of RSA algorithm
import random
import math
import base64


# Fast exponentiation algorithm for calculating (b^e) % m
def fast_exp_mod(b, e, m):  # base, exponent, modulus
    result = 1
    e = int(e)
    while e != 0:
        if e % 2 != 0:  # Bitwise AND
            e -= 1
            result = (result * b) % m
            continue
        e >>= 1
        b = (b * b) % m
    return result


# Miller-Rabin primality test for checking if a number is prime
def miller_rabin_test(n):
    p = n - 1
    r = 0
    while p % 2 == 0:  # Find the odd p (i.e., m)
        r += 1
        p //= 2
    b = random.randint(2, n - 2)  # Randomly select b in range (2, n-2)
    if fast_exp_mod(b, int(p), n) == 1:
        return True  # Passes the test, possibly a prime
    for i in range(0, 7):  # Perform the test six times
        if fast_exp_mod(b, (2 ** i) * p, n) == n - 1:
            return True  # Possibly a prime
    return False  # Definitely not a prime


# Generate a large prime number
def create_prime_num(keylength):
    while True:
        n = random.randint(0, keylength)
        if n % 2 != 0:
            found = True
            for i in range(0, 10):
                if not miller_rabin_test(n):
                    found = False
                    break
            if found:
                return n


# Generate public and private keys
def create_keys(keylength=1024):
    p = create_prime_num(keylength // 2)
    q = create_prime_num(keylength // 2)
    n = p * q
    fn = (p - 1) * (q - 1)
    e = select_e(fn)
    d = match_d(e, fn)
    return n, e, d


# Randomly select an e in (1, fn) such that gcd(e, fn) = 1
def select_e(fn):
    while True:
        e = random.randint(2, fn - 1)
        if math.gcd(e, fn) == 1:
            return e


# Find the unique d for the selected e
def match_d(e, fn):
    d = 0
    while True:
        if (e * d) % fn == 1:
            return d
        d += 1


# Generate public and private keys (PEM format)
def generateKeys(keylength=1024):
    n, e, d = create_keys(keylength)
    public_key_pem = f"""-----BEGIN PUBLIC KEY-----\n{base64.b64encode(f'{e},{n}'.encode()).decode()}\n-----END PUBLIC KEY-----"""
    private_key_pem = f"""-----BEGIN RSA PRIVATE KEY-----\n{base64.b64encode(f'{d},{n}'.encode()).decode()}\n-----END RSA PRIVATE KEY-----"""
    # return public_key_pem, private_key_pem
    return {
        'publicKey': public_key_pem,
        'privateKey': private_key_pem,
    }


# Encryption function
def encrypt_message(public_key_pem, message):
    key_data = public_key_pem.split("\n")[1]
    e, n = map(int, base64.b64decode(key_data).decode().split(','))
    ciphertext = [fast_exp_mod(ord(char), e, n) for char in message]
    print(base64.b64encode(','.join(map(str, ciphertext)).encode()).decode())
    return {
        'ciphertext': base64.b64encode(','.join(map(str, ciphertext)).encode()).decode()
    }


# Decryption function
def decrypt_message(private_key_pem, ciphertext_base64):
    key_data = private_key_pem.split("\n")[1]
    d, n = map(int, base64.b64decode(key_data).decode().split(','))
    ciphertext = list(map(int, base64.b64decode(ciphertext_base64).decode().split(',')))
    plaintext = ''.join([chr(fast_exp_mod(char, d, n)) for char in ciphertext])
    print(plaintext)
    return {
        'plaintext': plaintext
    }
