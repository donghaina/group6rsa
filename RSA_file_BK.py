# @Author:Haina Dong
# @Date: 2024-11-23
# Description: Core implementation of RSA algorithm
import random
import math
import base64


# Fast exponentiation algorithm for calculating (b^e) % m
def fast_exp_mod(b, e, m):  # base, exponent, modulus
    result = 1
    b = b % m
    while e > 0:
        if e % 2 == 1:
            result = (result * b) % m
        e = e >> 1
        b = (b * b) % m
    return result


# Miller-Rabin primality test for checking if a number is prime
def miller_rabin_test(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = fast_exp_mod(a, d, n)
        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = fast_exp_mod(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


# Generate a large prime number
def create_prime_num(keylength):
    while True:
        n = random.getrandbits(keylength)
        n |= (1 << keylength - 1) | 1  # Ensure n is of keylength bits and odd
        if miller_rabin_test(n):
            return n


# Generate public and private keys
def create_keys(keylength):
    p = create_prime_num(keylength // 2)
    q = create_prime_num(keylength // 2)
    n = p * q
    fn = (p - 1) * (q - 1)
    e = select_e(fn)
    d = match_d(e, fn)
    return n, e, d


# Randomly select an e in (1, fn) such that gcd(e, fn) = 1
def select_e(fn):
    e = 65537  # Commonly used public exponent
    if math.gcd(e, fn) == 1:
        return e
    else:
        return select_e(fn)


# Find the unique d for the selected e using Extended Euclidean Algorithm
def match_d(e, fn):
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y

    g, x, _ = egcd(e, fn)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % fn


# Generate public and private keys (PEM format)
def generateKeys(keylength=2048):
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
