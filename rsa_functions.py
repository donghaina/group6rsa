import base64
# Import necessary modules from pycryptodome
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


# Step 2: Generate new RSA key
def generateKeys(keyLength):
    # Create an RSA key pair with a key size of 1024 bits
    key = RSA.generate(1024)

    # Set the private_key variable to the generated key
    private_key = key

    # Derive the public key from the generated key
    public_key = key.publickey()
    return {
        'publicKey': public_key.exportKey().decode('utf-8'),
        'privateKey': private_key.exportKey().decode('utf-8'),
    }


# Step 3: Encrypt using public key
def encrypt_message(public_key_pem, message):
    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message.encode('utf-8'))
    return {
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }


# Step 4: Decrypt using private key
def decrypt_message(private_key_pem, ciphertext_base64):
    private_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(private_key)
    ciphertext = base64.b64decode(ciphertext_base64)
    plaintext = cipher.decrypt(ciphertext)
    print(plaintext.decode('utf-8'))
    return {
        'plaintext': plaintext.decode('utf-8')
    }
