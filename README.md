# Cryptography---19CS412-Advanced -techqniques


# DES
DES using with different key values

# AIM:
To develop a program to implement Data Encryption Standard for encryption and
decryption.

# ALGORITHM DESCRIPTION:
The Data Encryption Standard (DES) is a symmetric-key block cipher published by
the National Institute of Standards and Technology (NIST). DES is an implementation of a
Feistel Cipher. It uses 16 round Feistel structure. The block size is 64-bit. Though, key length
is 64-bit, DES has an effective key length of 56 bits, since 8 of the 64 bits of the key are not
used by the encryption algorithm (function as check bits only). General Structure of DES is
depicted in the following illustration − 
![image](https://github.com/smriti1910/19CS412---CRYPTOGRAPHY---ADVANCED-ENCRYPTION/assets/133334803/ed171878-7b71-46ad-ac9d-72f5e17d32ab)

 
# PROGRAM:
```
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

def encrypt_des(key, plaintext):
    key = key[:8]  # DES key size is 8 bytes
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    plaintext = plaintext.encode('utf-8')
    padded_data = pad(plaintext, DES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return b64encode(ciphertext).decode('utf-8')

def decrypt_des(key, ciphertext):
    key = key[:8]  # DES key size is 8 bytes

    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)

    ciphertext = b64decode(ciphertext)
    decrypted_data = cipher.decrypt(ciphertext)
    unpadded_data = unpad(decrypted_data, DES.block_size)
    return unpadded_data.decode('utf-8')

# Take input for key and plaintext from the user
key = input("Enter the DES key (8 characters): ")
plaintext = input("Enter the plaintext: ")

encrypted_text = encrypt_des(key, plaintext)
print(f"Encrypted text: {encrypted_text}")

decrypted_text = decrypt_des(key, encrypted_text)
print(f"Decrypted text: {decrypted_text}")
```

# OUTPUT:

![DES_OUTPUT](https://github.com/smriti1910/19CS412---CRYPTOGRAPHY---ADVANCED-ENCRYPTION/assets/133334803/608c008d-5ce5-4225-860b-f850c058391d)
 

# RESULT:
	Thus the DES Algorithm is implemented successfully.
---------------------------------

# RSA
RSA using with different key values

# AIM:
To implement RSA (Rivest–Shamir–Adleman) algorithm by using Python code.

# ALGORITHM:
1. Choose two prime number p and q
2. Compute the value of n and p
3. Find the value of e (public key)
4. Compute the value of d (private key) using gcd()
5. Do the encryption and decryption
a. Encryption is given as,
 		c = te mod n
b. Decryption is given as,
 		t = cd mod n
   
# PROGRAM:
```
import random

def generate_prime():
    while True:
        prime_candidate = random.randint(100, 1000)
        if is_prime(prime_candidate):
            return prime_candidate

def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def generate_keys():
    p = generate_prime()
    q = generate_prime()
    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = random.randint(2, phi_n - 1)
    while gcd(e, phi_n) != 1:
        e = random.randint(2, phi_n - 1)

    d = mod_inverse(e, phi_n)
    return ((e, n), (d, n))

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def encrypt(message, public_key):
    e, n = public_key
    return pow(message, e, n)

def decrypt(ciphertext, private_key):
    d, n = private_key
    return pow(ciphertext, d, n)

def encode_message(message):
    return [ord(char) for char in message]

def decode_message(encoded_message):
    return ''.join(chr(char) for char in encoded_message)

if __name__ == '__main__':
    public_key, private_key = generate_keys()
    message=input("Plain Text:")

    encoded_message = encode_message(message)
    encrypted_message = [encrypt(char, public_key) for char in encoded_message]
    decrypted_message = [decrypt(char, private_key) for char in encrypted_message]

    decoded_message = decode_message(decrypted_message)

    
    print("\n\nThe encoded message(encrypted by public key)\n")
    print(''.join(str(p) for p in encrypted_message))
    print("\n\nThe decoded message(decrypted by private key)\n")
    print(decoded_message)
```
# OUTPUT:
 
![image](https://github.com/smriti1910/19CS412---CRYPTOGRAPHY---ADVANCED-ENCRYPTION/assets/133334803/af5b9681-891c-4a4d-9c81-772265bcdeaa)


# RESULT:
	Thus RSA Algorithm is implemented successfully.


---------------------------

# DIFFIE-HELLMAN
Deffie hellman algorithm to establish secret communication exchangine data over network

# Aim :
Develop a program to implement Diffie Hellman Key Exchange Algorithm for encryption and Decryption.

# Algorithm Description:
Diffie–Hellman key exchange (D–H) is a specific method of securely
exchanging cryptographic keys over a public channel and was one of the first publickey protocols. The Diffie–Hellman key exchange method allows two parties that have
no prior knowledge of each other to jointly establish a shared secret key over an
insecure channel. This key can then be used to encrypt subsequent communications
using a symmetric key cipher.

# Algorithm:
1. Global Public Elements:
Let q be a prime number and  where  < q and  is a primitive root
of q.
2. User A Key Generation:
Select private XA where XA < q
Calculate public YA where YA = 
XA mod q
3. User B Key Generation:
Select private XB where XB < q
Calculate public YB where YB = 
XB mod q
4. Calculation of Secret Key by User A
K = (YB)
XA mod q
5. Calculation of Secret Key by User B
   
# PROGRAM:
```
def mod_exp(base, exponent, modulus):
    result = 1
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent //= 2
    return result

while True:
    try:
        p = int(input("Enter a prime number (P): "))
        if p > 1 and all(p % i != 0 for i in range(2, int(p**0.5) + 1)):
            break
        else:
            print("Please enter a valid prime number.")
    except ValueError:
        print("Please enter a valid integer.")

while True:
    try:
        g = int(input("Enter a primitive root (G) for {}: ".format(p)))
        if 1 < g < p:
            break
        else:
            print("Please enter a valid primitive root.")
    except ValueError:
        print("Please enter a valid integer.")


while True:
    try:
        private_key_alice = int(input("Enter the private key of A: "))
        private_key_bob = int(input("Enter the private key of B: "))
        if 1 <= private_key_alice < p and 1 <= private_key_bob < p:
            break
        else:
            print("Private keys should be between 1 and {}.".format(p - 1))
    except ValueError:
        print("Please enter valid integers for private keys.")


public_value_alice = mod_exp(g, private_key_alice, p)
public_value_bob = mod_exp(g, private_key_bob, p)

received_public_value_alice = public_value_bob
received_public_value_bob = public_value_alice

shared_secret_alice = mod_exp(received_public_value_alice, private_key_alice, p)
shared_secret_bob = mod_exp(received_public_value_bob, private_key_bob, p)

print("\nShared Secret for A and B:", shared_secret_alice)
```
# OUTPUT:

 ![output](https://github.com/smriti1910/19CS412---CRYPTOGRAPHY---ADVANCED-ENCRYPTION/assets/133334803/3c590cf0-1962-4685-9dfd-d353f43c3f62)



# RESULT:
Thus Diffie–Hellman key exchange algorithm is implemented successfully.


-------------------------------------------------

# IMPLEMENTATION OF AES
# AIM:
To use Advanced Encryption Standard (AES) Algorithm for a practical application like URL Encryption.

# ALGORITHM:
AES is based on a design principle known as a substitution–permutation.
AES does not use a Feistel network like DES, it uses variant of Rijndael.
It has a fixed block size of 128 bits, and a key size of 128, 192, or 256 bits.
AES operates on a 4 × 4 column-major order array of bytes, termed the state
# PROGRAM:
# AES.py
```
from Crypto.Cipher import AES
from Crypto.Hash import SHA1
from Crypto.Util.Padding import pad, unpad
import base64

def encrypt_AES(text, key):
    key = SHA1.new(key.encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(text.encode(), AES.block_size))).decode()

def decrypt_AES(encrypted_text, key):
    key = SHA1.new(key.encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(base64.b64decode(encrypted_text)), AES.block_size).decode()

def main():
    secret_key = "annaUniversity"
    original_string = "www.annauniv.edu"
    
    encrypted_string = encrypt_AES(original_string, secret_key)
    decrypted_string = decrypt_AES(encrypted_string, secret_key)
    
    print("URL Encryption Using AES Algorithm\n------------")
    print("Original URL :", original_string)
    print("Encrypted URL :", encrypted_string)
    print("Decrypted URL :", decrypted_string)

if __name__ == "__main__":
    main()
```

# OUTPUT:
![image](https://github.com/smriti1910/19CS412---CRYPTOGRAPHY---ADVANCED-ENCRYPTION/assets/133334803/54af5b1e-4bf8-4ec3-8d1a-54027f232c12)


# RESULT:
	Thus AES algorithm was implemented successfully.
