from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
import os

def derive_key(password, salt, key_length):
    # Use PBKDF2 to derive a key from the password and a salt
    key = PBKDF2(password, salt, dkLen=key_length, count=600000)  # NIST suggests 600.000 derivations. i use 600.000.
    return key

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
import os

def derive_key(password, salt, key_length):
    # Use PBKDF2 to derive a key from the password and a salt
    key = PBKDF2(password, salt, dkLen=key_length, count=600000)  # NIST suggests 600,000 derivations
    return key

def encrypt_file(file_path, password):
    # Random 16-byte salt
    salt = get_random_bytes(16)
    print(salt)
    password = bytes(password, encoding='utf-8')
    # Derive a 256-bit key from the password and salt
    key = derive_key(password, salt, 32)  # Use 32 bytes for AES-256

    # Generate a unique IV for this encryption operation
    iv = get_random_bytes(16)

    # Create an AES cipher object with the derived key, AES.MODE_CFB mode, and the IV
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)

    # Open the file in rb = read bytes mode
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    # Encrypt and pad
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    # Write salt and IV to file
    salt_file_path = file_path + ".salt"
    with open(salt_file_path, 'wb') as salt_file:
        salt_file.write(salt)

    iv_file_path = file_path + ".iv"
    with open(iv_file_path, 'wb') as iv_file:
        iv_file.write(iv)

    encrypted_file_path = file_path + ".encrypted"
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(ciphertext)

    print(f"Encrypted file: {file_path}.")

def decrypt_file(salt_path, iv_path, file_path, password):
    # Read the salt and IV from their respective files
    with open(salt_path, 'rb') as salt_file:
        salt = salt_file.read(16)  # Read the salt

    with open(iv_path, 'rb') as iv_file:
        iv = iv_file.read(16)  # Read the IV

    with open(file_path, 'rb') as encrypted_file:
        ciphertext = encrypted_file.read()

    # Derive the key from the password and salt
    key = derive_key(password, salt, 32)  # Use 32 bytes for AES-256

    # Create an AES cipher object with the derived key, AES.MODE_CFB mode, and the IV
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)

    try:
        # Decrypt and then unpad
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        # Determine the output file name based on the original file name
        output_file_path = os.path.splitext(file_path)[0]

        # Write the decrypted data to a new file
        with open(output_file_path, 'wb') as decrypted_file:
            decrypted_file.write(plaintext)

        print(f"Decrypted {file_path}. Saved as {output_file_path}")
    except ValueError:
        print(f"Failed to decrypt {file_path}. The file may be corrupted or the password is incorrect.")


def secure_delete(file_path, passes=3):
    print("Securely deleting of file: {file_path} ")
    length = os.path.getsize(path)
    with open(path, "br+", buffering=-1) as f:
        for i in range(passes):
            f.seek(0)
            f.write(os.urandom(length))
        f.close()
    print("{file_path} deletion successful.")

# Example usage:
# encrypt_file('your_file_to_encrypt.txt', 'your_password')
# decrypt_file('your_file_to_encrypt.txt.salt', 'your_file_to_encrypt.txt.iv', 'your_file_to_encrypt.txt.encrypted', 'your_password')
# secure_delete('your_file_to_delete.bin', passes=n)



# Get user input for the password
# password = input("Enter the encryption/decryption password: ")

# Paths to the files to be processed
#db_path = [r""]

# for file_path in db_path:
    # assume file ending in .enc are encrypted and thus can only be decrypted. chaining encryption is bad.
  #  if file_path.endswith(".enc"):
   #     decrypt_file(file_path, password)
    #else:
     #   encrypt_file(file_path, password)
