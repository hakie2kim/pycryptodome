import os
import sys
from base64 import b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad


def rsa_decrypt(user):
    if user == "Alice":
        # Receiver (Alice) decrypts sym_key with their own sk
        file_in = open("sym_key_encrypted_with_Alice_pk.bin", "rb")
        private_key = RSA.import_key(open("private_Alice.pem").read())
        enc_data = file_in.read(private_key.size_in_bytes())
        cipher_rsa = PKCS1_OAEP.new(private_key)
        sym_key = cipher_rsa.decrypt(enc_data)
        file_in.close()

        print(sym_key)
        print()

        return sym_key

    elif user == "Bob":
        # Receiver (Bob) decrypts sym_key with their own sk
        file_in = open("sym_key_encrypted_with_Bob_pk.bin", "rb")
        private_key = RSA.import_key(open("private_Bob.pem").read())
        enc_data = file_in.read(private_key.size_in_bytes())
        cipher_rsa = PKCS1_OAEP.new(private_key)
        sym_key = cipher_rsa.decrypt(enc_data)
        file_in.close()

        return sym_key


def get_enc_file_names():
    # List to store file names
    enc_file_names = []

    for dir_list in os.listdir():
        if dir_list.find(".enc", -4) != -1:
            enc_file_names.append(dir_list)

    return enc_file_names


def main():
    # 1. Ask whether user is Alice or Bob
    user = input("Are you Alice or Bob? (Enter either Alice or Bob) : ")

    # 2. Decrypt an encrypted symmetric key using private key -> public key decryption
    sym_key = rsa_decrypt(user)

    # 3. Get all file names where extension is .enc.
    enc_file_names = get_enc_file_names()

    # Initial vector is from user input
    iv = b64decode(sys.argv[1])
    cipher = AES.new(sym_key, AES.MODE_CBC, iv)

    for enc_file_name in enc_file_names:
        try:
            file_in = open(enc_file_name, "rb")

            ct_bytes_b64encode = file_in.read()
            ct = b64decode(ct_bytes_b64encode.decode('utf-8'))

            # 4. Decrypt an encrypted message using symmetric key -> symmetric key decryption
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            print("The message for", enc_file_name, "was", pt)

            file_in.close()

        except ValueError:
            print("Incorrect decryption")

        except KeyError:
            print("Incorrect key")


if __name__ == "__main__":
    main()
