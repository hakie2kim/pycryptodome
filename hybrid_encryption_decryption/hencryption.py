import os
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def keys_pair_gen():
    key = RSA.generate(2048)

    # 1. Generate a public key and save it into public_Alice.pem file
    public_key = key.publickey().export_key()
    file_out = open("public_Alice.pem", "wb")
    file_out.write(public_key)
    file_out.close()

    # 2. Generate a private key and save it into private_Alice.pem file
    private_key = key.export_key()
    file_out = open("private_Alice.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    # 3. Create another key pair for Bob
    key = RSA.generate(2048)

    public_key = key.publickey().export_key()
    file_out = open("public_Bob.pem", "wb")
    file_out.write(public_key)
    file_out.close()

    private_key = key.export_key()
    file_out = open("private_Bob.pem", "wb")
    file_out.write(private_key)
    file_out.close()


def rsa_encrypt(sym_key, user):
    if user == "Alice":
        # Sender (Alice) encrypts sym_key with recipient's (Bob) pk
        recipient_key = RSA.import_key(open("public_Bob.pem").read())
        file_out = open("sym_key_encrypted_with_Bob_pk.bin", "wb")
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_sym_key = cipher_rsa.encrypt(sym_key)
        file_out.write(enc_sym_key)
        file_out.close()

    elif user == "Bob":
        # Sender (Bob) encrypts sym_key with recipient's (Alice) pk
        recipient_key = RSA.import_key(open("public_Alice.pem").read())
        file_out = open("sym_key_encrypted_with_Alice_pk.bin", "wb")
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_sym_key = cipher_rsa.encrypt(sym_key)
        file_out.write(enc_sym_key)
        file_out.close()


def get_txt_file_names():
    # List to store file names
    txt_file_names = []

    for dir_list in os.listdir():
        if dir_list.find(".txt", -4) != -1:
            txt_file_names.append(dir_list)

    return txt_file_names


def sym_encrypt(data, file_name, cipher):
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))

    iv = b64encode(cipher.iv).decode('utf-8')
    # ct = b64encode(ct_bytes).decode('utf-8')
    # skey = b64encode(sym_key).decode('utf-8')
    # print(iv, ct, skey)

    file_out = open(file_name + ".enc", "wb")
    ct = b64encode(ct_bytes)
    file_out.write(ct)
    file_out.close()
    print(file_name + ".txt", "has been encrypted to", file_name + ".enc")
    print("Initial vector:", iv)
    print()


def main():
    # 1. Create two public and private key pairs for Alice and Bob
    keys_pair_gen()

    # 2. Ask whether user is Alice or Bob
    user = input("Are you Alice or Bob? (Enter either Alice or Bob) : ")

    # 3. Generate a symmetric key
    sym_key = get_random_bytes(16)

    # 4. Encrypt a symmetric key using sender's public key -> public key encryption
    rsa_encrypt(sym_key, user)

    # 5. Get all file names where extension is .txt.
    txt_file_names = get_txt_file_names()

    # 6. Create a cipher to enable encryption
    cipher = AES.new(sym_key, AES.MODE_CBC)

    # 7. For every file names in array, first read in data
    # and encrypt a message using a symmetric key -> symmetric key encryption
    for txt_file_name in txt_file_names:
        txt_file_data_in = open(txt_file_name, "rb")
        txt_file_data = txt_file_data_in.read()
        txt_file_data_in.close()

        sym_encrypt(txt_file_data, txt_file_name[:-4], cipher)


if __name__ == "__main__":
    main()
