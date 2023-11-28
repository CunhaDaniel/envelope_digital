# pip install pycryptodome
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES
from Crypto.Cipher import ARC4
from Crypto.Hash import SHA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os

# Basic input infos
plain_text        = "message.txt" #input("Digite o caminho do arquivo em claro: ")
public_key_dest   = "./tmp/public/public_key_alice.pem" #input("Digite o caminho da chave pública do destinatário: ")
private_key_remet = "./tmp/secret/bob/private_key_bob.pem" #input("Digite o caminho da chave privada do remetente: ")
encryp_algorithm  = "aes" #input("Digite o algoritmo disponíveis: [AES|DES|RC4]: ") # TODO: dizer tamanho da chave

# This method create a user keys
# @param[string] <user> represents who that keys will belongs
# this method creates two files
# private_key with path: ./tmp/secret/<user>/private_key_<user>.pem
# public_key  with path: ./tmp/public/public_key_<user>.pem
def create_users_keys(user="daniel"):
    user = user.lower()
    # Create and export private key
    key         = RSA.generate(2048)
    private_key = key.export_key()
    os.makedirs(f"./tmp/secret/{user}/", exist_ok=True)
    file_key    = open(f"./tmp/secret/{user}/private_key_{user}.pem", "wb")
    file_key.write(private_key)
    file_key.close()

    # Create and export public keys 
    public_key = key.publickey().export_key()
    file_key   = open(f"./tmp/public/public_key_{user}.pem", "wb")
    file_key.write(private_key)
    file_key.close()

def create_envelope(plain_text, public_key_dest, private_key_remet, encryp_algorithm):
    plain_text = open(plain_text, "r").read().encode("utf-8")

    session_key       = get_random_bytes(16)
    cipher            = AES.new(session_key, AES.MODE_EAX)
    encrypted_message = cipher.encrypt(plain_text)

    private_key = RSA.import_key(open(private_key_remet).read())
    h = SHA256.new(encrypted_message)
    signature = pkcs1_15.new(private_key).sign(h)

    instantiate_dest_public_key = RSA.import_key(open(public_key_dest).read())
    cipher_rsa                  = PKCS1_OAEP.new(instantiate_dest_public_key)
    encrypt_session_key         = cipher_rsa.encrypt(session_key)

    output_message = open("./tmp/messages/message", "wb")
    output_key     = open("./tmp/messages/key", "wb")

    signed_data = encrypted_message + b'\n' + signature
    output_message.write(signed_data)
    output_key.write(encrypt_session_key)

# create_envelope(plain_text, public_key_dest, private_key_remet, encryp_algorithm)

message = "tmp/messages/message"
public_key_remet = "tmp/public/public_key_bob.pem"
private_key_dest = "tmp/secret/alice/private_key_alice.pem"

def open_envelope(message, public_key_remet, private_key_dest, encryp_algorithm):
    signed_data = open(message, 'rb').read()
    data, signature = signed_data.rsplit(b'\n', 1)
    key = RSA.import_key(open(public_key_remet).read())
    h = SHA256.new(data)
    try:
        pkcs1_15.new(key).verify(h, signature)
        print("Assinatura válida.")
        valid = True
    except (ValueError, TypeError):
        print("Assinatura inválida.")
        valid = False
    if valid:
        encrypted_session_key = open("./tmp/messages/key", "rb").read()
        private_key = RSA.import_key(open(private_key_dest).read())
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(encrypted_session_key)
        if encryp_algorithm == "aes":
            print("AES")
            cipher = AES.new(session_key, AES.MODE_EAX)
        elif encryp_algorithm == "des":
            print("DES")
            cipher = DES.new(session_key, DES.MODE_ECB)
        elif encryp_algorithm == "rc4":
            print("RC4")
            cipher = ARC4.new(session_key)
        else:
            print("Algoritmo inválido.")
            return
        plain_text = cipher.decrypt(data)
        print("Mensagem descriptografada:")
        print(cipher )
        # print(plain_text.decode("utf-8"))

open_envelope(message, public_key_remet, private_key_dest, encryp_algorithm)


# def open_envelope(message, public_key_remet):
#     signed_data = open(message, 'rb').read()
#     data, signature = signed_data.rsplit(b'\n', 1)
#     key = RSA.import_key(open(public_key_remet).read())
#     h = SHA256.new(data)
#     try:
#         pkcs1_15.new(key).verify(h, signature)
#         print("Assinatura válida.")
#         return True
#     except (ValueError, TypeError):
#         print("Assinatura inválida.")
#         return False

# open_envelope(message, public_key_remet)
