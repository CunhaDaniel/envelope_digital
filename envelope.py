from Crypto.Util.Padding import pad, unpad
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
path_plain_text   = "message.txt" #input("Digite o caminho do arquivo em claro: ")
public_key_dest   = "./tmp/public/public_key_alice.pem" #input("Digite o caminho da chave pública do destinatário: ")
private_key_remet = "./tmp/secret/bob/private_key_bob.pem" #input("Digite o caminho da chave privada do remetente: ")
encryp_algorithm  = "RC4" #input("Digite o algoritmo disponíveis: [AES|DES|RC4]: ") # TODO: dizer tamanho da chave

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

def create_envelope(path_plain_text, public_key_dest, private_key_remet, encryp_algorithm):
    data_plain_text = open(path_plain_text, "r").read().encode('utf-8')

    if (encryp_algorithm == 'AES'):
        session_key     = get_random_bytes(16)

        cipher_aes        = AES.new(session_key, AES.MODE_ECB)
        padded_message    = pad(data_plain_text, AES.block_size)
        encrypted_message = cipher_aes.encrypt(padded_message)
    elif (encryp_algorithm == 'DES'):
        session_key = get_random_bytes(8)

        cipher            = DES.new(session_key, DES.MODE_ECB)
        padded_message    = pad(data_plain_text, DES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
    elif (encryp_algorithm == 'RC4'):
        session_key = get_random_bytes(16)
     
        cipher            = ARC4.new(session_key)
        encrypted_message = cipher.encrypt(data_plain_text)

    instantiate_dest_public_key = RSA.import_key(open(public_key_dest).read())
    cipher_rsa                  = PKCS1_OAEP.new(instantiate_dest_public_key)
    encrypt_session_key         = cipher_rsa.encrypt(session_key)

    private_key = RSA.import_key(open(private_key_remet).read())
    hash_sign   = SHA256.new(encrypted_message)
    signature   = pkcs1_15.new(private_key).sign(hash_sign)

    output_message = open("./tmp/messages/message", "wb")
    output_key     = open("./tmp/messages/key", "wb")

    signed_data = encrypted_message + b'space' + signature
    output_message.write(signed_data)
    output_key.write(encrypt_session_key)

create_envelope(path_plain_text, public_key_dest, private_key_remet, encryp_algorithm)

message = "tmp/messages/message"
public_key_remet = "tmp/public/public_key_bob.pem"
private_key_dest = "tmp/secret/alice/private_key_alice.pem"
session_key = "tmp/messages/key"

def open_envelope(message, public_key_remet, private_key_dest, session_key, encryp_algorithm):
    signed_data = open(message, 'rb').read()
    data        = signed_data.rsplit(b'space')[0]
    signature   = signed_data.rsplit(b'space')[1]
    public_key  = RSA.import_key(open(public_key_remet).read())
    hash_sign   = SHA256.new(data)
    
    try:
        pkcs1_15.new(public_key).verify(hash_sign, signature)
        
        print("Assinatura válida.")
        print("Resolvendo chave de sessao...")

        loaded_private_key  = RSA.import_key(open(private_key_dest, "rb").read())
        cipher_rsa          = PKCS1_OAEP.new(loaded_private_key)
        session_key         = cipher_rsa.decrypt(open(session_key, 'rb').read())
    
        print("Resolvendo texto...")
        if (encryp_algorithm == 'AES'):
            cipher    = AES.new(session_key, AES.MODE_ECB)
            plaintext = unpad(cipher.decrypt(data), AES.block_size)
        elif (encryp_algorithm == 'DES'):
            cipher    = DES.new(session_key, DES.MODE_ECB)
            plaintext = unpad(cipher.decrypt(data), DES.block_size)
        elif (encryp_algorithm == 'RC4'):
            cipher    = ARC4.new(session_key)
            plaintext = cipher.decrypt(data)

        print(plaintext.decode("utf-8"))
    except:
        print("Assinatura inválida.")

open_envelope(message, public_key_remet, private_key_dest, session_key, encryp_algorithm)
