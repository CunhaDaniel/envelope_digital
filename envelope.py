# UNIVERSIDADE FEDERAL DO PIAUÍ
# CENTRO DE CIÊNCIAS DA NATUREZA
# DEPARTAMENTO DE COMPUTAÇÃO
# PROFESSOR: Dr. CARLOS ANDRE BATISTA DE CARVALHO
# Alunos: Daniel Mesquita Cunha
#         Marcelo Eduardo Rufino de Oliveira
#         Leonidas Pereira de Abreu

# Para execução do programa:

# 1. O arquivo message.txt na possui a mensagem a ser criptografada, caso deseje mudar é só apagar o que está
# dentro do arquivo e adicionar uma nova mensagem 

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


def validate_encryp_algorithm():
            # Input for encryption algorithm
    encryption_algorithms = ["AES", "DES", "RC4"]
    print("Opções de algoritmo de criptografia: ", encryption_algorithms)
    encryp_algorithm = input("Digite o algoritmo desejado: ")

    # Ensure the chosen encryption algorithm is valid
    while encryp_algorithm not in encryption_algorithms:
        print("Algoritmo inválido. Escolha entre ", encryption_algorithms)
        encryp_algorithm = input("Digite o algoritmo desejado: ")
    return encryp_algorithm

# Teste
def create_users_keys(user):
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




def create_envelope(path_plain_text, private_key_remet, encryp_algorithm, user_dest):
    data_plain_text = open(path_plain_text, "r").read().encode('utf-8')
    public_key_dest = f"./tmp/public/public_key_{user_dest}.pem"
       # Escolha do tamanho da chave
    valid_key_sizes_aes = [128, 192, 256]
    valid_key_sizes_des = [64]
    valid_key_sizes_rc4 = list(range(40, 2049, 8))
    
    if (encryp_algorithm == 'AES'):
        print("Escolha o tamanho da chave para AES (em bits):", valid_key_sizes_aes)
        key_size = int(input())
        if key_size not in valid_key_sizes_aes:
            print("Tamanho de chave inválido para AES. Usando tamanho padrão (128 bits).")
            key_size = 128
        session_key = get_random_bytes(key_size // 8)

        cipher_aes = AES.new(session_key, AES.MODE_ECB)
        padded_message = pad(data_plain_text, AES.block_size)
        encrypted_message = cipher_aes.encrypt(padded_message)
    elif (encryp_algorithm == 'DES'):
        print("Escolha o tamanho da chave para DES (em bits):", valid_key_sizes_des)
        key_size = int(input())
        if key_size not in valid_key_sizes_des:
            print("Tamanho de chave inválido para DES. Usando tamanho padrão (56 bits).")
            key_size = 64
        session_key = get_random_bytes(key_size // 8)

        cipher = DES.new(session_key, DES.MODE_ECB)
        padded_message = pad(data_plain_text, DES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
    elif (encryp_algorithm == 'RC4'):
        print("Escolha o tamanho da chave para RSA (em bits) [40,48,..., 2048]: " )
        key_size = int(input())
        if key_size not in valid_key_sizes_rc4:
            print("Tamanho de chave inválido para RSA. Usando tamanho padrão (2048 bits).")
            key_size = 2048
        session_key = get_random_bytes(key_size // 8)

        cipher = ARC4.new(session_key)
        encrypted_message = cipher.encrypt(data_plain_text)

    instantiate_dest_public_key = RSA.import_key(open(public_key_dest).read())
    cipher_rsa = PKCS1_OAEP.new(instantiate_dest_public_key)
    encrypt_session_key = cipher_rsa.encrypt(session_key)

    private_key = RSA.import_key(open(private_key_remet).read())
    hash_sign = SHA256.new(encrypted_message)
    signature = pkcs1_15.new(private_key).sign(hash_sign)

       # Criar pasta do destinatário
    output_folder_dest = f"./tmp/messages/{user_dest}/"
    os.makedirs(output_folder_dest, exist_ok=True)

    # Criar subpasta com o nome do remetente
    output_folder_remet = os.path.join(output_folder_dest, f"{user_remet}/")
    # output_folder_remet = os.path.join(output_folder_dest, f"{user_remet}_.{encryp_algorithm}/")
    os.makedirs(output_folder_remet, exist_ok=True)
    
    # Criar subpasta com o nome do arquivo
    output_folder_path = os.path.join(output_folder_remet, f"{path_plain_text}/")
    # output_folder_remet = os.path.join(output_folder_dest, f"{user_remet}_.{encryp_algorithm}/")
    os.makedirs(output_folder_path, exist_ok=True)

    output_message = open(os.path.join(output_folder_path, "message"), "wb")
    output_key = open(os.path.join(output_folder_path, "key"), "wb")

    signed_data = encrypted_message + b'space' + signature
    output_message.write(signed_data)
    output_key.write(encrypt_session_key)



def open_envelope( user_remet, user_dest,path_arq):
    
    message = f"tmp/messages/{user_dest}/{user_remet}/{path_arq}/message" # vai ser com base no destinatario e Remetente
    session_key = f"tmp/messages/{user_dest}/{user_remet}/{path_arq}/key" # vai ser com base no destinatario e Remetente   
    public_key_remet = f"./tmp/public/public_key_{user_remet}.pem"
    private_key_dest = f"./tmp/secret/{user_dest}/private_key_{user_dest}.pem"
    
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
      
        algorithms = ['AES', 'DES', 'RC4']

        # Loop for para tentar cada algoritmo
        
        for algorithm in algorithms:
            #testando as 3 opções
            try:
                # Criar o objeto cipher de acordo com o algoritmo
                if algorithm == 'AES':
                    cipher = AES.new(session_key, AES.MODE_ECB)
                    plaintext = unpad(cipher.decrypt(data), cipher.block_size)
                    break
                elif algorithm == 'DES':
                    cipher = DES.new(session_key, DES.MODE_ECB)
                    plaintext = unpad(cipher.decrypt(data), cipher.block_size)
                    break
                elif algorithm == 'RC4':
                    cipher = ARC4.new(session_key)
                    plaintext = cipher.decrypt(data)
                    break
               
            except:
                # Se ocorrer um erro, imprimir uma mensagem de erro
                print("...")

        print(plaintext.decode("utf-8"))
    except:
        print("Assinatura inválida.")


while True:
    print("\nMenu:")
    print("1. Criar chave de usuário")
    print("2. Enviar envelope")
    print("3. Abrir envelope")
    print("4. Sair do programa")

    choice = input("Escolha uma opção (1/2/3/4): ")

    if choice == '1':
        # Opção para criar chave de usuário
        user = input("Digite o nome do usuário: ")
        create_users_keys(user)
        print(f"Chave de usuário criada para {user}")
    elif choice == '2':
        path_plain_text = ""
        while not os.path.exists(path_plain_text):
            path_plain_text = input("Digite o caminho do arquivo de texto: ")
            if not os.path.exists(path_plain_text):
                print("Arquivo nao encontrado! ")
        # Input for public key destination
        user_dest = input("Digite o nome do destinatário (Ex: alice): ")
        public_key_dest = f"./tmp/public/public_key_{user_dest}.pem"

        # Create a new key pair if the user's public key does not exist

        while not os.path.exists(public_key_dest):
            print("Usuário não encontrado.")
            choice = input("Deseja tentar novamente (digite 'sim') ou sair do programa (digite 'sair')? ").lower()

            if choice == 'sair':
                exit()
            elif choice != 'sim':
                print("Opção inválida. Saindo do programa.")
                exit()

            # Se o usuário optar por tentar novamente, solicite o nome do destinatário novamente
            user_dest = input("Digite o nome do destinatário (Ex: alice): ")
            public_key_dest = f"./tmp/public/public_key_{user_dest}.pem"

        # Input for private key sender
        user_remet = input("Digite o nome do remetente (Ex: bob): ")
        private_key_remet = f"./tmp/secret/{user_remet}/private_key_{user_remet}.pem"

        # Create a new key pair if the user's private key does not exist
        if not os.path.exists(private_key_remet):
            create_new_key = input("Deseja criar um Chave para esse usuario ?[sim | nao]")
            if create_new_key == "sim":
                create_users_keys(user_remet)
            else:
                print("Saindo do programa. Até logo!")
                exit()
        
        # Input for encryption algorithm
        encryp_algorithm = validate_encryp_algorithm()
        

        create_envelope(path_plain_text, private_key_remet, encryp_algorithm, user_dest)
    elif choice == '3':
        # abrir envelope 
        print(" 3 ")
        user_dest = input("Digite o nome do Usuario para entrar: ")
        public_key_dest = f"./tmp/public/public_key_{user_dest}.pem"  # adiciona o caminho da chave publica
        path_dest = f"./tmp/messages/{user_dest}"  # adiciona o caminho da pasta para depois verificar se ela existe

        # Se a pasta path_dest existir, quero que liste os nomes das pastas dentro dela
        if os.path.exists(path_dest):
            print(f"Listando pastas dentro de {path_dest}:")
            subfolders = [f.path for f in os.scandir(path_dest) if f.is_dir()]
            if subfolders:
                for folder in subfolders:
                    print(os.path.basename(folder))
            else:
                print("Nenhuma pasta encontrada dentro de", path_dest)
        else:
            print(f"A pasta {path_dest} não existe.")
        
        user_remet = input("Digite o nome de um remetente valido " )    
        path_remet = f"./tmp/messages/{user_dest}/{user_remet}"
         # Se a pasta path_ do arquivo existir, quero que liste os nomes das pastas dentro dela
        if os.path.exists(path_remet):
            print(f"Listando pastas dentro de {path_remet}:")
            subfolders = [f.path for f in os.scandir(path_remet) if f.is_dir()]
            if subfolders:
                for folder in subfolders:
                    print(os.path.basename(folder))
            else:
                print("Nenhuma pasta encontrada dentro de", path_dest)
        else:
            print(f"A pasta {path_remet} não existe.")
        
        path_arq = input("Digite o nome de um arquivo valido " )      
        # encryp_algorithm = validate_encryp_algorithm() 
        open_envelope( user_remet, user_dest , path_arq )
    elif choice == '4':
        print("Saindo do programa. Até logo!")
        exit()
    else:
        print("Opção inválida. Tente novamente.")
        
