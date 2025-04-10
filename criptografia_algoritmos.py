
# --- CRIPTOGRAFIA COM CHAVE SIMÉTRICA (AES) ---
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def criptografia_simetrica_aes(mensagem):
    chave = get_random_bytes(16)
    cifra = AES.new(chave, AES.MODE_CBC)
    ct_bytes = cifra.encrypt(pad(mensagem.encode(), AES.block_size))
    return {
        'mensagem_original': mensagem,
        'mensagem_criptografada': ct_bytes,
        'chave': chave,
        'iv': cifra.iv
    }

# --- CRIPTOGRAFIA COM CHAVE ASSIMÉTRICA (RSA) ---
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def criptografia_assimetrica_rsa(mensagem):
    chave = RSA.generate(2048)
    chave_publica = chave.publickey()
    cifra = PKCS1_OAEP.new(chave_publica)
    mensagem_criptografada = cifra.encrypt(mensagem.encode())
    return {
        'mensagem_original': mensagem,
        'mensagem_criptografada': mensagem_criptografada,
        'chave_publica': chave_publica.export_key(),
        'chave_privada': chave.export_key()
    }

# --- FUNÇÃO HASH (SHA-256) ---
import hashlib

def funcao_hash_sha256(mensagem):
    hash_obj = hashlib.sha256()
    hash_obj.update(mensagem.encode())
    return hash_obj.hexdigest()

# --- EXEMPLOS DE USO ---
if __name__ == '__main__':
    texto = "Exemplo de mensagem"

    print("=== Criptografia Simétrica (AES) ===")
    resultado_aes = criptografia_simetrica_aes(texto)
    print(resultado_aes)

    print("\n=== Criptografia Assimétrica (RSA) ===")
    resultado_rsa = criptografia_assimetrica_rsa(texto)
    print(resultado_rsa)

    print("\n=== Função Hash (SHA-256) ===")
    resultado_hash = funcao_hash_sha256(texto)
    print("Hash:", resultado_hash)
