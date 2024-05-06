import socket
import random
import pickle
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_data = cipher.encrypt(pad(pickle.dumps(data), AES.block_size))
    return iv + encrypted_data

def aes_decrypt(key, encrypted_data):
    iv = encrypted_data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
    return pickle.loads(decrypted_data)
class TicketGrantingServer:
    def __init__(self):
        self.sessions = {}

    def generate_session_key(self):
        return ''.join(random.choice('0123456789ABCDEF') for i in range(16))

def main():
    tgs_server = TicketGrantingServer()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8001))
    server_socket.listen(1)

    print("Ticket Granting Server running...")

    while True:
        client_socket, address = server_socket.accept()
        print(f"Connection from {address} established.")
        serialized_data = client_socket.recv(1024)
        T_tgs, authenticator_c = pickle.loads(serialized_data)
        file1 = open('K_tgs.txt', 'r')
        for line in file1:
            key=line.strip().encode()
        K_C_tgs = aes_decrypt(eval(key),T_tgs)
        if aes_decrypt(K_C_tgs,authenticator_c)[0] == "police":
            K_v = get_random_bytes(16)
            f = open("K_v.txt", "w")
            f.write(str(K_v))
            f.close()
            K_C_v = get_random_bytes(16)
            f = open("K_C_v.txt", "w")
            f.write(str(K_C_v))
            f.close()
            T_v=aes_encrypt(K_v,(K_C_v))
            data = (K_C_v, T_v)
            encrypted_data = aes_encrypt(K_C_tgs,data)
            client_socket.send(encrypted_data)
        else:
            print("Client not authorised.")
        client_socket.close()

if __name__ == "__main__":
    main()
