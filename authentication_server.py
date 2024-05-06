import socket
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import pickle

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

class AuthenticationServer:
    def __init__(self):
        self.users = {}

    def add_user(self, username, password):
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        self.users[username] = password_hash

    def authenticate(self, username, password):
        if username in self.users:
            if self.users[username] == hashlib.sha256(password.encode()).hexdigest():
                return True
        return False

def main():
    auth_server = AuthenticationServer()
    auth_server.add_user("police", "password123")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8000))
    server_socket.listen(1)

    print("Authentication Server running...")

    while True:
        client_socket, address = server_socket.accept()
        print(f"Connection from {address} established.")

        request = client_socket.recv(1024).decode()
        username, password = request.split(',')

        if auth_server.authenticate(username, password):
            K_C = get_random_bytes(16)
            f = open("K_C.txt", "w")
            f.write(str(K_C))
            f.close()
            K_C_tgs = get_random_bytes(16)
            f = open("K_C_tgs.txt", "w")
            f.write(str(K_C_tgs))
            f.close()
            K_tgs = get_random_bytes(16)
            f = open("K_tgs.txt", "w")
            f.write(str(K_tgs))
            f.close()
            #Ticket
            T_tgs=aes_encrypt(K_tgs,(K_C_tgs))
            data = (K_C_tgs, T_tgs)
            encrypted_data = aes_encrypt(K_C, data)
            client_socket.send(encrypted_data)

        else:
            client_socket.send("Authentication failed".encode())

        client_socket.close()

if __name__ == "__main__":
    main()
