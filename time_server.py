import socket
import datetime
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP

# Generate or load the server's RSA key pair
private_key = RSA.generate(2048)
public_key = private_key.publickey()
with open("public_key_time.txt", "w") as f:
    f.write(private_key.export_key().decode())

def sign_message(message):
    h = SHA256.new(message.encode())
    signer = pkcs1_15.new(private_key)
    signature = signer.sign(h)
    return signature

def encrypt_with_private_key(message):
    cipher = PKCS1_OAEP.new(private_key)
    cipher_text = cipher.encrypt(message.encode())
    return base64.b64encode(cipher_text)

def get_current_time():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def serve():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8003))  # Change to your desired host and port
    server_socket.listen(1)
    print("Time server started.")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr}")

        try:
            current_time = get_current_time()
            encrypted_time = encrypt_with_private_key(current_time)
            signature = sign_message(current_time)

            # Send encrypted time and signature to the client
            client_socket.sendall(encrypted_time)
            client_socket.sendall(signature)
        except Exception as e:
            print("Error:",  e)
        finally:
            client_socket.close()

if __name__ == "__main__":
    serve()
