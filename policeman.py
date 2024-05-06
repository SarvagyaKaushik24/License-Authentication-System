import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import pickle
import time
import datetime
from cryptography.fernet import Fernet
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

with open("public_key_time.txt", "r") as fi:
    public_key_string = fi.read()
    public_key_time = RSA.import_key(public_key_string.encode())

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

def verify_signature(data, signature, public_key):
    data_bytes = pickle.dumps(data)
    verifier = PKCS1_v1_5.new(public_key)
    digest = SHA256.new()
    digest.update(data_bytes)
    if verifier.verify(digest, signature):
        return True
    else:
        return False

def verify_time_signature(message, signature):
    h = SHA256.new(message.encode())
    verifier = PKCS1_v1_5.new(public_key_time)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def decrypt_with_public_key(cipher_text):
    cipher = PKCS1_OAEP.new(public_key_time)
    decoded_cipher_text = base64.b64decode(cipher_text)
    return cipher.decrypt(decoded_cipher_text).decode()

def get_time_from_server(host, port):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((host, port))
        # Receive encrypted time and signature from server
        encrypted_time = client_socket.recv(1024)
        signature = client_socket.recv(1024)
        # Decrypt time
        decrypted_time = decrypt_with_public_key(encrypted_time)
        # Verify signature
        if verify_time_signature(decrypted_time, signature):
            return decrypted_time
        else:
            return "Signature verification failed"
    # except Exception as e:
    #     print("Error:", e)
    finally:
        client_socket.close()

def main():
    username = str(input("Enter Username: "))
    password = str(input("Enter Password: "))
    
    auth_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    auth_socket.connect(('localhost', 8000))
    auth_socket.send(f"{username},{password}".encode())

    auth_result = auth_socket.recv(1024)
    file1 = open('K_C.txt', 'r')
    for line in file1:
        key=line.strip().encode()
    
    K_C_tgs, T_tgs = aes_decrypt(eval(key),auth_result)
    auth_socket.close()
    authenticator_c = aes_encrypt(K_C_tgs,(username,time.time()))
    data = (T_tgs, authenticator_c)
    tgs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tgs_socket.connect(('localhost', 8001))
    serialized_data = pickle.dumps(data)
    tgs_socket.send(serialized_data)
    encrypted_data = tgs_socket.recv(1024)
    K_C_v, T_v = aes_decrypt(K_C_tgs,encrypted_data)
    tgs_socket.close()
    authenticator_c = aes_encrypt(K_C_v,(username,time.time()))
    data = (T_v, authenticator_c)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect(('localhost', 8002))
    serialized_data = pickle.dumps(data)
    server_socket.send(serialized_data)
    encrypted_data = server_socket.recv(1024)
    auth_result = aes_decrypt(K_C_v,encrypted_data)
    if auth_result == "Authenticated":
        # Now, police officer can use the obtained session_key to communicate with service provider
        # Here we simulate sending license verification request to service provider
        inp = str(input("Enter the licence number you want to verify: "))
        license_number = (inp,get_time_from_server('localhost',8003))
        encrypted_data = aes_encrypt(K_C_v,license_number)
        server_socket.send(encrypted_data)
        personal_data = server_socket.recv(1024)
        (Name, DOB, date_time), signature = aes_decrypt(K_C_v,personal_data)
        with open("public_key_service.txt", "r") as f:
            public_key_str = f.read()
            public_key = RSA.import_key(public_key_str.encode())
        date_timer = datetime.datetime.strptime(date_time, "%Y-%m-%d %H:%M:%S")
        current_time = datetime.datetime.now()
        # Calculate the time difference
        time_difference = abs((date_timer - current_time).total_seconds())
        if  time_difference>1 or (not verify_signature((Name,DOB),signature,public_key)):
            print("This secure connection has been compromised and the data has been tampered")
            return
        
        if Name=="Not Verified":
            print("The Licence is not legitimate.")
        else:
            print("Name: ", Name) 
            print("Date of Birth: ", DOB)
            received_data = b''
            while True:
                chunk = server_socket.recv(4096)
                if not chunk:
                    break
                received_data += chunk
            file1 = open('K_img.txt', 'r')
            for line in file1:
                key=line.strip().encode()
            cipher_suite = Fernet(eval(key))
            decrypted_data = cipher_suite.decrypt(received_data)
            received_image_file = "received_image.jpg"
            with open(received_image_file, "wb") as f:
                f.write(decrypted_data)
        
        
    else:
        print("Authentication failed")
    server_socket.close()

if __name__ == "__main__":
    main()
