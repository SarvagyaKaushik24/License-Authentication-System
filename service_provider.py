import socket
import pickle
import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.fernet import Fernet
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import base64
from Crypto.PublicKey import RSA

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

def sign_data(data, private_key):
    data_bytes = pickle.dumps(data)
    signer = PKCS1_v1_5.new(private_key)
    digest = SHA256.new()
    digest.update(data_bytes)
    signature = signer.sign(digest)
    return signature

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

class ServiceProvider:
    def __init__(self):
        self.numbers = ("ABC123","XYZ456")
    def verify_license_number(self, license_number):
        if license_number in self.numbers:
            return f"License number {license_number} verified successfully",1
        else:
            return f"License number {license_number} is not verified",0

def main():
    service_provider = ServiceProvider()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8002))
    server_socket.listen(1)

    print("Service Provider running...")

    while True:
        client_socket, address = server_socket.accept()
        print(f"Connection from {address} established.")

        serialized_data = client_socket.recv(1024)
        data = pickle.loads(serialized_data)
        T_v, authenticator_c = data
        file1 = open('K_v.txt', 'r')
        for line in file1:
            key=line.strip().encode()
        K_C_v = aes_decrypt(eval(key),T_v)
        if aes_decrypt(K_C_v,authenticator_c)[0] == "police":
            data=aes_encrypt(K_C_v,("Authenticated"))
            client_socket.send(data)
            encrypted_data = client_socket.recv(1024)
            license_number,date_time = aes_decrypt(K_C_v,encrypted_data)
            print(date_time)
            date_time = datetime.datetime.strptime(date_time, "%Y-%m-%d %H:%M:%S")
            current_time = datetime.datetime.now()
            # Calculate the time difference
            time_difference = abs((date_time - current_time).total_seconds())
            if time_difference <= 1:
                output,flag = service_provider.verify_license_number(license_number)
                print(output)
                if flag==1:
                    if license_number=="ABC123":
                        private_key = RSA.generate(2048)
                        public_key = private_key.publickey()
                        with open("public_key_service.txt", "w") as f:
                            f.write(public_key.export_key().decode())
                        
                        data = ("Sarvagya Kaushik", "10/02/2001",get_time_from_server('localhost',8003))
                        signature = sign_data(("Sarvagya Kaushik", "10/02/2001"), private_key)
                        personal_data = aes_encrypt(K_C_v,(data,signature))
                        client_socket.send(personal_data)
                        key=Fernet.generate_key()
                        f = open("K_img.txt", "w")
                        f.write(str(key))
                        f.close()
                        cipher_suite = Fernet(key)
                        image_file = "private_data/Sarvagya.jpg"
                        with open(image_file, "rb") as f:
                            image_data = f.read()
                        encrypted_data = cipher_suite.encrypt(image_data)
                        client_socket.send(encrypted_data)
                    if license_number=="XYZ456":
                        private_key = RSA.generate(2048)
                        public_key = private_key.publickey()
                        with open("public_key_service.txt", "w") as f:
                            f.write(public_key.export_key().decode())
                        
                        data = ("Kunal Sharma", "20/02/2002",get_time_from_server('localhost',8003))
                        signature = sign_data(("Kunal Sharma", "20/02/2002"), private_key)
                        personal_data = aes_encrypt(K_C_v,(data,signature))
                        client_socket.send(personal_data)
                        key=Fernet.generate_key()
                        f = open("K_img.txt", "w")
                        f.write(str(key))
                        f.close()
                        cipher_suite = Fernet(key)
                        image_file = "private_data/Kunal.jpg"
                        with open(image_file, "rb") as f:
                            image_data = f.read()
                        encrypted_data = cipher_suite.encrypt(image_data)
                        client_socket.send(encrypted_data)
                else:
                    data = ("Not Verified", "00/00/0000")
                    personal_data = aes_encrypt(K_C_v,data)
                    client_socket.send(personal_data)
        else:
            print("Client not authorised")
        client_socket.close()

if __name__ == "__main__":
    main()
