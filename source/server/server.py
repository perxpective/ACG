import socket
import sys
import traceback
import base64
import pickle
import random
from threading import Thread
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA256

def decode(string):
    string2 = ""
    for byte in string:
        string2 += str(byte)
    return string2

def receive_input(connection, max_buffer_size):
   client_input = connection.recv(max_buffer_size)
   file_dictionary = pickle.loads(client_input)
   client_input_size = sys.getsizeof(client_input)
   if client_input_size > max_buffer_size:
      print("The input size is greater than expected {}".format(client_input_size))
   return file_dictionary

global decrypt_aes_key
# Function to decrypt AES key using private key of server
def decrypt_aes_key(encrypted_key):
    private_key_bytes = open("./depolyment/server_private.pem", "rb").read()
    server_private_key = RSA.import_key(private_key_bytes)
    cipher = PKCS1_OAEP.new(server_private_key)
    decrypted_aes_key = cipher.decrypt(encrypted_key)
    return decrypted_aes_key

global decryption
# Function to decrypt encrypted image
def decryption(encrypted, aes_key, iv):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypt = cipher.decrypt(encrypted)
    decrypt = unpad(decrypt, 16)
    decrypted = decrypt.decode()
    return decrypted

global verify
def verify(signature, digest):
    camera_public_key_bytes = open("./depolyment/camera_public.pem", "rb").read()
    camera_public_key = RSA.import_key(camera_public_key_bytes)
    verifier = pkcs1_15.new(camera_public_key)
    try:
        verifier.verify(digest, signature)
        print("Signature is valid.")
        return True
    except:
        print("Signature is invalid.")
        return False

# Function to generate a message digest for image
def get_digest(image):
    message_digest = SHA256.new()
    message_digest.update(image.encode())
    return message_digest

# Function to generate a signature by using camera private key and digest
def sign(digest):
    # Import camera private key
    private_key_bytes = open("./depolyment/camera_private.pem", "rb").read()
    private_key = RSA.import_key(private_key_bytes)
    signer = PKCS1_v1_5.new(private_key)
    signature = signer.sign(digest)
    return signature

def clientThread(connection, ip, port, max_buffer_size=5120):
   is_active = True
   while is_active:
        file_dictionary = receive_input(connection, max_buffer_size)
        if "QUIT" in file_dictionary:
            print("Connection closed.")
            is_active = False

        if "Filename" in file_dictionary:
            new_dictionary = {}
            global write_filename
            filename = file_dictionary["Filename"]
            new_dictionary["Filename"] = file_dictionary["Filename"]
        elif "EncryptedCameraID" in file_dictionary:
            global encrypted_camera_id
            print(f"Received encrypted ID!")
            new_dictionary["EncryptedCameraID"] = file_dictionary["EncryptedCameraID"]
        elif "EncryptedImage" in file_dictionary:
            print(f"Received encrypted image!")
            new_dictionary["EncryptedImage"] = file_dictionary["EncryptedImage"]
        elif "EncryptedAESKey" in file_dictionary:
            new_dictionary["EncryptedAESKey"] = file_dictionary["EncryptedAESKey"]
            print(f"Received AES Key!")
        elif "IV" in file_dictionary:
            new_dictionary["IV"] = file_dictionary["IV"]
            print(f"Received IV!")

            encrypted_aes_key = new_dictionary["EncryptedAESKey"]
            encrypted_image = new_dictionary["EncryptedImage"]
            encrypted_camera_id = new_dictionary["EncryptedCameraID"]
            iv = new_dictionary["IV"]
            decrypted_aes_key = decrypt_aes_key(encrypted_aes_key)
            decrypted_image = decryption(encrypted_image, decrypted_aes_key, iv)
            digest = get_digest(decrypted_image)
            signature = sign(digest)
            filename = decryption(filename, decrypted_aes_key, iv)
            write_filename = "./source/server/data/" + filename
            camera_id = decryption(encrypted_camera_id, decrypted_aes_key, iv)
            rng = random.randint(1, 10)
            if rng >= 7:
                digest = SHA256.new("wrongmess".encode())   # Simulate failed signature verification
            
            verify_signature = verify(signature, digest)
            if verify_signature == True:
                with open(write_filename, "wb") as file:
                    file.write(base64.urlsafe_b64decode(decrypted_image))
                    connection.sendall("Server received.".encode())
                with open("./depolyment/audit_log.txt", "a") as file:
                    file.write("[RECEIVED] " + write_filename  + " [VERIFIED] from " + camera_id + "\n")


            else:
                print("Signature Verification Failed. Cannot write file to data...")
                connection.sendall("Signature Verification Failed. Cannot write file to data...".encode())
                with open("./depolyment/audit_log.txt", "a") as file:
                    file.write("[RECEIVED] " + write_filename + " [FAILED VERIFICATION] from " + camera_id + "\n")


host = "127.0.0.1"
port = 8000  # arbitrary non-privileged port
soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
print("Socket created")
try:
    soc.bind((host, port))
except:
    print("Bind failed. Error : " + str(sys.exc_info()))
    sys.exit()

soc.listen(6)  # queue up to 6 requests
print("Socket now listening")

# infinite loop- do not reset for every requests
while True:
    connection, address = soc.accept()
    ip, port = str(address[0]), str(address[1])
    print("Connected with " + ip + ":" + port)

    try:
        Thread(target=clientThread, args=(connection, ip, port)).start()
    except:
        print("Thread did not start.")
        traceback.print_exc()

soc.close()


