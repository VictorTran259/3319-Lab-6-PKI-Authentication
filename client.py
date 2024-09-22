import socket
import time
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from des import des_encrypt, des_decrypt

# Hardcoded values
ID_CA = "ID-CA"
ID_S = "ID-Server"
ID_C = "ID-Client"
IP_C = "127.0.0.1"
PORT_C = 5000
LIFETIME_SESS = 60
REQ = "memo"
DATA = "take cis3319 class this morning"

# Checks the validity of timestamps. Exits the program if invalid timestamp.
def is_valid_timestamp(received_timestamp, max_time_difference=60):
    current_timestamp = int(time.time())
    time_difference = abs(current_timestamp - int(received_timestamp))
    if time_difference > max_time_difference:
        print("Error: Timestamp is not valid.")
        exit()

# Reconstructs the certificate and then checks it against the received certificate from the server
def validate_certificate(received_certificate, public_key_s, ca_private_key):
    # Get the PEM-encoded string representation of the public key
    public_key_s_str = public_key_s.export_key().decode()

    # Recreate the certificate to test against the received certificate: Certs = SignSKca[IDs || IDca || PKs]
    recreated_certificate_data = f"{ID_S}||{ID_CA}||{public_key_s_str}"
    recreated_certificate = pkcs1_15.new(ca_private_key).sign(SHA256.new(recreated_certificate_data.encode())).hex()

    # Compare the received certificate with the recreated certificate
    if recreated_certificate == received_certificate:
        print("\nCertificate validation successful.")
    else:
        print("\nError: Certificate mismatch.")
        exit()

def step_3(server_socket):
    # Create a message with IDs || TS3
    timestamp_3 = int(time.time())
    message_step_3 = f"{ID_S}||{timestamp_3}"
    
    # Encrypt the message to be sent to the server
    ciphertext_step_3 = message_step_3.encode()

    # Send the encrypted message to the server
    server_socket.sendall(ciphertext_step_3)

    print("Step (3) - C->S:", message_step_3)

def step_5(server_socket, server_public_key, key_tmp2):
    # Create a message with RSAPKs[Ktmp2 || IDc || IPc || Portc || TS5]
    timestamp_5 = int(time.time())
    message_step_5 = f"{key_tmp2.hex()}||{ID_C}||{IP_C}||{PORT_C}||{timestamp_5}"

    # Encrypt the message with the server's public key using RSA PKCS1_OAEP
    cipher_rsa = PKCS1_OAEP.new(server_public_key)
    ciphertext_step_5 = cipher_rsa.encrypt(message_step_5.encode())

    # Send the encrypted message to the server
    server_socket.sendall(ciphertext_step_5)

    # Print the information
    print(f"\nStep (5) - C->S: {ciphertext_step_5.hex()}")
    print(f"\nSent Ktmp2: {key_tmp2.hex()}")

def step_7(server_socket, key_sess):
    # Create a message with DESKsess[req || TS7]
    timestamp_7 = int(time.time())
    message_step_7 = f"{REQ}||{timestamp_7}"

    # Encrypt the message with the session DES key (Ksess)
    ciphertext_step_7 = des_encrypt(bytes.fromhex(key_sess), message_step_7.encode())

    # Send the encrypted message to the server
    server_socket.sendall(ciphertext_step_7)

    # Print the information
    print(f"\nStep (7) - C->S: {ciphertext_step_7.hex()}")
    print("\nSent req:", REQ)

# Create a socket to connect to the server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.connect(('127.0.0.1', 23456))

# Call the function for Step (3)
step_3(server_socket)

# BEGIN STEP 4 FOR THE CLIENT
# Receive the encrypted message from the server
ciphertext_step_4 = server_socket.recv(4096)
print("\nStep (4) - S->C: client receives ciphertext message from server")

# Decrypt the encrypted message from the server
message_step_4 = ciphertext_step_4.decode()

print("Received plaintext message from server:", message_step_4)

# Split the string using "||" as the delimiter
public_key_s, certificate_s, timestamp_4 = message_step_4.split("||")

# Check the validity of TS4
is_valid_timestamp(timestamp_4)

# Receive CA's private key from server
ca_private_key_data = server_socket.recv(4096)
ca_private_key = RSA.import_key(ca_private_key_data)

# Convert public_key_s back into an RSA key object
public_key_bytes = public_key_s.encode('utf-8')
server_public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())

# Convert the public key so RSA PKCS1_OAEP can be used with it
public_key_pem = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Load the PEM representation back to an RSA object
rsa_key = RSA.import_key(public_key_pem.decode())

validate_certificate(certificate_s, rsa_key, ca_private_key)

# Generate a temporary DES key (Ktmp2)
key_tmp2 = get_random_bytes(8)

# Call the function for Step (5)
step_5(server_socket, rsa_key, key_tmp2)

# BEGIN STEP 6 FOR CLIENT
# Receive the encrypted message from the server
ciphertext_step_6 = server_socket.recv(4096)
print("\nStep (6) - S->C: client receives ciphertext message from server")
print(f"Received ciphertext message from server: {ciphertext_step_6.hex()}")

# Decrypt the message with Ktmp2 using DES
message_step_6 = des_decrypt(key_tmp2, ciphertext_step_6)
print("\nReceived plaintext message from server:", message_step_6)

# Decode the bytes into a string
message_step_6_str = message_step_6.decode()

# Split the string using "||" as the delimiter
key_sess, lifetime_sess, id_c, timestamp_6 = message_step_6_str.split("||")

print("\nReceived Ksess from server:", key_sess)

# Check the validity of TS6
is_valid_timestamp(timestamp_6)

# Call the function for Step (7)
step_7(server_socket, key_sess)

# BEGIN STEP 8 FOR SERVER
# Receive the encrypted message from the server
ciphertext_step_8 = server_socket.recv(4096)
print("\nStep (8) - S->C: client receives ciphertext message from server")
print(f"Received ciphertext message from server: {ciphertext_step_8.hex()}")

# Decrypt the message with Ktmp2 using DES
message_step_8 = des_decrypt(bytes.fromhex(key_sess), ciphertext_step_8)
print("\nReceived plaintext message from server:", message_step_8)

# Decode the bytes into a string
message_step_8_str = message_step_8.decode()

# Split the string using "||" as the delimiter
data, timestamp_8 = message_step_8_str.split("||")

print("\nReceived data from server:", data)

# Check the validity of TS8
is_valid_timestamp(timestamp_8)

# Close the socket
server_socket.close()
