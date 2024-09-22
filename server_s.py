import socket
import time
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, DES
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
SERVER_IP = "127.0.0.1"
SERVER_PORT = 23456
REQ = "memo"
DATA = "take cis3319 class this morning"

# Checks the validity of timestamps. Exits the program if invalid timestamp.
def is_valid_timestamp(received_timestamp, max_time_difference=60):
    current_timestamp = int(time.time())
    time_difference = abs(current_timestamp - int(received_timestamp))
    if time_difference > max_time_difference:
        print("Error: Timestamp is not valid.")
        exit()

def step_1(ca_socket, ca_public_key, key_tmp1):
    # Create a message with RSAPKca[Ktmp1 || IDs || TS1]
    timestamp_1 = int(time.time())
    message_step_1 = f"{key_tmp1.hex()}||{ID_S}||{timestamp_1}"

    # Encrypt the message with CA's public key using RSA PKCS1_OAEP
    cipher_rsa = PKCS1_OAEP.new(ca_public_key)
    ciphertext_step_1 = cipher_rsa.encrypt(message_step_1.encode())

    # Send the encrypted message to CA
    ca_socket.sendall(ciphertext_step_1)

    # Print the information
    print(f"Step (1) - S->CA: {ciphertext_step_1.hex()}")
    print(f"\nSent Ktmp1: {key_tmp1.hex()}")

def step_4(client_socket, public_key_s, certificate_s):
    # Create a message with PKs || Certs || TS4
    timestamp_4 = int(time.time())
    message_step_4 = f"{public_key_s}||{certificate_s}||{timestamp_4}"

    # Encrypt the message to be sent to the client
    ciphertext_step_4 = message_step_4.encode()

    # Send the encrypted message to the client
    client_socket.sendall(ciphertext_step_4)

    print("\nStep (4) S->C:", message_step_4)

def step_6(client_socket, key_sess, key_tmp2):
    # Create a message with DESKtmp2[Ksess || Lifetimesess || IDc || TS6]
    timestamp_6 = int(time.time())
    message_step_6 = f"{key_sess.hex()}||{LIFETIME_SESS}||{ID_C}||{timestamp_6}"

    # Encrypt the message with the temporary DES key (Ktmp2)
    ciphertext_step_6 = des_encrypt(bytes.fromhex(key_tmp2), message_step_6.encode())

    # Send the encrypted message to the server
    client_socket.sendall(ciphertext_step_6)

    # Print the information
    print(f"\nStep (6) - S->C: {ciphertext_step_6.hex()}")
    print(f"\nSent Ksess: {key_sess.hex()}")

def step_8(client_socket, key_sess):
    # Create a message with DESKsess[data || TS8]
    timestamp_8 = int(time.time())
    message_step_8 = f"{DATA}||{timestamp_8}"

    # Encrypt the message with the session DES key (Ksess)
    ciphertext_step_8 = des_encrypt(key_sess, message_step_8.encode())

    # Send the encrypted message to the server
    client_socket.sendall(ciphertext_step_8)

    # Print the information
    print(f"\nStep (8) - S->C: {ciphertext_step_8.hex()}")
    print("\nSent data:", DATA)

# Create a socket to connect to the CA
ca_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ca_socket.connect(('127.0.0.1', 12345))

# Receive CA's public and private key from the CA
ca_public_key_data = ca_socket.recv(4096)
ca_public_key = RSA.import_key(ca_public_key_data)
ca_private_key_data = ca_socket.recv(4096)
ca_private_key = RSA.import_key(ca_private_key_data)
print("\nSuccessfully received CA's public and private key from CA\n")

# Generate a temporary DES key (Ktmp1)
key_tmp1 = get_random_bytes(8)

# Call the function for Step (1)
step_1(ca_socket, ca_public_key, key_tmp1)

# BEGIN STEP 2 FOR SERVER
# Receive the encrypted message from the CA
ciphertext_step_2 = ca_socket.recv(4096)
print("\nStep (2) - CA->S: server receives ciphertext message from CA")
print(f"Received ciphertext message from CA: {ciphertext_step_2.hex()}")

# Decrypt the message with Ktmp1 using DES
message_step_2 = des_decrypt(key_tmp1, ciphertext_step_2)
print("\nReceived plaintext message from CA:", message_step_2)

# Decode the bytes into a string
message_step_2_str = message_step_2.decode()

# Split the string using "||" as the delimiter
public_key_s, private_key_s, certificate_s, id_s_ca, timestamp_2 = message_step_2_str.split("||")

print("\nReceived public key s from CA:", public_key_s)
print("\nReceived private key s from CA:", private_key_s)
print("\nReceived Certs from CA:", certificate_s)

# Check the validity of TS2
is_valid_timestamp(timestamp_2)

# Close the socket
ca_socket.close()

# Create a socket for the server to wait for connections
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((SERVER_IP, SERVER_PORT))
server_socket.listen(1)

print(f"\nServer is listening on {SERVER_IP}:{SERVER_PORT}")

# Accept a connection from the client
client_socket, addr = server_socket.accept()
print(f"Connection established with {addr}")

# BEGIN STEP 3 FOR SERVER
# Receive the encrypted message from the client
ciphertext_step_3 = client_socket.recv(4096)
print("\nStep (3) - C->S: server receives ciphertext message from client")

# Decrypt the encrypted message from the client
message_step_3 = ciphertext_step_3.decode()

print("Received plaintext message from client:", message_step_3)

# Split the string using "||" as the delimiter
id_s_c, timestamp_3 = message_step_3.split("||")

# Check the validity of TS3
is_valid_timestamp(timestamp_3)

# Call the function for Step (4)
step_4(client_socket, public_key_s, certificate_s)

# Send CA's private key to the client
client_socket.sendall(ca_private_key_data)

# Convert private_key_s back into an RSA key object
private_key_bytes = private_key_s.encode('utf-8')
server_private_key = serialization.load_pem_private_key(private_key_bytes, password=None, backend=default_backend())

# Convert the private key so RSA PKCS1_OAEP can be used with it
private_key_pem = server_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Load the PEM representation back to an RSA object
rsa_key = RSA.import_key(private_key_pem.decode())

# BEGIN STEP 5 FOR SERVER
# Receive the encrypted message from the server
ciphertext_step_5 = client_socket.recv(4096)
print("\nStep (5) - C->S: server receives ciphertext message from client")
print(f"Received ciphertext message from server: {ciphertext_step_5.hex()}")

# Decrypt the message with CA's private key using RSA PKCS1_OAEP
cipher_rsa = PKCS1_OAEP.new(rsa_key)
message_step_5 = cipher_rsa.decrypt(ciphertext_step_5).decode()

print("\nReceived plaintext message from server:", message_step_5)

# Parse the decrypted message
key_tmp2, id_c, ip_c, port_c, timestamp_5 = message_step_5.split("||")

print("\nReceived Ktmp2 from client:", key_tmp2)

# Check the validity of TS5
is_valid_timestamp(timestamp_5)

# Generate a session DES key (Ksess)
key_sess = get_random_bytes(8)

# Call the function for Step (6)
step_6(client_socket, key_sess, key_tmp2)

# BEGIN STEP 7 FOR SERVER
# Receive the encrypted message from the server
ciphertext_step_7 = client_socket.recv(4096)
print("\nStep (7) - C->S: server receives ciphertext message from client")
print(f"Received ciphertext message from client: {ciphertext_step_7.hex()}")

# Decrypt the message with Ktmp2 using DES
message_step_7 = des_decrypt(key_sess, ciphertext_step_7)
print("\nReceived plaintext message from client:", message_step_7)

# Decode the bytes into a string
message_step_7_str = message_step_7.decode()

# Split the string using "||" as the delimiter
req, timestamp_7 = message_step_7_str.split("||")

print("\nReceived req from client:", req)

# Check the validity of TS7
is_valid_timestamp(timestamp_7)

# Call the function for Step (8)
step_8(client_socket, key_sess)

# Close the sockets
client_socket.close()
server_socket.close()