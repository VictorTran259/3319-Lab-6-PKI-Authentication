import socket
import time
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, DES
from des import des_encrypt, des_decrypt

# Hardcoded values
CA_SERVER_IP = "127.0.0.1"
CA_SERVER_PORT = 12345
ID_CA = "ID-CA"
ID_S = "ID-Server"
ID_C = "ID-Client"
IP_C = "127.0.0.1"
PORT_C = 5000
LIFETIME_SESS = 60

# Checks the validity of timestamps. Exits the program if invalid timestamp.
def is_valid_timestamp(received_timestamp, max_time_difference=60):
    current_timestamp = int(time.time())
    time_difference = abs(current_timestamp - int(received_timestamp))
    if time_difference > max_time_difference:
        print("Error: Timestamp is not valid.")
        exit()

def step_1_and_2_ca(server_socket, ca_private_key):
    # BEGIN STEP 1 FOR CA
    # Receive the encrypted message from the server
    ciphertext_step_1 = server_socket.recv(4096)
    print("Step (1) - S->CA: CA receives ciphertext message from server")
    print(f"Received ciphertext message from server: {ciphertext_step_1.hex()}")

    # Decrypt the message with CA's private key using RSA PKCS1_OAEP
    cipher_rsa = PKCS1_OAEP.new(ca_private_key)
    message_step_1 = cipher_rsa.decrypt(ciphertext_step_1).decode()

    print("\nReceived plaintext message from server:", message_step_1)

    # Parse the decrypted message
    key_tmp1, id_s, timestamp_1 = message_step_1.split("||")

    print("\nReceived Ktmp1 from server:", key_tmp1)

    # Check the validity of TS1
    is_valid_timestamp(timestamp_1)

    # BEGIN STEP 2 FOR CA
    # Generate public/private key pair and certificate for the application server S
    key_pair_s = RSA.generate(2048)
    public_key_s = key_pair_s.publickey().export_key().decode()
    private_key_s = key_pair_s.export_key().decode()

    # Create a certificate for S: Certs = SignSKca[IDs || IDca || PKs]
    certificate_s_data = f"{id_s}||{ID_CA}||{public_key_s}"
    certificate_s = pkcs1_15.new(ca_private_key).sign(SHA256.new(certificate_s_data.encode())).hex()

    # Create a message with DESKtmp1[PKs || SKs || Certs || IDs || TS2]
    timestamp_2 = int(time.time())
    message_step_2 = f"{public_key_s}||{private_key_s}||{certificate_s}||{id_s}||{timestamp_2}"

    # Encrypt the message with the temporary DES key (Ktmp1)
    ciphertext_step_2 = des_encrypt(bytes.fromhex(key_tmp1), message_step_2.encode())

    # Send the encrypted message to the server
    server_socket.sendall(ciphertext_step_2)

    # Print the information
    print(f"\nStep (2) - CA->S: {ciphertext_step_2.hex()}")
    print(f"\nSent Public Key S: {public_key_s}")
    print(f"\nSent Private Key S: {private_key_s}")
    print(f"\nSent Certs: {certificate_s}")

# Create a socket for the CA server to wait for connections
ca_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ca_server_socket.bind((CA_SERVER_IP, CA_SERVER_PORT))
ca_server_socket.listen(1)

print(f"CA server is listening on {CA_SERVER_IP}:{CA_SERVER_PORT}")

# Accept a connection from the application server
server_socket, addr = ca_server_socket.accept()
print(f"Connection established with {addr}")

# Generate CA's public/private key pair
key_pair_ca = RSA.generate(2048)
public_key_ca = key_pair_ca.publickey().export_key()
private_key_ca = key_pair_ca.export_key()

# Send CA's public key to the server
print("\nSending CA's public and private key to the server\n")
server_socket.sendall(public_key_ca)
server_socket.sendall(private_key_ca)

# Call the function for Step (2)
step_1_and_2_ca(server_socket, key_pair_ca)

# Close the sockets
server_socket.close()
ca_server_socket.close()
