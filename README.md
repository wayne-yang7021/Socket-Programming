# Socket-Programming

## Introduction

This is a P2P (peer-to-peer) transaction program using C++! In this project, I implement secure communications and transactions using socket programming with OpenSSL for encryption and decryption. The program supports both server-side and client-side functionalities, ensuring data confidentiality and authenticity through public and private key cryptography.

## How to Execute the program

### 1. Generate Keys for Secure Communication

To enable secure communication between the server and clients, you need to generate the required keys. Execute the commands below to create the server's private key, public key, and self-signed certificate:

```
openssl genpkey -algorithm RSA -out server_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in server_private.pem -out server_public.pem
openssl req -new -x509 -key server_private.pem -out server_cert.pem -days 365
openssl genpkey -algorithm RSA -out server_key.pem -pkeyopt rsa_keygen_bits:2048
```

### 2. Generate Keys for P2P Transactions
Each client (e.g., Client B) participating in the P2P transaction system needs its own key pair. Use the following commands to generate a private and public key for a client:
```
openssl genpkey -algorithm RSA -out B_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in B_private.pem -out B_public.pem
```

### 3. Compile the Code
Use the commands below to compile the server and client programs. Adjust the paths for OpenSSL libraries and includes as necessary.
```
# Compile the server-side code
g++ -std=c++17 -o server server.cpp -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto

# Compile the client-side code
Client side: g++ -std=c++17 -o client client.cpp -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto
```
### 4. Run the Program
#### Start the Server
To start the server, execute the following command:
 ```
 ./server <port_number>
 ``` 
Replace `<port_number>` with the port you want the server to listen on (e.g., 8080).

#### Start the Client
To start the client, execute the following command:
```
./client <IP address> <port_number>
``` 
Replace `<IP_address>` with the server's IP address (e.g., 127.0.0.1 for localhost). 
Replace `<port_number>` with the port number the server is listening on.

### 5.Multi-Client Support
You can open multiple terminals and run the client program simultaneously to test multi-client functionality. Each client will have its own session and can perform operations such as:

1. Registering an account.
2. Logging in.
3. Listing online users.
4. Performing P2P transactions.

### 6.Features
**Secure Communication**: TLS/SSL ensures secure communication between the server and clients. <br>
**Public/Private Key Cryptography**: RSA is used for encrypting and decrypting messages and transactions. <br>
**P2P Transactions**: Clients can interact directly with each other for secure payments. <br>
**Multi-Client Support**: The server can handle multiple clients concurrently. <br>
