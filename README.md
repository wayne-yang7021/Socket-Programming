# Socket-Programming

## Introduction

This is a p2p transaction program! In this program, I use

## How to Execute the program

In order to create the key to implement secure transaction, please execute the command below to create the key:

```
openssl genpkey -algorithm RSA -out server_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in server_private.pem -out server_public.pem
openssl req -new -x509 -key server_private.pem -out server_cert.pem -days 365
openssl genpkey -algorithm RSA -out server_key.pem -pkeyopt rsa_keygen_bits:2048
```

To generate the key for p2p transaction:
```
openssl genpkey -algorithm RSA -out B_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in B_private.pem -out B_public.pem
```

Last, to execute the program, please execute the following command to compile the code:
```
Server side: g++ -std=c++17 -o server server.cpp -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto
Client side: g++ -std=c++17 -o client client.cpp -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto
```

To run the code, run `./server <port_number>` to implement the server.
For client side, run `./client <IP address> <port_number>` to implement the client, you can also open multiple terminals to do the multi-client service.