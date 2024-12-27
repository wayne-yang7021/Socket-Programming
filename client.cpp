#include <iostream>
#include <string>
#include <sstream>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <thread>
#include <pthread.h>
#include <mutex>
#include <map>
#include <vector>
#include <algorithm>
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;

#define BUFFER_SIZE 1024

std::mutex console_mutex;
map<string, pair<string, int>> online_users;

int sockfd = -1;
SSL* ssl = nullptr;
EVP_PKEY* B_private_key = nullptr; // 用於 Client B
EVP_PKEY* B_public_key = nullptr;  // 用於 Client A (取得 B 的 public key)
EVP_PKEY* server_public_key = nullptr; // 用於 Client B 轉給 Server 時

// 加載公鑰
static EVP_PKEY* load_public_key(const char* pubkey_file) {
    FILE* fp = fopen(pubkey_file, "r");
    if (!fp) {
        perror("Failed to open public key file");
        return nullptr;
    }
    EVP_PKEY* pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    if (!pkey) {
        ERR_print_errors_fp(stderr);
        std::cerr << "Failed to load public key" << std::endl;
    }
    fclose(fp);
    return pkey;
}
// 加載私鑰
static EVP_PKEY* load_private_key(const char* privkey_file) {
    FILE* fp = fopen(privkey_file, "r");
    if (!fp) {
        perror("Failed to open private key file");
        return nullptr;
    }
    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (!pkey) {
        ERR_print_errors_fp(stderr);
        std::cerr << "Failed to load private key" << std::endl;
    }
    fclose(fp);
    return pkey;
}


// 公鑰加密
static std::string evp_public_encrypt(EVP_PKEY* pkey, const std::string& plaintext) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return "";
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0 || 
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return "";
    }
    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, 
                         reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return "";
    }
    std::vector<unsigned char> outbuf(outlen);
    if (EVP_PKEY_encrypt(ctx, outbuf.data(), &outlen, 
                         reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return "";
    }
    EVP_PKEY_CTX_free(ctx);
    return std::string(reinterpret_cast<char*>(outbuf.data()), outlen);
}

// 私鑰解密
static std::string evp_private_decrypt(EVP_PKEY* pkey, const std::string& ciphertext) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return "";
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0 || 
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return "";
    }
    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, 
                         reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size()) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return "";
    }
    std::vector<unsigned char> outbuf(outlen);
    if (EVP_PKEY_decrypt(ctx, outbuf.data(), &outlen, 
                         reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size()) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return "";
    }
    EVP_PKEY_CTX_free(ctx);
    return std::string(reinterpret_cast<char*>(outbuf.data()), outlen);
}

int my_port = 0;
string my_username;

void update_online_users() {
    SSL_write(ssl, "List", 4);
    char buffer[BUFFER_SIZE] = {};
    int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes_received > 0) {
        std::lock_guard<std::mutex> lock(console_mutex);
        cout << buffer << endl;
        online_users.clear();
        stringstream ss(buffer);
        string line;
        vector<string> lines;
        while (getline(ss, line, '\n')) {
            lines.push_back(line);
        }
        if (lines.size() < 3) {
            cerr << "Response format invalid. Not enough data." << endl;
            return;
        }
        for (size_t i = 3; i < lines.size(); ++i) {
            stringstream line_stream(lines[i]);
            string username, ip, port_str;
            if (getline(line_stream, username, '#') &&
                getline(line_stream, ip, '#') &&
                getline(line_stream, port_str)) {
                try {
                    int port = stoi(port_str);
                    online_users[username] = make_pair(ip, port);
                } catch (const invalid_argument& e) {
                    cerr << "Invalid port number in line: " << lines[i] << endl;
                }
            } else {
                cerr << "Invalid format in line: " << lines[i] << endl;
            }
        }
    } else {
        std::cerr << "Failed to receive user list from server.\n";
    }
}

void* handle_transfer(void* args) {
    int* sockets = (int*)args;
    int server_sd = sockets[0];
    int local_sd = sockets[1];
    while (true) {
        sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sd = accept(local_sd, (struct sockaddr*)&client_addr, &client_len);
        if (client_sd < 0) {
            std::cerr << "Failed to accept connection from client.\n";
            continue;
        }
        char received[BUFFER_SIZE] = {};
        int recv_len = recv(client_sd, received, sizeof(received), 0);
        if (recv_len > 0) {
            std::string encrypted_msg(received, recv_len);
            string decrypted_msg = evp_private_decrypt(B_private_key, encrypted_msg);
            if (decrypted_msg.empty()) {
                cerr << "Failed to decrypt message with private key." << endl;
                continue;
            }
            {
                std::lock_guard<std::mutex> lock(console_mutex);
                std::cout << "Received P2P encrypted message: " << decrypted_msg << std::endl;
            }

            if (SSL_write(ssl, decrypted_msg.data(), decrypted_msg.size()) < 0) {
                std::cerr << "Failed to forward P2P message to server.\n";
            }
            char trans_reply[BUFFER_SIZE] = {};
            int bytes_received = SSL_read(ssl, trans_reply, sizeof(trans_reply));
            cout << trans_reply << endl;

            if (send(client_sd, trans_reply, strlen(trans_reply), 0) < 0) {
                std::cerr << "Failed to forward P2P message back to sender.\n";
            }
        } else {
            std::cerr << "Failed to receive message from P2P connection.\n";
        }
        close(client_sd);
    }
    close(local_sd);
    return nullptr;
}

SSL_CTX* create_client_context() {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        cerr << "Usage: ./client <server_ip> <server_port>" << endl;
        return -1;
    }

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();

    SSL_CTX* ctx = create_client_context();

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        std::cerr << "Fail to create the socket.\n";
        return EXIT_FAILURE;
    }
    char* server_ip = argv[1];
    int server_port = std::stoi(argv[2]);

    sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    server_addr.sin_port = htons(server_port);

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Connection failed");
        close(sockfd);
        return EXIT_FAILURE;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(sockfd);
        return EXIT_FAILURE;
    }

    cout << "Connected to the server!\n";
    cout << "Welcome to p2p transaction system!" << endl;
    cout << "Please enter the command below to continue:" << endl;
    cout << "------------------------------------------" << endl;
    cout << "1. Enter 'Register' to register an account" << endl;
    cout << "2. Enter 'Login' to continue login process" << endl;
    cout << "3. Enter 'Exit' to terminate the service" << endl; 

    // 載入必要的金鑰
    B_private_key = load_private_key("B_private.pem");
    B_public_key = load_public_key("B_public.pem");
    server_public_key = load_public_key("server_public.pem");

    while (true) {
        string input;
        cout << "> ";
        getline(cin, input);

        if (input == "Exit") {
            SSL_write(ssl, input.c_str(), input.size());
            char buf[BUFFER_SIZE] = {};
            SSL_read(ssl, buf, sizeof(buf));
            cout << buf;
            cout << "Client exiting...\n";
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sockfd);
            return 0;
        } else if (input == "Register"){
            string username = "";
            cout << "Please enter your username: ";
            cin >> username;
            string send_str = "REGISTER#" + username;
            SSL_write(ssl, send_str.c_str(), send_str.size());
            char register_buffer[BUFFER_SIZE] = {};
            SSL_read(ssl, register_buffer, sizeof(register_buffer));
            cout << register_buffer;
        } else if (input == "Login") {
            string port_num = "";
            string username = "";
            cout << "Please enter your username: ";
            cin >> username;
            cout << "Please choose a port(1024 ~ 65535): ";
            cin >> port_num; 
            int port = stoi(port_num);
            my_port = port;
            string sent_str = username + "#" + port_num;
            SSL_write(ssl, sent_str.c_str(), sent_str.size());
            char login_buffer[BUFFER_SIZE] = {};
            SSL_read(ssl, login_buffer, sizeof(login_buffer));
            cout << login_buffer;
            if (strstr(login_buffer, "AUTH_FAIL") == NULL) {
                my_username = username;
                break;
            }
        }
    }

    int listener_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listener_sock == -1) {
        cerr << "Failed to create P2P listener socket.\n";
        return EXIT_FAILURE;
    }

    sockaddr_in local_addr = {};
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    local_addr.sin_port = htons(my_port);

    if (::bind(listener_sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        cerr << "Failed to bind P2P listener socket.\n";
        close(listener_sock);
        return EXIT_FAILURE;
    }

    if (listen(listener_sock, 10) == -1) {
        cerr << "Failed to listen on P2P port.\n";
        close(listener_sock);
        return EXIT_FAILURE;
    }

    int sockets[2] = {sockfd, listener_sock};
    pthread_t transfer_thread;
    if (pthread_create(&transfer_thread, nullptr, handle_transfer, (void*)sockets) != 0) {
        cerr << "Failed to create thread!" << endl;
        return EXIT_FAILURE;
    }
    pthread_detach(transfer_thread);

    cout << "Login successfully! Welcome to p2p transaction system~" << endl;
    cout << "Please enter the command below to continue:" << endl;
    cout << "------------------------------------------" << endl;
    cout << "1. Enter 'List' to get the online users list(use this after login)" << endl;
    cout << "2. Enter 'Transaction' to process a transaction(use after login)" << endl;
    cout << "3. Enter 'Exit' to terminate the service" << endl;

    while (true) {
        string input;
        cin >> input;
        if (input == "Transaction") {
            string sender, recipient, amount_str;
            cout << "Please enter the sender name(your user name): ";
            cin >> sender;
            cout << "Please enter the recipient name: ";
            cin >> recipient;
            cout << "Please enter the amount you want to transfer: ";
            cin >> amount_str;
            
            cout << "Auto fetch online users list before transfer..." << endl;
            update_online_users();
            if (online_users.find(recipient) == online_users.end()) {
                {
                    std::lock_guard<std::mutex> lock(console_mutex);
                    std::cout << "Recipient not online.\n";
                }
                continue;
            }

            string recipient_ip = online_users[recipient].first;
            int recipient_port = online_users[recipient].second;

            int trans_sock = socket(AF_INET, SOCK_STREAM, 0);
            if (trans_sock == -1) {
                std::lock_guard<std::mutex> lock(console_mutex);
                std::cout << "Failed to create P2P socket.\n";
                continue;
            }

            sockaddr_in recipient_addr;
            memset(&recipient_addr, 0, sizeof(recipient_addr));
            recipient_addr.sin_family = AF_INET;
            recipient_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
            recipient_addr.sin_port = htons(recipient_port);

            if (connect(trans_sock, (struct sockaddr*)&recipient_addr, sizeof(recipient_addr)) < 0) {
                cout << "Failed to connect to recipient." << endl;
                close(trans_sock);
                continue;
            }

            string sent_str = sender + "#" + amount_str + "#" + recipient;

            string encrypted_msg = evp_public_encrypt(B_public_key, sent_str);
            send(trans_sock, encrypted_msg.data(), encrypted_msg.size(), 0);
            char trans_reply[BUFFER_SIZE] = {};
            int bytes_received = recv(trans_sock, trans_reply, sizeof(trans_reply), 0);
            if (bytes_received > 0) {
                cout << "Received response: " << trans_reply << endl;
            } else {
                std::cerr << "Failed to receive response from recipient." << std::endl;
            }

            close(trans_sock);
        } else if (input == "List" || input == "Exit") {
            SSL_write(ssl, input.c_str(), input.size());
            char buffer[BUFFER_SIZE] = {};
            SSL_read(ssl, buffer, sizeof(buffer));
            cout << buffer << endl;
            if (input == "Exit") {
                pthread_join(transfer_thread, nullptr);
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(sockfd);
                cout << "Client exiting...\n";
                return 0;
            }
        }else{
            cout << "Can't recognize the command, please re-enter it!" << endl;
            continue;
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(listener_sock);
    close(sockfd);
    return 0;
}
