#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <queue>
#include <condition_variable>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/err.h>
// #include "common_crypto.hpp"

using namespace std;

struct UserInfo {
    bool login = false;
    string ip;
    int port;
    string username;
    int balance = 10000;
    UserInfo(bool login, const string& ip, int port, const string& username, int balance)
        : login(login), ip(ip), port(port), username(username), balance(balance) {}
    UserInfo() = default;
};

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


unordered_map<int, string> clientToUserMap; 
mutex clientMapMutex; 
unordered_map<string, UserInfo> userAccounts; 
mutex userMutex;
queue<int> taskQueue; 
mutex queueMutex;
condition_variable condVar;

EVP_PKEY* server_private_key = nullptr;

SSL_CTX* create_server_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if(!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_server_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);
    if (SSL_CTX_use_certificate_file(ctx, "server_cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "server_key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void handleClient(SSL* ssl) {
    char buffer[1024] = {};
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytesReceived = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytesReceived <= 0) {
            cout << "Client disconnected." << endl;
            SSL_shutdown(ssl);
            SSL_free(ssl);
            break;
        }

        string message(buffer, bytesReceived);
        cout << "Received message: " << message << endl;

        size_t pos1 = message.find("#");
        size_t pos2 = message.find("#", pos1 + 1);

        if (message.find("REGISTER#") == 0) {
            string username = message.substr(9);
            lock_guard<mutex> lock(userMutex);
            if (userAccounts.find(username) == userAccounts.end()) {
                userAccounts[username] = UserInfo(false, "127.0.0.1", 0, username, 10000);
                SSL_write(ssl, "100 OK\r\n", 8);
            } else {
                SSL_write(ssl, "210 FAIL\r\n", 10);
            }
        } else if (message.find("#") != string::npos && pos2 == string::npos) {
            string username = message.substr(0, pos1);
            int port = stoi(message.substr(pos1 + 1));
            lock_guard<mutex> lock(userMutex);
            if (port > 65535 || port < 1024) {
                SSL_write(ssl, "Invalid port range.\r\n", 21);
                continue;
            }
            if (userAccounts.find(username) != userAccounts.end()) {
                userAccounts[username].login = true;
                userAccounts[username].ip = "127.0.0.1";
                userAccounts[username].port = port;

                {
                    lock_guard<mutex> lockMap(clientMapMutex);
                    clientToUserMap[SSL_get_fd(ssl)] = username;
                }

                int balance = userAccounts[username].balance;
                string online_list;
                int onlineCount = 0;

                for (const auto& user : userAccounts) {
                    if (user.second.login) {
                        online_list += user.first + "#" + user.second.ip + "#" + to_string(user.second.port) + "\r\n";
                        onlineCount++;
                    }
                }
                string response = to_string(balance) + "\n<serverPublicKey>\r\n" + to_string(onlineCount) + "\n" + online_list;
                SSL_write(ssl, response.c_str(), response.size());
            } else {
                SSL_write(ssl, "220 AUTH_FAIL\r\n", 16);
            }
        } else if (message == "List") {
            string username;
            int balance = 0;
            {
                lock_guard<mutex> lock(clientMapMutex);
                if (clientToUserMap.find(SSL_get_fd(ssl)) != clientToUserMap.end()) {
                    username = clientToUserMap[SSL_get_fd(ssl)];
                    balance = userAccounts[username].balance;
                } else {
                    SSL_write(ssl, "Please Login First\r\n", 20);
                    continue;
                }
            }

            lock_guard<mutex> lock(userMutex);
            string online_list;
            int onlineCount = 0;

            for (const auto& user : userAccounts) {
                if (user.second.login) {
                    online_list += user.first + "#" + user.second.ip + "#" + to_string(user.second.port) + "\r\n";
                    onlineCount++;
                }
            }
            string response = to_string(balance) + "\n<serverPublicKey>\r\n" + to_string(onlineCount) + "\n" + online_list;
            SSL_write(ssl, response.c_str(), response.size());
        } else if (message == "Exit") {
            string username;
            {
                lock_guard<mutex> lock(clientMapMutex);
                if (clientToUserMap.find(SSL_get_fd(ssl)) != clientToUserMap.end()) {
                    username = clientToUserMap[SSL_get_fd(ssl)];
                }
            }
            SSL_write(ssl, "Bye\r\n", 5);
            {
                lock_guard<mutex> lock(userMutex);
                if (!username.empty()) {
                    userAccounts[username].login = false;
                }
            }
            SSL_shutdown(ssl);
            SSL_free(ssl);
            break;
        } else if (pos1 != string::npos && pos2 != string::npos) {
            string sender = message.substr(0, pos1);
            int amount = stoi(message.substr(pos1 + 1, pos2 - pos1 - 1));
            string recipient = message.substr(pos2 + 1);

            lock_guard<mutex> lock(userMutex);
            if (userAccounts.find(sender) == userAccounts.end() || !userAccounts[sender].login) {
                SSL_write(ssl, "Sender not logged in.\r\n", 23);
            } else if (userAccounts.find(recipient) == userAccounts.end()) {
                SSL_write(ssl, "Recipient not found.\r\n", 23);
            } else if (userAccounts[sender].balance < amount) {
                SSL_write(ssl, "Insufficient balance.\r\n", 24);
            } else {
                userAccounts[sender].balance -= amount;
                userAccounts[recipient].balance += amount;

                string successMessage = "Transfer Successful: " + to_string(amount) +
                                        " from " + sender + " to " + recipient + ".\r\n";
                SSL_write(ssl, successMessage.c_str(), successMessage.size());
            }
        } else {
            SSL_write(ssl, "Invalid command format.\r\n", 25);
        }
    }
}

void worker(SSL_CTX* ctx) {
    while (true) {
        int clientSocket;
        {
            unique_lock<mutex> lock(queueMutex);
            condVar.wait(lock, [] { return !taskQueue.empty(); });
            clientSocket = taskQueue.front();
            taskQueue.pop();
        }

        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, clientSocket);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(clientSocket);
            SSL_free(ssl);
            continue;
        }

        handleClient(ssl);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "Usage: ./server <port>" << endl;
        return -1;
    }

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();

    server_private_key = load_private_key("server_private.pem");
    if (!server_private_key) {
        cerr << "Failed to load server private key" << endl;
        return -1;
    }

    SSL_CTX* ctx = create_server_context();
    configure_server_context(ctx);

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        cerr << "Failed to create socket." << endl;
        return -1;
    }

    sockaddr_in serverAddr = {};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(stoi(argv[1]));

    if (::bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        cerr << "Failed to bind socket." << endl;
        return -1;
    }

    listen(serverSocket, 5);
    cout << "Server activated! Waiting for connections..." << endl;
    vector<thread> threadPool;
    for (int i = 0; i < 5; ++i) {
        threadPool.emplace_back(worker, ctx);
    }

    while (true) {
        sockaddr_in clientAddr = {};
        socklen_t clientLen = sizeof(clientAddr);
        int clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientLen);
        if (clientSocket >= 0) {
            // Extract client IP and port
            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, INET_ADDRSTRLEN);
            int clientPort = ntohs(clientAddr.sin_port);

            // Output IP and port
            cout << "Client connected!" << endl;
            cout << "IP = "<< clientIP << ", Port = " << clientPort << endl;

            lock_guard<mutex> lock(queueMutex);
            taskQueue.push(clientSocket);
            condVar.notify_one();
        }
    }

    for (auto& t : threadPool) {
        t.join();
    }

    close(serverSocket);
    SSL_CTX_free(ctx);
    EVP_PKEY_free(server_private_key);

    return 0;
}
