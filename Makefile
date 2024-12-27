CXX       = g++
CXXFLAGS  = -Wall -O2 -std=c++14
# 如果你在 macOS 上使用 Homebrew 的 openssl@3，需指定 include 路徑及 lib 路徑
# 可依實際情況調整
OPENSSL_INC = /opt/homebrew/opt/openssl@3/include
OPENSSL_LIB = /opt/homebrew/opt/openssl@3/lib

INCLUDES  = -I$(OPENSSL_INC)
LDFLAGS   = -L$(OPENSSL_LIB) -lssl -lcrypto -lpthread

# 產生兩個執行檔：server、client
SERVER_TARGET = server
CLIENT_TARGET = client

# 只包含 server.cpp 和 client.cpp
SERVER_SRCS   = server.cpp
CLIENT_SRCS   = client.cpp

SERVER_OBJS   = $(SERVER_SRCS:.cpp=.o)
CLIENT_OBJS   = $(CLIENT_SRCS:.cpp=.o)

all: $(SERVER_TARGET) $(CLIENT_TARGET)

# 編譯 server
$(SERVER_TARGET): $(SERVER_OBJS)
	$(CXX) $(CXXFLAGS) $(SERVER_OBJS) $(LDFLAGS) -o $@

# 編譯 client
$(CLIENT_TARGET): $(CLIENT_OBJS)
	$(CXX) $(CXXFLAGS) $(CLIENT_OBJS) $(LDFLAGS) -o $@

# 自動將 .cpp 編譯為 .o
%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(SERVER_OBJS) $(CLIENT_OBJS) $(SERVER_TARGET) $(CLIENT_TARGET)
