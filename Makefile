CXXFLAGS += -pthread
LDFLAGS += -pthread -lboost_system

TARGET = tcp_tun udp_tun tls_tun dtls_tun

all: $(TARGET)

tcp_tun: tcp_tun.o
	$(CXX) $(LDFLAGS) -o $@ $^

udp_tun: udp_tun.o
	$(CXX) $(LDFLAGS) -o $@ $^

tls_tun: tls_tun.o
	$(CXX) $(LDFLAGS) -o $@ $^ -lssl -lcrypto

dtls_tun: dtls_tun.o
	$(CXX) $(LDFLAGS) -o $@ $^ -lssl -lcrypto

clean:
	rm -f $(TARGET) *.o
