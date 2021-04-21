CXXFLAGS += -pthread
LDFLAGS += -pthread -lboost_system -lboost_coroutine

TARGET = tcp_tun udp_tun tls_tun dtls_tun

all: $(TARGET)

tcp_tun: tcp_tun.o
	$(CXX) -o $@ $^ $(LDFLAGS)

udp_tun: udp_tun.o
	$(CXX) -o $@ $^ $(LDFLAGS)

tls_tun: tls_tun.o
	$(CXX) -o $@ $^ $(LDFLAGS) -lssl -lcrypto

dtls_tun: dtls_tun.o
	$(CXX) -o $@ $^ $(LDFLAGS) -lssl -lcrypto

clean:
	rm -f $(TARGET) *.o
