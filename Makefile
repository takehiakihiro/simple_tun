CXXFLAGS += -pthread
LDFLAGS += -pthread

TARGET = tcp_tun udp_tun

all: $(TARGET)

tcp_tun: tcp_tun.o
	$(CXX) $(LDFLAGS) -o $@ $^

udp_tun: udp_tun.o
	$(CXX) $(LDFLAGS) -o $@ $^

clean:
	rm -f $(TARGET) *.o
