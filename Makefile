CXXFLAGS += -pthread
LDFLAGS += -pthread

all: tcp_tun

tcp_tun: tcp_tun.o
	${CXX} ${LDFLAGS} -o tcp_tun tcp_tun.o

clean:
	rm -f tcp_tun *.o
