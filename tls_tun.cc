/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.      *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2010 Davide Brini.                                                 *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/ 

#include <thread>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <cstdarg>
#include <cctype>

#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

int debug;
char *progname;

void my_err(const char *msg, ...);
void do_debug(const char *msg, ...);

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            must reserve enough space in *dev.                          *
 **************************************************************************/
int tun_alloc(char *dev, int flags)
{
  struct ifreq ifr;
  int fd, err;
  const char *clonedev = "/dev/net/tun";

  if ( (fd = open(clonedev , O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if ( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**
 */
size_t el_chop(const char *str)
{
    int i, len = strlen(str);
    for (i = len - 1; i >= 0; i--) {
        if (iscntrl(str[i])) {
            len--;
        } else {
            break;
        }
    }
    return len;
}

/**
 */
int exec_command(int *status, const char *command, char *const argv[])
{
  int ret = 0, pid, s;
  char str[BUFSIZ];
  int pipefds[2];
  FILE *cmdout;

  if (pipe(pipefds) < 0) {
    perror("pipe");
    return -1;
  }
  if ((pid = fork()) < 0) {
    perror("fork");
    close(pipefds[0]);
    close(pipefds[1]);
    return -1;
  }

  if (pid == 0) {
    if (close(STDIN_FILENO) < 0) {
      perror("close");
      exit(EXIT_FAILURE);
    }
    if (close(pipefds[0]) < 0) {
      perror("close");
      exit(EXIT_FAILURE);
    }
    if (dup2(pipefds[1], STDOUT_FILENO) < 0) {
      perror("dup2");
      exit(EXIT_FAILURE);
    }
    if (dup2(pipefds[1], STDERR_FILENO) < 0) {
      perror("dup2");
      exit(EXIT_FAILURE);
    }
    execvp(command, argv);
    exit(EXIT_FAILURE);
  }
  if (close(pipefds[1]) < 0) {
    perror("close");
    ret = -1;
  } else if ((cmdout = fdopen(pipefds[0], "r")) == NULL) {
    perror("fdopen");
    ret = -1;
  } else {
    while (fgets(str, sizeof(str), cmdout) != NULL) {
      str[el_chop(str)] = '\0';
    }
    fclose(cmdout);
  }

  if (waitpid(pid, &s, 0) < 0) {
    perror("waitpid");
    ret = -1;
  }

  if (ret == 0)
    *status = s;

  return ret;
}
 
/**
 */
int set_ip(const char *dev_name, const char *ipaddr)
{
  int status;
  const char *argv[10];

  // ip add add 10.10.10.10/24 dev tun10
  argv[0] = "ip";
  argv[1] = "address";
  argv[2] = "add";
  argv[3] = ipaddr;
  argv[4] = "dev";
  argv[5] = dev_name;
  argv[6] = NULL;

  if (exec_command(&status, "ip", (char *const *) argv) < 0) {
    return -1;
  }
  if (status != 0) {
    my_err("ip address add status is %d\n", status);
    return -1;
  }

  // ip link set tun10 up
  argv[0] = "ip";
  argv[1] = "link";
  argv[2] = "set";
  argv[3] = dev_name;
  argv[4] = "up";
  argv[5] = NULL;

  if (exec_command(&status, "ip", (char *const *) argv) < 0) {
    return -1;
  }
  if (status != 0) {
    my_err("ip link set status is %d\n", status);
    return -1;
  }

  return 0;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int tls_cread(int fd, SSL* ssl, char *buf, int n)
{
  int nread;
  fd_set rd_set;

  do {
    nread = SSL_read(ssl, buf, n);
    if (nread > 0) {
      break;
    }
    else {
      int ssl_err = SSL_get_error(ssl, nread);
      if (ssl_err == SSL_ERROR_WANT_READ) {
        do_debug("SSL_read: WANT READ !!!");
        FD_ZERO(&rd_set);
        FD_SET(fd, &rd_set);
        select(fd + 1, &rd_set, NULL, NULL, NULL);
      }
      else if (ssl_err == SSL_ERROR_WANT_WRITE) {
        do_debug("SSL_read: WANT WRITE !!!");
        FD_ZERO(&rd_set);
        FD_SET(fd, &rd_set);
        select(fd + 1, NULL, &rd_set, NULL, NULL);
      }
      else {
        my_err("SSL_read err=%d\n", ssl_err);
        return 0;
      }
    }
  } while (nread > 0);

  return nread;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n)
{
  int nread;

  if ((nread=read(fd, buf, n)) < 0) {
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int tls_cwrite(SSL* ssl, char *buf, int n)
{
  int nwrite;

  if ((nwrite=SSL_write(ssl, buf, n)) < 0){
    perror("SSL_write");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n)
{
  int nwrite;

  if ((nwrite=write(fd, buf, n)) < 0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts them into "buf".     *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int tls_read_n(int fd, SSL* ssl, char *buf, int n)
{
  int nread, left = n;

  while (left > 0) {
    if ((nread = tls_cread(fd, ssl, buf, left)) == 0) {
      return 0 ;      
    }
    else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts them into "buf".     *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n)
{
  int nread, left = n;

  while (left > 0) {
    if ((nread = cread(fd, buf, left)) == 0) {
      return 0 ;      
    }
    else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(const char *msg, ...)
{
  if (debug) {
    va_list argp;
    va_start(argp, msg);
    vfprintf(stderr, msg, argp);
    va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(const char *msg, ...)
{
  va_list argp;
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

/**
 *
 */
void tap_read(int tap_fd, int net_fd, SSL* ssl)
{
  fd_set rd_set_org;
  fd_set rd_set;
  FD_ZERO(&rd_set_org);
  FD_SET(tap_fd, &rd_set_org);
  int maxfd = tap_fd;
  unsigned long int tap2net = 0;
  uint16_t nread, nwrite, plength;
  char buffer[BUFSIZE];

  while (1) {
    int ret;
    std::memcpy(&rd_set, &rd_set_org, sizeof(rd_set_org));

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    /* data from tun/tap: just read it and write it to the network */

    nread = cread(tap_fd, buffer, BUFSIZE);

    tap2net++;
    do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

    /* write length + packet */
    plength = htons(nread);
    nwrite = tls_cwrite(ssl, (char *)&plength, sizeof(plength));
    nwrite = tls_cwrite(ssl, buffer, nread);

    do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);

    // std::this_thread::yield();
  }
}

/**
 *
 */
void net_read(int tap_fd, int net_fd, SSL* ssl)
{
  fd_set rd_set_org;
  fd_set rd_set;
  FD_ZERO(&rd_set_org);
  FD_SET(net_fd, &rd_set_org);
  int maxfd = net_fd;
  unsigned long int net2tap = 0;
  uint16_t nread, nwrite, plength;
  char buffer[BUFSIZE];

  while (1) {
    int ret;
    std::memcpy(&rd_set, &rd_set_org, sizeof(rd_set_org));

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    /* data from the network: read it, and write it to the tun/tap interface. 
     * We need to read the length first, and then the packet */

    /* Read length */      
    nread = tls_read_n(net_fd, ssl, (char *)&plength, sizeof(plength));
    if (nread == 0) {
      /* ctrl-c at the other end */
      break;
    }

    net2tap++;

    /* read packet */
    nread = tls_read_n(net_fd, ssl, buffer, ntohs(plength));
    do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

    /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
    nwrite = cwrite(tap_fd, buffer, nread);
    do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);

    // std::this_thread::yield();
  }
}

/**
 *
 */
int main(int argc, char *argv[])
{
  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  char ipaddr[128] = { 0 };
  int maxfd;
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";            /* dotted quad IP string */
  unsigned short int port = PORT;
  int sock_fd, net_fd, optval = 1;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;

  progname = argv[0];
  
  /* Check command line options */
  while ((option = getopt(argc, argv, "i:sc:p:uahdn:")) > 0) {
    switch (option) {
      case 'd':
        debug = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name,optarg, IFNAMSIZ-1);
        break;
      case 'n':
        strncpy(ipaddr, optarg, 128);
        break;
      case 's':
        cliserv = SERVER;
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(remote_ip,optarg,15);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN | IFF_ONE_QUEUE;
        break;
      case 'a':
        flags = IFF_TAP | IFF_NO_PI;
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if (argc > 0) {
    my_err("Too many options!\n");
    usage();
  }

  if (*if_name == '\0') {
    my_err("Must specify interface name!\n");
    usage();
  }
  else if(cliserv < 0) {
    my_err("Must specify client or server mode!\n");
    usage();
  }
  else if((cliserv == CLIENT)&&(*remote_ip == '\0')) {
    my_err("Must specify server address!\n");
    usage();
  }

  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name, flags)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }
  if (set_ip(if_name, ipaddr) < 0) {
    my_err("Error up to tun/tap interface %s!\n", if_name);
    exit(1);
  }
  do_debug("Successfully connected to interface %s\n", if_name);


  if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL) == 0) {
    my_err("OPENSSL_init_ssl failed");
    exit(1);
  }
  ERR_clear_error();


  if ( (sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket()");
    exit(1);
  }


  SSL_CTX *ssl_ctx = nullptr;
  if ((ssl_ctx = SSL_CTX_new(TLS_method())) == nullptr) {
    perror("SSL_CTX_new()");
    exit(1);
  }

  SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL);
  SSL_CTX_clear_options(ssl_ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1);
  SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);
  SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv3);

  // SSL_CTX_set_min_proto_version(ssl_ctx, 0);
  // SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_2_VERSION);

  if (SSL_CTX_set_cipher_list(ssl_ctx, "ALL") == 0) {
    perror("SSL_CTX_set_cipher_list()");
    exit(1);
  }

  SSL *ssl = nullptr;
  if ((ssl = SSL_new(ssl_ctx)) == NULL) {
    perror("SSL_new()");
    exit(1);
  }

  if (cliserv == CLIENT) {
    /* Client, try to connect to server */

    /* assign the destination address */
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);

    /* connection request */
    if (connect(sock_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0) {
      perror("connect()");
      exit(1);
    }

    net_fd = sock_fd;

#if 0
    int sock_opt_int = 1;
    if (setsockopt(net_fd, IPPROTO_TCP, O_NDELAY, &sock_opt_int, sizeof(sock_opt_int)) < 0) {
      perror("setsockopt(TCP_NODELAY)");
      exit(1);
    }
#endif

    do_debug("CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));
    
    if (SSL_set_fd(ssl, net_fd) == 0) {
      perror("SSL_set_fd()");
      exit(1);
    }
    if (SSL_connect(ssl) < 0) {
      perror("SSL_connect()");
      exit(1);
    }
  }
  else {
    /* Server, wait for connections */

    /* avoid EADDRINUSE error on bind() */
    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0) {
      perror("setsockopt()");
      exit(1);
    }
    
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);
    if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0) {
      perror("bind()");
      exit(1);
    }
    
    if (listen(sock_fd, 5) < 0) {
      perror("listen()");
      exit(1);
    }
    
    /* wait for connection request */
    remotelen = sizeof(remote);
    memset(&remote, 0, remotelen);
    if ((net_fd = accept(sock_fd, (struct sockaddr*)&remote, &remotelen)) < 0) {
      perror("accept()");
      exit(1);
    }

#if 0
    int sock_opt_int = 1;
    if (setsockopt(net_fd, IPPROTO_TCP, O_NDELAY, &sock_opt_int, sizeof(sock_opt_int)) < 0) {
      perror("setsockopt(TCP_NODELAY)");
      exit(1);
    }
#endif

    do_debug("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));

    if (SSL_set_fd(ssl, net_fd) == 0) {
      perror("SSL_set_fd()");
      exit(1);
    }
    if (SSL_accept(ssl) < 0) {
      perror("SSL_accept()");
      exit(1);
    }
  }

  std::thread tap_read_th(tap_read, tap_fd, net_fd, ssl);
  std::thread net_read_th(net_read, tap_fd, net_fd, ssl);
  tap_read_th.join();
  net_read_th.join();

  return(0);
}

// vim: nu ts=2 sw=2 si et :
