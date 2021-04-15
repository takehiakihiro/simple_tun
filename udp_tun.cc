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

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

int debug;
char *progname;

void my_err(const char *msg, ...);

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            must reserve enough space in *dev.                          *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;
  const char *clonedev = "/dev/net/tun";

  if( (fd = open(clonedev , O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
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
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n)) < 0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n)) < 0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts them into "buf".     *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left)) == 0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(const char *msg, ...){
  if(debug) {
    va_list argp;
    va_start(argp, msg);
    vfprintf(stderr, msg, argp);
    va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(const char *msg, ...) {
  va_list argp;
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
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
void tap_read(int tap_fd, int net_fd) {
  fd_set rd_set_org;
  fd_set rd_set;
  FD_ZERO(&rd_set_org);
  FD_SET(tap_fd, &rd_set_org);
  int maxfd = tap_fd;
  unsigned long int tap2net = 0;
  uint16_t nread, nwrite, plength;
  char buffer[BUFSIZE];

  while(1) {
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
    nwrite = cwrite(net_fd, (char *)&plength, sizeof(plength));
    nwrite = cwrite(net_fd, buffer, nread);
    
    do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);

    // std::this_thread::yield();
  }
}

/**
 *
 */
void net_read(int tap_fd, int net_fd) {
  fd_set rd_set_org;
  fd_set rd_set;
  FD_ZERO(&rd_set_org);
  FD_SET(net_fd, &rd_set_org);
  int maxfd = net_fd;
  unsigned long int net2tap = 0;
  uint16_t nread, nwrite, plength;
  char buffer[BUFSIZE];

  while(1) {
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
    nread = read_n(net_fd, (char *)&plength, sizeof(plength));
    if(nread == 0) {
      /* ctrl-c at the other end */
      break;
    }

    net2tap++;

    /* read packet */
    nread = read_n(net_fd, buffer, ntohs(plength));
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
int accept_handle(int cfd, struct sockaddr_in *local, struct sockaddr_in *remote)
{
  socklen_t remote_len;
  char buff[128];
  int fd;
  int err;
  const int on = 1, off = 0;

  remote_len = sizeof(*remote);
  err = recvfrom(cfd, buff, sizeof(buff), 0, (struct sockaddr *)remote, &remote_len);
  if (err < 0) {
    goto out;
  }

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    goto out;
  }

  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*)&on, (socklen_t)sizeof(on));

  err = bind(fd, (struct sockaddr *)local, sizeof(*local));
  if (err != 0) {
    goto out;
  }

  err = connect(fd, (struct sockaddr *)remote, remote_len);
  if (err != 0) {
    goto out;
  }

  return fd;

out:
  printf("%s(): error occurred errno=%d\n", __func__, errno);
  return -1;
}


/**
 *
 */
int main(int argc, char *argv[]) {
  
  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  char ipaddr[128] = { 0 };
  int maxfd;
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";            /* dotted quad IP string */
  unsigned short int port = PORT;
  int sock_fd, net_fd;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;
  const int on = 1;

  progname = argv[0];
  
  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uahdn:")) > 0) {
    switch(option) {
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
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0) {
    my_err("Too many options!\n");
    usage();
  }

  if(*if_name == '\0') {
    my_err("Must specify interface name!\n");
    usage();
  } else if(cliserv < 0) {
    my_err("Must specify client or server mode!\n");
    usage();
  } else if((cliserv == CLIENT)&&(*remote_ip == '\0')) {
    my_err("Must specify server address!\n");
    usage();
  }

  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }
  if (set_ip(if_name, ipaddr) < 0) {
    my_err("Error up to tun/tap interface %s!\n", if_name);
    exit(1);
  }
  do_debug("Successfully connected to interface %s\n", if_name);

  sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock_fd < 0) {
    perror("socket()");
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
    do_debug("CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));
    
  }
  else {
    /* Server, wait for connections */

    /* avoid EADDRINUSE error on bind() */
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, (socklen_t)sizeof(on)) < 0) {
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

    /* wait for connection request */
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sock_fd, &rfds);
    int err = select(sock_fd + 1, &rfds, NULL, NULL, NULL);
    if (err < 0) {
      perror("select()");
      exit(1);
    }

    memset(&remote, 0, sizeof(remote));
    net_fd = accept_handle(sock_fd, &local, &remote);
    if (net_fd < 0) {
      perror("accept_handle()");
      exit(1);
    }

    do_debug("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));
  }
  
  std::thread tap_read_th(tap_read, tap_fd, net_fd);
  std::thread net_read_th(net_read, tap_fd, net_fd);
  tap_read_th.join();
  net_read_th.join();

  return(0);
}

// vim: nu ts=2 sw=2 si et :