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
#include <functional>
#include <mutex>
#include <chrono>

#include <boost/format.hpp>
#include <boost/asio.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/windows/object_handle.hpp>
#include <boost/asio/spawn.hpp>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <cstdarg>
#include <cctype>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <Windows.h>
#include <SetupAPI.h>
#else
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <sys/wait.h>
#endif

 /* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

int debug;
char* progname;

void my_err(const char* msg, ...);
void do_debug(const char* msg, ...);

namespace asio = boost::asio;

#ifdef _WIN32

typedef int socklen_t;

std::mutex tun_lock;

char* optarg = NULL;
int optind = 1;

static int getopt(int argc, char* const argv[], const char* optstring)
{
  if ((optind >= argc) || (argv[optind][0] != '-') || (argv[optind][0] == 0)) {
    return -1;
  }

  int opt = argv[optind][1];
  const char* p = strchr(optstring, opt);

  if (p == NULL) {
    return '?';
  }
  if (p[1] == ':') {
    optind++;
    if (optind >= argc) {
      return '?';
    }
    optarg = argv[optind];
    optind++;
  }
  else {
    optind++;
  }
  return opt;
}

/**
 * デバイス情報を取得する
 */
static HDEVINFO get_device_info(void)
{
  BOOL bRet;
  HDEVINFO hDev;
  GUID ClassGUID;
  DWORD reqSize;

  // "Net"クラスのGUIDを取得する
  for (size_t loop = 0; loop < 10; loop++) {
    // 10回リトライを行い、それでも駄目ならエラーとみなす
    bRet = SetupDiClassGuidsFromNameW(L"Net", &ClassGUID, 1, &reqSize);
    if (TRUE == bRet) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  if (bRet == FALSE) {
    my_err("error occurred SetupDiClassGuidsFromNameW %d\n", GetLastError());
    return INVALID_HANDLE_VALUE;
  }

  // デバイス情報セットを取得する
  hDev = SetupDiGetClassDevsW(&ClassGUID, NULL, NULL, DIGCF_PRESENT);
  if (hDev == INVALID_HANDLE_VALUE) {
    // エラー
    my_err("error occurred SetupDiGetClassDevsW %d\n", GetLastError());
    return INVALID_HANDLE_VALUE;
  }

  return hDev;
}

/**
 * hardware idからデバイス情報を検索し、対象のデバイスに対し操作を行う
 */
static bool enum_hardware_id(const char* hwid,
  std::function< bool(HDEVINFO DeviceInfoSet, const PSP_DEVINFO_DATA DeviceInfoData) > func)
{
  HDEVINFO hDev;
  DWORD nIndex = 0;
  SP_DEVINFO_DATA DeviceInfoData;
  char buffer[256];
  DWORD reqSize, dataType;
  bool found = false;

  hDev = get_device_info();

  DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

  // デバイス情報セットの取得
  std::string target_hardware_id(hwid);
  while (SetupDiEnumDeviceInfo(hDev, nIndex, &DeviceInfoData)) {
    nIndex++;
    memset(buffer, 0, sizeof(buffer));
    BOOL bRet = SetupDiGetDeviceRegistryPropertyA(hDev, &DeviceInfoData,
      SPDRP_HARDWAREID, &dataType, (BYTE*)buffer, sizeof(buffer) - 1, &reqSize);
    if (bRet == TRUE) {
      std::string enum_hardware_id(buffer);
      do_debug("target = %s, enum hardwareid = %s\n", target_hardware_id.c_str(), enum_hardware_id.c_str());
      if (_stricmp(target_hardware_id.c_str(), enum_hardware_id.c_str()) == 0) {
        // 指定のデバイス情報発見
        do_debug("found\n");
        found = func(hDev, &DeviceInfoData);
        break;
      }
    }
  }

  if (!found) {
    do_debug("device is not found\n");
  }

  return found;
}

/**
 * レジストリの値を取得する
 */
static bool read_config_device(HDEVINFO DeviceInfoSet,
  PSP_DEVINFO_DATA DeviceInfoData, const char* pszValueName,
  char* buffer, size_t buffer_size)
{
  HKEY hKey;
  LONG lRet;
  bool bRet;
  DWORD dwSize = buffer_size;
  DWORD dwType;

  // レジストリのオープン
  hKey = SetupDiOpenDevRegKey(DeviceInfoSet, DeviceInfoData,
    DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_READ);
  if (hKey == INVALID_HANDLE_VALUE) {
    my_err("error occurred SetupDiOpenDevRegKey %d\n", GetLastError());
    return false;
  }

  // レジストリエントリのデータを取得
  lRet = RegQueryValueExA(hKey, pszValueName, 0, &dwType, (BYTE*)buffer, &dwSize);
  if (lRet == ERROR_SUCCESS) {
    bRet = true;
  }
  else {
    my_err("error occurred RegQueryValueExA %d\n", GetLastError());
    bRet = false;
  }

  // レジストリクローズ
  RegCloseKey(hKey);

  return bRet;
}

/**
 * デバイスのインスタンスIDを取得する
 */
static bool get_device_instance_id(HDEVINFO DeviceInfoSet,
  const PSP_DEVINFO_DATA DeviceInfoData, char* instance_id,
  size_t instance_id_size)
{
  // デバイスプロパティ取得
  return read_config_device(DeviceInfoSet,
    DeviceInfoData, "NetCfgInstanceId", instance_id, instance_id_size);
}

/**
 * インターフェイスの名前を取得する
 */
static bool get_interface_name(const char* instance_id,
  char* interface_name, size_t interface_name_size)
{
  HKEY hkey;
  LSTATUS status;
  bool ret = false;
  char keyname[256];

  sprintf_s(keyname, sizeof(keyname),
    "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection",
    instance_id);

  status = RegCreateKeyExA(HKEY_LOCAL_MACHINE,
    keyname, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_READ, nullptr, &hkey, nullptr);
  if (ERROR_SUCCESS != status) {
    my_err("error occurred RegCreateKeyExA %d\n", GetLastError());
    return false;
  }

  DWORD dwSize = interface_name_size - 1;
  DWORD dwType = REG_SZ;

  memset(interface_name, 0, interface_name_size);
  status = RegQueryValueExA(hkey, "Name", nullptr, &dwType, (LPBYTE)interface_name, &dwSize);
  if ((status == ERROR_SUCCESS) && (dwType == REG_SZ)) {
    ret = true;
  }
  else {
    my_err("error occurred RegQueryValueExA %d\n", GetLastError());
  }

  RegCloseKey(hkey);
  return ret;
}

static std::tuple<std::string, std::string> tun_alloc(const std::string& hardware_id)
{
  // instance id と interface nameを取得しておく
  char instanceid[256] = { 0 };
  auto ret = enum_hardware_id(hardware_id.c_str(),
    std::bind(get_device_instance_id, std::placeholders::_1, std::placeholders::_2,
      instanceid, sizeof(instanceid)));
  if (!ret) {
    // error handling
    my_err("error occurred enum_hardware_id(get_device_instance_id)\n");
    return std::make_tuple(std::string(), std::string());
  }
  std::string instance_id{ instanceid };
  do_debug("instance id=%s\n", instance_id.c_str());

  char interface_name_[256] = { 0 };
  if (!get_interface_name(instanceid, interface_name_, sizeof(interface_name_) - 1)) {
    // error handling
    my_err("error occurred get_interface_name\n");
    return std::make_tuple(std::string(), std::string());
  }
  std::string interface_name{ interface_name_ };
  do_debug("interface name=%s\n", interface_name.c_str());
  return std::make_tuple(interface_name, instance_id);
}

/**
 * アドレスを設定するためのnetshコマンド文字列を生成する
 */
static std::string generate_to_set_address_commandline(
  const std::string& address, const std::string& interface_name)
{
  std::stringstream ss;
  std::string ipstr{ "ipv4" };

  {
    auto setaddress = address;
    if (setaddress.find('/') == std::string::npos) {
      setaddress += "/32";
    }
    ss << "netsh interface " << ipstr
      << " set address \"" << interface_name << "\" static " << setaddress
      << " store=active";
  }

  return ss.str();
}

/**
 * プロセス生成
 */
static bool start_process(const std::string& commandline)
{
  do_debug("command line=[%s]\n", commandline.c_str());

  PROCESS_INFORMATION pi = {};
  STARTUPINFOA si = {};
  std::string cl(commandline);
  si.cb = sizeof(si);
  BOOL ret = CreateProcessA(nullptr, &cl[0], nullptr, nullptr,
    FALSE, NORMAL_PRIORITY_CLASS, nullptr, nullptr, &si, &pi);
  if (FALSE == ret) {
    return false;
  }
  WaitForSingleObject(pi.hProcess, INFINITE);
  return true;
}

/**
 * 非同期でコマンドラインを実行する
 */
static bool exec_proc(const std::string& commandline)
{
  return start_process(commandline);
}

/**
 * 非同期で仮想NICにアドレスなどを設定する
 */
static int set_address(const std::string& address, const std::string& interface_name)
{
  // IPv4アドレスを仮想NICに設定する
  exec_proc(generate_to_set_address_commandline(address, interface_name));
  return 0;
}

/**
 * 仮想NICをオープンする
 */
static HANDLE vnic_open(const std::string& device_name_prefix, const std::string& instance_id)
{
  // ドライバをオープン(これでインターフェイスは接続状態になる)
  char device_name[256];
  sprintf_s(device_name, sizeof(device_name),
    "\\\\.\\Global\\%s%s", device_name_prefix.c_str(), instance_id.c_str());
  do_debug("opened device name=%s\n", device_name);
  HANDLE handle = CreateFileA(device_name, GENERIC_READ | GENERIC_WRITE,
    0, 0, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, 0);
  if (INVALID_HANDLE_VALUE == handle) {
    // error handling
    my_err("error occurred CreateFileA(%s), err=%d\n", device_name, GetLastError());
    return nullptr;
  }
  do_debug("opened device\n");

  return handle;
}

#else
/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            must reserve enough space in *dev.                          *
 **************************************************************************/
static int tun_alloc(char* dev, int flags) {

  struct ifreq ifr;
  int fd, err;
  const char* clonedev = "/dev/net/tun";

  if ((fd = open(clonedev, O_RDWR)) < 0) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if ((err = ioctl(fd, TUNSETIFF, (void*)&ifr)) < 0) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**
 */
static size_t el_chop(const char* str)
{
  int i, len = strlen(str);
  for (i = len - 1; i >= 0; i--) {
    if (iscntrl(str[i])) {
      len--;
    }
    else {
      break;
    }
  }
  return len;
}

/**
 */
static int exec_command(int* status, const char* command, char* const argv[])
{
  int ret = 0, pid, s;
  char str[BUFSIZ];
  int pipefds[2];
  FILE* cmdout;

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
  }
  else if ((cmdout = fdopen(pipefds[0], "r")) == NULL) {
    perror("fdopen");
    ret = -1;
  }
  else {
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
static int set_ip(const char* dev_name, const char* ipaddr)
{
  int status;
  const char* argv[10];

  // ip add add 10.10.10.10/24 dev tun10
  argv[0] = "ip";
  argv[1] = "address";
  argv[2] = "add";
  argv[3] = ipaddr;
  argv[4] = "dev";
  argv[5] = dev_name;
  argv[6] = NULL;

  if (exec_command(&status, "ip", (char* const*)argv) < 0) {
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

  if (exec_command(&status, "ip", (char* const*)argv) < 0) {
    return -1;
  }
  if (status != 0) {
    my_err("ip link set status is %d\n", status);
    return -1;
  }

  return 0;
}
#endif

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(const char* msg, ...) {
  if (debug) {
    va_list argp;
    char buff[256] = { 0 };
    va_start(argp, msg);
    vsnprintf(buff, sizeof(buff), msg, argp);
    va_end(argp);

    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()
      );

    auto hours = std::chrono::duration_cast<std::chrono::hours>(ms).count() % 24;
    auto minutes = std::chrono::duration_cast<std::chrono::minutes>(ms).count() % 60;
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(ms).count() % 60;
    auto milliseconds = ms.count() % 1000;

    fprintf(stderr, "%02d:%02d:%02lld.%03lld %s", hours, minutes, seconds, milliseconds, buff);

    fflush(nullptr);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(const char* msg, ...) {
  va_list argp;
  char buff[256] = { 0 };
  va_start(argp, msg);
  vsnprintf(buff, sizeof(buff), msg, argp);
  va_end(argp);

  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()
    );

  auto hours = std::chrono::duration_cast<std::chrono::hours>(ms).count() % 24;
  auto minutes = std::chrono::duration_cast<std::chrono::minutes>(ms).count() % 60;
  auto seconds = std::chrono::duration_cast<std::chrono::seconds>(ms).count() % 60;
  auto milliseconds = ms.count() % 1000;

  fprintf(stderr, "%02d:%02d:%02lld.%03lld %s", hours, minutes, seconds, milliseconds, buff);

  fflush(nullptr);
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

void dump_out(const char* buffer, size_t len)
{
  if (!debug) {
    return;
  }
  size_t offset = 0;
  while (offset < len) {
    for (uint16_t i = 0; i < 16; i++) {
      uint8_t data = buffer[offset + i];
      printf("%02x ", data);	//0で埋める、2桁、16進
      if ((offset + i) >= len) {
        printf("\n");
        return;
      }
    }
    printf("\n");
    offset += 16;
  }
}

/**
 *
 */
int main(int argc, char* argv[])
{
#ifdef _WIN32
  HANDLE tap_fd;
#else
  int tap_fd;
#endif
  int option;
#ifndef _WIN32
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
#endif
  char ipaddr[128] = { 0 };
  char remote_ip[16] = "";            /* dotted quad IP string */
  unsigned short int port = PORT;
#ifdef _WIN32
#else
  int maxfd;
  int sock_fd;
  int net_fd;
#endif
  int cliserv = -1;    /* must be specified on cmd line */

#ifdef _WIN32
  {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 0), &wsaData);
  }
#endif

  progname = argv[0];

  /* Check command line options */
  while ((option = getopt(argc, argv, "i:sc:p:uahdn:")) > 0) {
    do_debug("getopt loop %c\n", option);
    switch (option) {
    case 'd':
      debug = 1;
      break;
    case 'h':
      usage();
      break;
#ifndef _WIN32
    case 'i':
      strncpy(if_name, optarg, IFNAMSIZ - 1);
      break;
#endif
    case 'n':
#ifdef _WIN32
      strncpy_s(ipaddr, sizeof(ipaddr), optarg, 128);
#else
      strncpy(ipaddr, optarg, 128);
#endif
      break;
    case 's':
      cliserv = SERVER;
      break;
    case 'c':
      cliserv = CLIENT;
#ifdef _WIN32
      strncpy_s(remote_ip, sizeof(remote_ip), optarg, 15);
#else
      strncpy(remote_ip, optarg, 15);
#endif
      break;
    case 'p':
      port = (uint16_t)atoi(optarg);
      break;
#ifndef _WIN32
    case 'u':
      flags = IFF_TUN | IFF_ONE_QUEUE;
      break;
    case 'a':
      flags = IFF_TAP | IFF_NO_PI;
      break;
#endif
    default:
      my_err("Unknown option %c\n", option);
      usage();
    }
  }

  argv += optind;
  argc -= optind;

  do_debug("analyzed option\n");

  if (argc > 0) {
    my_err("Too many options!\n");
    usage();
  }

#ifndef _WIN32
  if (*if_name == '\0') {
    my_err("Must specify interface name!\n");
    usage();
  }
  else
#endif
    if (cliserv < 0) {
      my_err("Must specify client or server mode!\n");
      usage();
    }
    else if ((cliserv == CLIENT) && (*remote_ip == '\0')) {
      my_err("Must specify server address!\n");
      usage();
    }

  asio::io_context ioc{};

#ifdef _WIN32
  auto tpl = tun_alloc("ELLanAdapter");
  auto interface_name = std::get<0>(tpl);
  auto instanceid = std::get<1>(tpl);
  if (interface_name.empty() || instanceid.empty()) {
    my_err("Error connecting to tun/tap interface\n");
    exit(1);
  }
  if (set_address(ipaddr, interface_name) < 0) {
    my_err("Error setting ipaddress to tun/tap interface\n");
    exit(1);
  }
  tap_fd = vnic_open("ELDA32", instanceid);
  if (tap_fd == nullptr) {
    my_err("Error up to tun/tap interface\n");
    exit(1);
  }
  do_debug("Successfully connected to interface %s\n", interface_name.c_str());

  asio::windows::stream_handle tap_device(ioc, tap_fd);

#else
  /* initialize tun/tap interface */
  if ((tap_fd = tun_alloc(if_name, flags)) < 0) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }
  if (set_ip(if_name, ipaddr) < 0) {
    my_err("Error up to tun/tap interface %s!\n", if_name);
    exit(1);
  }
  do_debug("Successfully connected to interface %s\n", if_name);

  asio::posix::stream_descriptor tap_device(ioc, tap_fd);
#endif

  asio::ip::udp::socket net_sock{ ioc };
  boost::system::error_code ec;
  std::array<char, 2000> buff;

  if (cliserv == CLIENT) {
    // client
    asio::spawn([&buff, &net_sock, &remote_ip, &port](asio::yield_context yield)
      {
        boost::system::error_code ec;
        net_sock.async_connect(asio::ip::udp::endpoint(asio::ip::address::from_string(remote_ip), port), yield[ec]);
        if (ec) {
          my_err("Failed to connect server %s\n", ec.message().c_str());
          exit(1);
        }
        net_sock.async_send(asio::buffer(buff, 2), yield[ec]);
        if (ec) {
          my_err("Failed to async_send(connect) server %s\n", ec.message().c_str());
          exit(1);
        }
      }
    );
  }
  else {
    // server
    asio::spawn([&buff, &ioc, &net_sock, &remote_ip, &port](asio::yield_context yield)
      {
        do_debug("start server\n");
        boost::system::error_code ec;
        asio::ip::udp::socket acceptor{ ioc, asio::ip::udp::endpoint(asio::ip::udp::v4(), port) };
        acceptor.set_option(asio::ip::udp::socket::reuse_address(true), ec);
        asio::ip::udp::endpoint remote_endpoint;
        acceptor.async_receive_from(asio::buffer(buff), remote_endpoint, yield[ec]);
        do_debug("recv from client\n");
        if (ec) {
          my_err("Failed to async_receive_from client %s\n", ec.message().c_str());
          exit(1);
        }

        do_debug("remote=%s\n", remote_endpoint.address().to_string().c_str());

        asio::ip::udp::socket client_sock{ ioc };
        client_sock.set_option(asio::ip::udp::socket::reuse_address(true), ec);
        client_sock.bind(asio::ip::udp::endpoint(asio::ip::udp::v4(), port));
        client_sock.async_connect(remote_endpoint, yield[ec]);
        net_sock = std::move(client_sock);
      }
    );
  }

  ioc.run();

  my_err("handshaked\n");

  bool finish = false;

  // start to read from tap
  asio::spawn([&finish, &buff, &net_sock, &tap_device](asio::yield_context yield)
    {
      boost::system::error_code ec{};
      uint32_t tap2net = 0;

      while (!finish) {
        auto nread = tap_device.async_read_some(asio::buffer(buff, sizeof(buff)), yield[ec]);
        do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

        auto nwrite = net_sock.async_send(asio::buffer(buff, nread), yield[ec]);
        if (ec) {
          my_err("Failed async_write(): err=%s\n", ec.message().c_str());
          finish = true;
          continue;
        }

        do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
        tap2net++;
      }

      net_sock.close(ec);
      net_sock.cancel(ec);
      tap_device.close(ec);
      tap_device.cancel(ec);
    }
  );

  // start to read from net
  asio::spawn([&finish, &buff, &net_sock, &tap_device](asio::yield_context yield)
    {
      boost::system::error_code ec{};
      uint32_t net2tap = 0;

      while (!finish) {
        auto nread = net_sock.async_receive(asio::buffer(buff), yield[ec]);
        if (ec) {
          my_err("Failed async_read(): err=%s\n", ec.message().c_str());
          finish = true;
          continue;
        }
        do_debug("NET2TAP %lu: Read %d bytes from the tap network\n", net2tap, nread);

        auto nwrite = tap_device.async_write_some(asio::buffer(buff, nread), yield[ec]);
        if (ec) {
          my_err("Failed async_write(): err=%s\n", ec.message().c_str());
          finish = true;
          continue;
        }

        do_debug("TAP2NET %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
        net2tap++;
      }

      net_sock.close(ec);
      net_sock.cancel(ec);
      tap_device.close(ec);
      tap_device.cancel(ec);
    }
  );

  asio::signal_set signals(ioc, SIGINT);
  asio::spawn([&](asio::yield_context yield)
    {
      signals.async_wait(yield[ec]);

      finish = true;
      net_sock.close(ec);
      net_sock.cancel(ec);
      tap_device.close(ec);
      tap_device.cancel(ec);
    }
  );

  ioc.run();

#ifdef _WIN32
  WSACleanup();
#endif

  return(0);
}

// vim: nu ts=2 sw=2 si et :
