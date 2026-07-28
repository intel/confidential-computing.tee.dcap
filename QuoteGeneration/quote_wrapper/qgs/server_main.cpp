/*
 * Copyright(c) 2011-2026 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "qgs_server.h"
#include "qgs_log.h"
#include <iostream>
#include <fstream>
#include <signal.h>
#include <string.h>
#include <linux/vm_sockets.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <pwd.h>
#include <grp.h>

#define QGS_CONFIG_FILE "/etc/qgs.conf"
#define QGS_UNIX_SOCKET_FILE "/var/run/tdx-qgs/qgs.socket"
#define MAX_PORT_NUMBER 0xFFFF // accepted port range 0..65535 (0xFFFF)

using namespace std;
using namespace intel::sgx::dcap::qgs;
volatile bool reload = false;
static QgsServer* server = NULL;

void signal_handler(int sig)
{
    switch(sig)
    {
        case SIGINT:
        case SIGTERM:
            QGS_LOG_INFO("Received signal %d (%s), initiating shutdown\n",
                         sig, strsignal(sig));
            if (server)
            {
                reload = false;
                server->shutdown();
            }
            break;
        case SIGHUP:
            QGS_LOG_INFO("Received signal %d (%s), initiating reload\n",
                         sig, strsignal(sig));
            if (server)
            {
                reload = true;
                server->shutdown();
            }
            break;
        default:
            break;
    }
}

bool do_chown(const char *file_path,
              const char *user_name,
              const char *group_name)
{
    uid_t          uid;
    gid_t          gid;
    struct passwd *pwd;
    struct group  *grp;

    // POSIX allows getpwnam to return NULL either for "not found"
    // (errno unchanged) or for a system error (errno set).
    // Zero errno first so we can tell the two cases apart in the
    // error message below.
    errno = 0;
    pwd = getpwnam(user_name);
    if (pwd == NULL) {
        QGS_LOG_ERROR("Failed to get uid for user '%s': %s\n", user_name,
                      errno ? strerror(errno) : "user not found");
        return false;
    }
    uid = pwd->pw_uid;

    errno = 0;
    grp = getgrnam(group_name);
    if (grp == NULL) {
        QGS_LOG_ERROR("Failed to get gid for group '%s': %s\n", group_name,
                      errno ? strerror(errno) : "group not found");
        return false;
    }
    gid = grp->gr_gid;

    if (chown(file_path, uid, gid) == -1) {
        QGS_LOG_ERROR("Failed to chown '%s' to %s:%s: %s\n",
                      file_path, user_name, group_name, strerror(errno));
        return false;
    }
    return true;
}

// Creates every component of the socket directory path that does not
// yet exist (like mkdir -p), then enforces correct ownership and
// permissions on the final directory.
bool prepareSocketDirectory(const std::string& path) {
    if (path.empty()) {
        QGS_LOG_ERROR("prepareSocketDirectory: empty path\n");
        return false;
    }

    size_t pos = 0;
    std::string dir;

    // Skip leading slash
    if (path[0] == '/') {
        pos = 1;
    }

    while ((pos = path.find('/', pos)) != std::string::npos) {
        dir = path.substr(0, pos++);

        if (mkdir(dir.c_str(), 0755) != 0 && errno != EEXIST) {
            QGS_LOG_ERROR("Failed to create directory: %s\n", dir.c_str());
            return false;
        }
    }

    // newly_created is true only when mkdir() returns 0
    // (i.e., we just created it).
    // It is used below to decide whether chown is appropriate.
    bool newly_created = (mkdir(path.c_str(), 0755) == 0);
    if (!newly_created && errno != EEXIST) {
        QGS_LOG_ERROR("Failed to create directory: %s: %s\n", path.c_str(), strerror(errno));
        return false;
    }

    // Always stat the path:
    // - on a fresh mkdir, this is a cheap confirmation;
    // - on EEXIST, it catches the case where a non-directory
    //   (e.g., a regular file) occupies the path, which would
    //   otherwise surface as a confusing ENOTDIR from bind.
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        QGS_LOG_ERROR("Failed to stat path %s: %s\n", path.c_str(), strerror(errno));
        return false;
    }
    if (!S_ISDIR(st.st_mode)) {
        QGS_LOG_ERROR("Path exists but is not a directory: %s (mode 0%o)\n",
                      path.c_str(), st.st_mode & 0xFFF);
        return false;
    }

    // Always enforce 0755 regardless of whether the directory already existed:
    // mkdir() is subject to the process umask, and a pre-existing
    // directory may have been left with incorrect permissions.
    if (chmod(path.c_str(), 0755) != 0) {
        QGS_LOG_ERROR("Failed to chmod directory %s: %s\n",
                      path.c_str(), strerror(errno));
        return false;
    }

    // Only chown when the directory was newly created.
    // Attempting to chown a pre-existing directory owned by root
    // (e.g. created by systemd's RuntimeDirectory=) would fail
    // with EPERM unless we are running as root.
    if (newly_created && !do_chown(path.c_str(), "qgsd", "qgsd")) {
        QGS_LOG_ERROR("Failed to change ownership of directory: %s\n", path.c_str());
        return false;
    }
    return true;
}

bool ensureSocketDirectory(const std::string& socket_file) {
    size_t last_slash = socket_file.find_last_of('/');

    if (last_slash != std::string::npos) {
        std::string dir_path = socket_file.substr(0, last_slash);
        return prepareSocketDirectory(dir_path);
    }
    return true;
}

static bool apply_log_level(const char *level_str)
{
    if (!qgs_log_set_level_str(level_str)) {
        cout << "Please input valid log level (error|warn|info|debug)" << endl;
        return false;
    }
    return true;
}

void cleanupSocketFile(const std::string& socket_file)
{
    // Call unlink() directly and treat ENOENT as success — do NOT guard with
    // a prior stat()/fileExists() check.  A stat-then-unlink sequence introduces
    // a TOCTOU race: another process could create or remove the file between the
    // two calls.  Unconditional unlink() with ENOENT handling is both correct and
    // race-free: the file either goes away (success) or was already gone (ENOENT).
    if (unlink(socket_file.c_str()) == 0) {
        QGS_LOG_INFO("Socket file removed: %s\n", socket_file.c_str());
    } else if (errno != ENOENT) {
        QGS_LOG_ERROR("Failed to remove socket file %s: %s\n",
                      socket_file.c_str(), strerror(errno));
    }
}

// Checks whether a QGS process is actively listening on the Unix socket.
// This distinguishes a stale socket file (left behind after a crash)
// from a live server.
// Returns true if the socket is live or if we cannot determine
// staleness safely:
// - connect() succeeds: clearly live.
// - EACCES/EPERM: a server is listening but this process lacks
//   permission to connect; treat as live to avoid unlinking an
//   active server's socket (DoS risk).
// - ECONNREFUSED/ENOENT/ENOTSOCK: stale or missing socket, safe to unlink.
// - socket() failure or any other error: treat as live
//   (fail-safe; do not unlink).
static bool isSocketLive(const std::string& socket_file)
{
    int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        // Cannot create a probe socket (e.g. EMFILE/ENFILE).  Assuming the
        // existing socket is live to avoid incorrectly unlinking it and
        // disrupting a running QGS instance.
        QGS_LOG_ERROR("isSocketLive: socket() failed, assuming live: %s\n", strerror(errno));
        return true;
    }
    if (socket_file.size() >= sizeof(sockaddr_un::sun_path)) {
        QGS_LOG_ERROR("isSocketLive: socket path too long (%zu >= %zu), assuming live\n",
                      socket_file.size(), sizeof(sockaddr_un::sun_path));
        ::close(fd);
        return true;
    }
    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_file.c_str(), sizeof(addr.sun_path) - 1);
    bool connected = (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0);
    int connect_errno = errno;
    ::close(fd);
    if (connected)
        return true;
    // Only treat as stale when the error unambiguously indicates no listener.
    if (connect_errno == ECONNREFUSED || connect_errno == ENOENT || connect_errno == ENOTSOCK)
        return false;
    // Permission error or anything unexpected: assume live to
    // avoid unsafe unlink.
    return true;
}

int main(int argc, const char* argv[])
{
    bool no_daemon = false;

    // Default to Unix domain socket; switch to vsock only when an
    // explicit port is given in the config file or on the command line.
    bool socket_based_communication = true;

    // Accepted port range 0..65535 (0xFFFF).
    // Use sentinel: Any value above MAX_PORT_NUMBER means "no port configured".
    // This lets us distinguish port=0 (a valid, explicitly-set value)
    // from "the user never set a port at all".
    unsigned long int port = MAX_PORT_NUMBER + 1;
    unsigned long int num_threads = 0;
    string socket_file = QGS_UNIX_SOCKET_FILE;
    const mode_t socket_mode = 0660;
    char *endptr = NULL;
    // Initialise logging to stdout before argument and config-file parsing
    // so that early diagnostic messages are visible in the terminal.
    // nosyslog=true is mandatory here: daemon(3) has not been called yet,
    // so the final log destination is not yet known.  openlog() is
    // intentionally skipped; it will be called below after the fork.
    QGS_LOG_INIT_EX(true);

    // First pass: apply -l= early so that the log level is set before any
    // QGS_LOG_* call, including those emitted during config-file parsing.
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "-l=", 3) == 0) {
            if (!apply_log_level(argv[i] + 3)) exit(1);
            break;
        }
    }

    // Use the port number and number of threads from QGS_CONFIG_FILE
    // and override them with values from command line
    ifstream config_file(QGS_CONFIG_FILE);
    if (config_file.is_open()) {
        string line;
        while(getline(config_file, line)) {
            line.erase(remove_if(line.begin(), line.end(), ::isspace),
                        line.end());
            if(line.empty() || line.front() == '#' ) {
                continue;
            }
            auto delimiterPos = line.find("=");
            if (delimiterPos == std::string::npos) {
                continue;
            }

            auto name = line.substr(0, delimiterPos);
            if (name.empty()) {
                cout << "Wrong config format in " << QGS_CONFIG_FILE
                     << endl;
                exit(1);
            }

            char value[256] = {};
            strncpy(value, line.substr(delimiterPos + 1).c_str(), sizeof(value) - 1);
            value[255] = '\0';
            if (name.compare("port") == 0) {
                errno = 0;
                endptr = NULL;
                port = strtoul(value, &endptr, 10);
                if ((strlen(value) == 0) || errno || strlen(endptr) || (port > (unsigned long)MAX_PORT_NUMBER) ) {
                    cout << "Please input valid port number in "
                         << QGS_CONFIG_FILE << endl;
                    exit(1);
                }
                socket_based_communication = false;
            } else if (name.compare("number_threads") == 0) {
                errno = 0;
                endptr = NULL;
                num_threads = strtoul(value, &endptr, 10);
                if (errno || strlen(endptr) || (num_threads > 255)) {
                    cout << "Please input valid thread number[0, 255] in "
                         << QGS_CONFIG_FILE << endl;
                    exit(1);
                }
            }
            // ignore unrecognized parameters
        }
        if(socket_based_communication)
            QGS_LOG_INFO("Parameters from configuration file: num_thread = %d, socket based communication\n", (uint8_t)num_threads);
        else
            QGS_LOG_INFO("Parameters from configuration file: num_thread = %d, port = %d (%04xh)\n", (uint8_t)num_threads, port, port);
    } else {
        cout << "Failed to open config file " << QGS_CONFIG_FILE << endl;
    }

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--no-daemon") == 0) {
            cout << "--no-daemon option found, will not run as a daemon"
                 << endl;
            no_daemon = true;
            continue;
        } else if (strncmp(argv[i], "-p=", 3 ) == 0) {
            if (strspn(argv[i] + 3, "0123456789") != strlen(argv[i] + 3)) {
                cout << "Please input valid port number" << endl;
                exit(1);
            }
            errno = 0;
            port = strtoul(argv[i] + 3, &endptr, 10);
            if (errno || strlen(endptr) || (port > (unsigned long)MAX_PORT_NUMBER) ) {
                cout << "Please input valid port number" << endl;
                exit(1);
            }
            cout << "port number [" << port << "] found in cmdline" << endl;
            socket_based_communication = false;
            continue;
        } else if (strncmp(argv[i], "-n=", 3) == 0) {
            if (strspn(argv[i] + 3, "0123456789") != strlen(argv[i] + 3)) {
                cout << "Please input valid thread number" << endl;
                exit(1);
            }
            errno = 0;
            num_threads = strtoul(argv[i] + 3, &endptr, 10);
            if (errno || strlen(endptr) || (num_threads > 255)) {
                cout << "Please input valid thread number[0, 255]" << endl;
                exit(1);
            }
            cout << "thread number [" << num_threads << "] found in cmdline" << endl;
            continue;
        } else if (strncmp(argv[i], "-l=", 3) == 0) {
            if (!apply_log_level(argv[i] + 3)) exit(1);
            cout << "log level [" << argv[i] + 3 << "] found in cmdline" << endl;
            continue;
        } else {
            cout << "Usage: " << argv[0] << " [--no-daemon] [-p=port_number] [-n=number_threads] [-l=log_level]"
                << endl;
            exit(1);
        }
    }
    if(socket_based_communication)
        QGS_LOG_INFO("Parameters after command line check: num_thread = %d, socket based comunication\n", (uint8_t)num_threads);
    else
        QGS_LOG_INFO("Parameters after command line check: num_thread = %d, port = %d (%04xh)\n", (uint8_t)num_threads, port, port);

    if (socket_based_communication) {
        cout << "Use unix socket: " << socket_file << endl;
    }

    if(!no_daemon && daemon(0, 0) < 0) {
        exit(1);
    }

    // Re-initialise logging now that the daemon mode is known: route to
    // syslog in daemon mode, or keep stdout when running with --no-daemon.
    // Calling QGS_LOG_INIT_EX twice is safe: the first call above passed
    // nosyslog=true, so openlog() was never called and there is no
    // existing syslog connection to close or reopen.
    QGS_LOG_INIT_EX(no_daemon);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, signal_handler);
    if (no_daemon) {
        // Only install SIGINT handler in foreground mode.
        // It is a terminal-originated signal (Ctrl+C) that is meaningless
        // to a daemon which has no controlling terminal.
        signal(SIGINT, signal_handler);
    }
    signal(SIGTERM, signal_handler);
    QGS_LOG_INFO("Added signal handler\n");

    try {
        do {
            reload = false;
            asio::io_context io_context;
            gs::endpoint ep;
            if (!socket_based_communication) {
                struct sockaddr_vm vm_addr = {};
                vm_addr.svm_family = AF_VSOCK;
                vm_addr.svm_reserved1 = 0;
                vm_addr.svm_port = port & UINT_MAX;
                vm_addr.svm_cid = VMADDR_CID_ANY;
                asio::generic::stream_protocol::endpoint vsock_ep(&vm_addr, sizeof(vm_addr));
                ep = vsock_ep;
            } else {
                if (ensureSocketDirectory(socket_file)) {
                    if (isSocketLive(socket_file)) {
                        QGS_LOG_ERROR("Another QGS instance is already running on %s\n", socket_file.c_str());
                        exit(1);
                    }
                    cleanupSocketFile(socket_file);
                    asio::local::stream_protocol::endpoint unix_ep(socket_file);
                    ep = unix_ep;
                } else {
                    QGS_LOG_ERROR("Failed to prepare socket directory for %s\n",
                                  socket_file.c_str());
                    exit(1);
                }
            }
            QGS_LOG_INFO("About to create QgsServer\n");

            if (socket_based_communication) {
                // Set the process umask to the bitwise complement of
                // socket_mode before QgsServer constructs and binds the socket.
                // As a result, the kernel creates the socket with socket_mode
                // permissions from the very first moment it is visible in
                // the filesystem.
                // This closes the window between bind() and a post-hoc
                // chmod() where a client could connect with
                // looser-than-intended permissions.
                // The umask is restored immediately after construction so
                // other file operations in this process are unaffected.
                // Because the socket mode is pinned here and by the chmod() below, it does not depend on the umask the service manager supplies.
                // That umask is free to be far more restrictive to protect the daemon's other files.
                mode_t prev_umask = umask(~socket_mode & 0777);
                server = new QgsServer(io_context, ep, (uint8_t)num_threads);
                umask(prev_umask);
                // chmod is an extra safety net: some asynchronous I/O
                // versions or future refactors may not create the socket
                // exactly at bind time, so we enforce the mode explicitly
                // after construction as well.
                if (chmod(socket_file.c_str(), socket_mode) != 0) {
                    QGS_LOG_ERROR("Failed to set permissions on socket %s: %s\n",
                                  socket_file.c_str(), strerror(errno));
                    cleanupSocketFile(socket_file);
                    exit(1);
                }
            } else {
                server = new QgsServer(io_context, ep, (uint8_t)num_threads);
            }
            QGS_LOG_INFO("About to start main loop\n");
            io_context.run();
            QGS_LOG_INFO("Quit main loop\n");
            QgsServer *temp_server = server;
            server = NULL;
            QGS_LOG_INFO("Deleted QgsServer object\n");
            delete temp_server;
            if (socket_based_communication) {
                cleanupSocketFile(socket_file);
            }
        } while (reload == true);
    } catch (std::exception &e) {
        cerr << e.what() << endl;
        exit(1);
    }

    QGS_LOG_FINI();
    return 0;
}
