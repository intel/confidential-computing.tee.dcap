/*
 * Copyright(c) 2011-2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "qgs_server.h"
#include "qgs_log.h"
#include <iostream>
#include <fstream>
#include <linux/vm_sockets.h>

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
        case SIGTERM:
            if (server)
            {
                reload = false;
                server->shutdown();
            }
            break;
        case SIGHUP:
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

bool createDirectoryRecursive(const std::string& path) {
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

    // Create the final directory
    if (mkdir(path.c_str(), 0700) != 0 && errno != EEXIST) {
        QGS_LOG_ERROR("Failed to create directory: %s\n", path.c_str());
        return false;
    }
    return true;
}

bool ensureSocketDirectory(const std::string& socket_file) {
    size_t last_slash = socket_file.find_last_of('/');

    if (last_slash != std::string::npos) {
        std::string dir_path = socket_file.substr(0, last_slash);
        return createDirectoryRecursive(dir_path);
    }
    return true;
}

int main(int argc, const char* argv[])
{
    bool no_daemon = false;
    bool socket_based_communication = true; // if port is not defined in config file and command line, use socket based communication
    unsigned long int port = MAX_PORT_NUMBER + 1; // accepted port range 0..65535 (0xFFFF)
    unsigned long int num_threads = 0;
    unsigned long int mode = 0;
    char *endptr = NULL;
    if (argc > 4) {
        cout << "Usage: " << argv[0] << " [--no-daemon] [-p=port_number] [-m=unix_socket_mode] [-n=number_threads]"
             << endl;
        exit(1);
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
            } else if (!mode && name.compare("socket_mode") == 0) {
                errno = 0;
                endptr = NULL;
                mode = strtoul(value, &endptr, 8);
                if (errno || strlen(endptr) || (mode > UINT_MAX)) {
                    cout << "Please input valid socket mode in "
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
        } else if (strncmp(argv[i], "-m=", 3 ) == 0) {
            if (strspn(argv[i] + 3, "0123456789") != strlen(argv[i] + 3)) {
                cout << "Please input valid socket mode" << endl;
                exit(1);
            }
            errno = 0;
            mode = strtoul(argv[i] + 3, &endptr, 8);
            if (errno || strlen(endptr) || (mode > UINT_MAX) ) {
                cout << "Please input valid socket mode" << endl;
                exit(1);
            }
            cout << "socket mode [" << oct << mode << dec << "] found in cmdline" << endl;
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
        } else {
            cout << "Usage: " << argv[0] << " [--no-daemon] [-p=port_number] [-m=unix_socket_mode] [-n=number_threads]"
                << endl;
            exit(1);
        }
    }
    if(socket_based_communication)
        QGS_LOG_INFO("Parameters after command line check: num_thread = %d, socket based comunication\n", (uint8_t)num_threads);
    else
        QGS_LOG_INFO("Parameters after command line check: num_thread = %d, port = %d (%04xh)\n", (uint8_t)num_threads, port, port);

    if (socket_based_communication) {
        cout << "Use unix socket: " << QGS_UNIX_SOCKET_FILE << endl;
    }

    if(!no_daemon && daemon(0, 0) < 0) {
        exit(1);
    }

    QGS_LOG_INIT_EX(no_daemon);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, signal_handler);
    signal(SIGTERM, signal_handler);
    QGS_LOG_INFO("Added signal handler\n");

    try {
        do {
            reload = false;
            asio::io_service io_service;
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
                if (ensureSocketDirectory(QGS_UNIX_SOCKET_FILE)) {
                    asio::local::stream_protocol::endpoint unix_ep(QGS_UNIX_SOCKET_FILE);
                    ep = unix_ep;
                } else {
                    QGS_LOG_ERROR("Access denied to create path for socket: %s\n", QGS_UNIX_SOCKET_FILE);
                    exit(1);
                }
            }
            QGS_LOG_INFO("About to create QgsServer\n");
            server = new QgsServer(io_service, ep, (uint8_t)num_threads);
            /* Allow mode to be determined by umask by default,
             * overriding only if an explicit mode is requested
             */
            if (socket_based_communication && mode != 0) {
                chmod(QGS_UNIX_SOCKET_FILE, mode);
            }
            QGS_LOG_INFO("About to start main loop\n");
            io_service.run();
            QGS_LOG_INFO("Quit main loop\n");
            QgsServer *temp_server = server;
            server = NULL;
            QGS_LOG_INFO("Deleted QgsServer object\n");
            delete temp_server;
            if (socket_based_communication) {
                unlink(QGS_UNIX_SOCKET_FILE);
                QGS_LOG_INFO("Socket file removed\n");
            }
        } while (reload == true);
    } catch (std::exception &e) {
        cerr << e.what() << endl;
        exit(1);
    }

    QGS_LOG_FINI();
    return 0;
}
