// BGP CLI Client
//
// Connects to the running BGP speaker via Unix socket
// and sends commands interactively or as one-shot.
//
// Build:
//   g++ -std=c++17 -o bgp_cli bgp_cli.cpp
//
// Usage:
//   bgp_cli                         (interactive mode)
//   bgp_cli show neighbors          (single command)
//   bgp_cli add route 10.0.0.0/24 10.0.0.1

#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

using namespace std;

const string SOCKET_PATH = "/tmp/bgp_speaker.sock";

int connect_to_speaker() {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        cerr << "Failed to create socket" << endl;
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        cerr << "Cannot connect to BGP speaker at " << SOCKET_PATH << endl;
        cerr << "Is the speaker running?" << endl;
        close(fd);
        return -1;
    }

    return fd;
}

string send_command(int fd, const string& cmd) {
    string msg = cmd + "\n";
    send(fd, msg.c_str(), msg.size(), 0);

    string response;
    char buf[4096];

    while (true) {
        ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        buf[n] = '\0';
        response += buf;

        if (response.size() >= 2 &&
            response[response.size() - 1] == '\n' &&
            response[response.size() - 2] == '\n') {
            break;
        }
    }

    return response;
}

void interactive_mode() {
    int fd = connect_to_speaker();
    if (fd < 0) return;

    string line;
    while (true) {
        cout << "bgp> " << flush;
        if (!getline(cin, line)) break;

        // Trim
        size_t start = line.find_first_not_of(" \t");
        if (start == string::npos) continue;
        line = line.substr(start);
        size_t end = line.find_last_not_of(" \t");
        if (end != string::npos) line = line.substr(0, end + 1);

        if (line.empty()) continue;

        if (line == "exit" || line == "quit") {
            send_command(fd, "exit");
            break;
        }

        string response = send_command(fd, line);
        cout << response;
    }

    close(fd);
}

void single_command(const string& cmd) {
    int fd = connect_to_speaker();
    if (fd < 0) return;

    string response = send_command(fd, cmd);
    cout << response;

    close(fd);
}

int main(int argc, char* argv[]) {
    if (argc == 1) {
        interactive_mode();
    } else {
        string cmd;
        for (int i = 1; i < argc; i++) {
            if (i > 1) cmd += " ";
            cmd += argv[i];
        }
        single_command(cmd);
    }

    return 0;
}
