#include "route_programmer.h"

#include <iostream>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>

#ifdef __APPLE__
#include <net/route.h>
#include <sys/sysctl.h>
#include <netinet/in.h>
#endif

#ifdef __linux__
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif

using namespace std;


RouteProgrammer::RouteProgrammer()
    : sock_fd(-1), seq(0), dry_run(false) {}

RouteProgrammer::~RouteProgrammer() {
    close();
}

uint32_t RouteProgrammer::ip_to_uint32(const string& ip) const {
    struct in_addr addr;
    inet_pton(AF_INET, ip.c_str(), &addr);
    return ntohl(addr.s_addr);
}

void RouteProgrammer::fill_sockaddr_in(void* sa, uint32_t ip) const {
    struct sockaddr_in* sin = (struct sockaddr_in*)sa;
    memset(sin, 0, sizeof(struct sockaddr_in));
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = htonl(ip);
#ifdef __APPLE__
    sin->sin_len = sizeof(struct sockaddr_in);
#endif
}

bool RouteProgrammer::is_dry_run() const {
    return dry_run;
}


// ===================================================================
// macOS: PF_ROUTE socket
// ===================================================================

#ifdef __APPLE__

string RouteProgrammer::platform_name() {
    return "macOS (PF_ROUTE)";
}

bool RouteProgrammer::open() {
    if (geteuid() != 0) {
        dry_run = true;
        return true;
    }

    sock_fd = socket(PF_ROUTE, SOCK_RAW, AF_INET);
    if (sock_fd < 0) {
        cerr << "  Failed to open PF_ROUTE socket: " << strerror(errno) << endl;
        return false;
    }

    return true;
}

void RouteProgrammer::close() {
    if (sock_fd >= 0) {
        ::close(sock_fd);
        sock_fd = -1;
    }
}

ProgramResult RouteProgrammer::add_route(const Route& route) {
    if (dry_run) {
        return {true, "dry-run"};
    }

    struct {
        struct rt_msghdr hdr;
        struct sockaddr_in dst;
        struct sockaddr_in gateway;
        struct sockaddr_in netmask;
    } msg;

    memset(&msg, 0, sizeof(msg));

    msg.hdr.rtm_msglen = sizeof(msg);
    msg.hdr.rtm_version = RTM_VERSION;
    msg.hdr.rtm_type = RTM_ADD;
    msg.hdr.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_STATIC;
    msg.hdr.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
    msg.hdr.rtm_pid = getpid();
    msg.hdr.rtm_seq = ++seq;

    uint32_t dst_ip = ip_to_uint32(route.prefix.network);
    uint32_t gw_ip = ip_to_uint32(route.next_hop);

    uint32_t mask = 0;
    if (route.prefix.length > 0) {
        mask = 0xFFFFFFFF << (32 - route.prefix.length);
    }

    fill_sockaddr_in(&msg.dst, dst_ip);
    fill_sockaddr_in(&msg.gateway, gw_ip);
    fill_sockaddr_in(&msg.netmask, mask);

    ssize_t n = write(sock_fd, &msg, sizeof(msg));
    if (n < 0) {
        return {false, string("RTM_ADD failed: ") + strerror(errno)};
    }

    return {true, ""};
}

ProgramResult RouteProgrammer::delete_route(const Route& route) {
    if (dry_run) {
        return {true, "dry-run"};
    }

    struct {
        struct rt_msghdr hdr;
        struct sockaddr_in dst;
        struct sockaddr_in gateway;
        struct sockaddr_in netmask;
    } msg;

    memset(&msg, 0, sizeof(msg));

    msg.hdr.rtm_msglen = sizeof(msg);
    msg.hdr.rtm_version = RTM_VERSION;
    msg.hdr.rtm_type = RTM_DELETE;
    msg.hdr.rtm_flags = RTF_UP | RTF_GATEWAY | RTF_STATIC;
    msg.hdr.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
    msg.hdr.rtm_pid = getpid();
    msg.hdr.rtm_seq = ++seq;

    uint32_t dst_ip = ip_to_uint32(route.prefix.network);
    uint32_t gw_ip = ip_to_uint32(route.next_hop);

    uint32_t mask = 0;
    if (route.prefix.length > 0) {
        mask = 0xFFFFFFFF << (32 - route.prefix.length);
    }

    fill_sockaddr_in(&msg.dst, dst_ip);
    fill_sockaddr_in(&msg.gateway, gw_ip);
    fill_sockaddr_in(&msg.netmask, mask);

    ssize_t n = write(sock_fd, &msg, sizeof(msg));
    if (n < 0) {
        return {false, string("RTM_DELETE failed: ") + strerror(errno)};
    }

    return {true, ""};
}

vector<Route> RouteProgrammer::read_kernel_routes() {
    vector<Route> routes;

    int mib[6] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0};
    size_t buf_len = 0;

    if (sysctl(mib, 6, nullptr, &buf_len, nullptr, 0) < 0) {
        return routes;
    }

    vector<char> buf(buf_len);
    if (sysctl(mib, 6, buf.data(), &buf_len, nullptr, 0) < 0) {
        return routes;
    }

    char* ptr = buf.data();
    char* end = ptr + buf_len;

    while (ptr < end) {
        struct rt_msghdr* rtm = (struct rt_msghdr*)ptr;

        if (rtm->rtm_msglen == 0) break;

        if ((rtm->rtm_flags & RTF_GATEWAY) && (rtm->rtm_flags & RTF_STATIC)) {
            struct sockaddr* sa = (struct sockaddr*)(rtm + 1);

            struct sockaddr_in* dst_sa = nullptr;
            struct sockaddr_in* gw_sa = nullptr;
            struct sockaddr_in* mask_sa = nullptr;

            for (int i = 0; i < RTAX_MAX; i++) {
                if (rtm->rtm_addrs & (1 << i)) {
                    if (sa->sa_family == AF_INET || sa->sa_len == sizeof(struct sockaddr_in)) {
                        if (i == RTAX_DST) dst_sa = (struct sockaddr_in*)sa;
                        else if (i == RTAX_GATEWAY) gw_sa = (struct sockaddr_in*)sa;
                        else if (i == RTAX_NETMASK) mask_sa = (struct sockaddr_in*)sa;
                    }
                    // Advance to next sockaddr (rounded up to long boundary)
                    sa = (struct sockaddr*)((char*)sa + ((sa->sa_len + sizeof(long) - 1) & ~(sizeof(long) - 1)));
                }
            }

            if (dst_sa && gw_sa) {
                Route route;
                char ip_buf[INET_ADDRSTRLEN];

                inet_ntop(AF_INET, &dst_sa->sin_addr, ip_buf, sizeof(ip_buf));
                route.prefix.network = ip_buf;

                // Calculate prefix length from netmask
                if (mask_sa) {
                    uint32_t mask_val = ntohl(mask_sa->sin_addr.s_addr);
                    route.prefix.length = 0;
                    while (mask_val & 0x80000000) {
                        route.prefix.length++;
                        mask_val <<= 1;
                    }
                } else {
                    route.prefix.length = 32;
                }

                inet_ntop(AF_INET, &gw_sa->sin_addr, ip_buf, sizeof(ip_buf));
                route.next_hop = ip_buf;
                route.protocol = RouteProtocol::STATIC;
                route.state = RouteState::INSTALLED;

                routes.push_back(route);
            }
        }

        ptr += rtm->rtm_msglen;
    }

    return routes;
}

#endif // __APPLE__


// ===================================================================
// Linux: Netlink socket
// ===================================================================

#ifdef __linux__

string RouteProgrammer::platform_name() {
    return "Linux (Netlink)";
}

bool RouteProgrammer::open() {
    if (geteuid() != 0) {
        dry_run = true;
        return true;
    }

    sock_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (sock_fd < 0) {
        cerr << "  Failed to open Netlink socket: " << strerror(errno) << endl;
        return false;
    }

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = getpid();

    if (bind(sock_fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        cerr << "  Failed to bind Netlink socket: " << strerror(errno) << endl;
        ::close(sock_fd);
        sock_fd = -1;
        return false;
    }

    return true;
}

void RouteProgrammer::close() {
    if (sock_fd >= 0) {
        ::close(sock_fd);
        sock_fd = -1;
    }
}

struct nl_route_msg {
    struct nlmsghdr nlh;
    struct rtmsg rtm;
    char buf[256];
};

static void add_rtattr(struct nlmsghdr* nlh, int type, const void* data, int len) {
    struct rtattr* rta = (struct rtattr*)((char*)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = RTA_LENGTH(len);
    memcpy(RTA_DATA(rta), data, len);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

ProgramResult RouteProgrammer::add_route(const Route& route) {
    if (dry_run) {
        return {true, "dry-run"};
    }

    struct nl_route_msg msg;
    memset(&msg, 0, sizeof(msg));

    msg.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    msg.nlh.nlmsg_type = RTM_NEWROUTE;
    msg.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    msg.nlh.nlmsg_seq = ++seq;
    msg.nlh.nlmsg_pid = getpid();

    msg.rtm.rtm_family = AF_INET;
    msg.rtm.rtm_dst_len = route.prefix.length;
    msg.rtm.rtm_table = RT_TABLE_MAIN;
    msg.rtm.rtm_protocol = RTPROT_STATIC;
    msg.rtm.rtm_scope = RT_SCOPE_UNIVERSE;
    msg.rtm.rtm_type = RTN_UNICAST;

    struct in_addr dst_addr, gw_addr;
    inet_pton(AF_INET, route.prefix.network.c_str(), &dst_addr);
    inet_pton(AF_INET, route.next_hop.c_str(), &gw_addr);

    add_rtattr(&msg.nlh, RTA_DST, &dst_addr, sizeof(dst_addr));
    add_rtattr(&msg.nlh, RTA_GATEWAY, &gw_addr, sizeof(gw_addr));

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    ssize_t n = sendto(sock_fd, &msg, msg.nlh.nlmsg_len, 0,
                       (struct sockaddr*)&sa, sizeof(sa));
    if (n < 0) {
        return {false, string("RTM_NEWROUTE failed: ") + strerror(errno)};
    }

    // Read ACK
    char reply[4096];
    n = recv(sock_fd, reply, sizeof(reply), 0);
    if (n > 0) {
        struct nlmsghdr* nlh = (struct nlmsghdr*)reply;
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr* err = (struct nlmsgerr*)NLMSG_DATA(nlh);
            if (err->error != 0) {
                return {false, string("RTM_NEWROUTE error: ") + strerror(-err->error)};
            }
        }
    }

    return {true, ""};
}

ProgramResult RouteProgrammer::delete_route(const Route& route) {
    if (dry_run) {
        return {true, "dry-run"};
    }

    struct nl_route_msg msg;
    memset(&msg, 0, sizeof(msg));

    msg.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    msg.nlh.nlmsg_type = RTM_DELROUTE;
    msg.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg.nlh.nlmsg_seq = ++seq;
    msg.nlh.nlmsg_pid = getpid();

    msg.rtm.rtm_family = AF_INET;
    msg.rtm.rtm_dst_len = route.prefix.length;
    msg.rtm.rtm_table = RT_TABLE_MAIN;
    msg.rtm.rtm_protocol = RTPROT_STATIC;
    msg.rtm.rtm_scope = RT_SCOPE_UNIVERSE;
    msg.rtm.rtm_type = RTN_UNICAST;

    struct in_addr dst_addr, gw_addr;
    inet_pton(AF_INET, route.prefix.network.c_str(), &dst_addr);
    inet_pton(AF_INET, route.next_hop.c_str(), &gw_addr);

    add_rtattr(&msg.nlh, RTA_DST, &dst_addr, sizeof(dst_addr));
    add_rtattr(&msg.nlh, RTA_GATEWAY, &gw_addr, sizeof(gw_addr));

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    ssize_t n = sendto(sock_fd, &msg, msg.nlh.nlmsg_len, 0,
                       (struct sockaddr*)&sa, sizeof(sa));
    if (n < 0) {
        return {false, string("RTM_DELROUTE failed: ") + strerror(errno)};
    }

    char reply[4096];
    n = recv(sock_fd, reply, sizeof(reply), 0);
    if (n > 0) {
        struct nlmsghdr* nlh = (struct nlmsghdr*)reply;
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr* err = (struct nlmsgerr*)NLMSG_DATA(nlh);
            if (err->error != 0) {
                return {false, string("RTM_DELROUTE error: ") + strerror(-err->error)};
            }
        }
    }

    return {true, ""};
}

vector<Route> RouteProgrammer::read_kernel_routes() {
    vector<Route> routes;

    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_type = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = ++seq;
    req.nlh.nlmsg_pid = getpid();
    req.rtm.rtm_family = AF_INET;
    req.rtm.rtm_table = RT_TABLE_MAIN;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    sendto(sock_fd, &req, req.nlh.nlmsg_len, 0,
           (struct sockaddr*)&sa, sizeof(sa));

    char buf[8192];
    bool done = false;

    while (!done) {
        ssize_t n = recv(sock_fd, buf, sizeof(buf), 0);
        if (n <= 0) break;

        struct nlmsghdr* nlh = (struct nlmsghdr*)buf;
        while (NLMSG_OK(nlh, n)) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                done = true;
                break;
            }

            if (nlh->nlmsg_type == RTM_NEWROUTE) {
                struct rtmsg* rtm = (struct rtmsg*)NLMSG_DATA(nlh);

                if (rtm->rtm_protocol == RTPROT_STATIC && rtm->rtm_table == RT_TABLE_MAIN) {
                    struct rtattr* rta = RTM_RTA(rtm);
                    int rta_len = RTM_PAYLOAD(nlh);

                    Route route;
                    route.prefix.length = rtm->rtm_dst_len;
                    route.protocol = RouteProtocol::STATIC;
                    route.state = RouteState::INSTALLED;
                    bool has_dst = false;
                    bool has_gw = false;

                    while (RTA_OK(rta, rta_len)) {
                        char ip_buf[INET_ADDRSTRLEN];

                        if (rta->rta_type == RTA_DST) {
                            inet_ntop(AF_INET, RTA_DATA(rta), ip_buf, sizeof(ip_buf));
                            route.prefix.network = ip_buf;
                            has_dst = true;
                        } else if (rta->rta_type == RTA_GATEWAY) {
                            inet_ntop(AF_INET, RTA_DATA(rta), ip_buf, sizeof(ip_buf));
                            route.next_hop = ip_buf;
                            has_gw = true;
                        }

                        rta = RTA_NEXT(rta, rta_len);
                    }

                    if (has_dst && has_gw) {
                        routes.push_back(route);
                    }
                }
            }

            nlh = NLMSG_NEXT(nlh, n);
        }
    }

    return routes;
}

#endif // __linux__
