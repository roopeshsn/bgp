#ifndef ROUTE_PROGRAMMER_H
#define ROUTE_PROGRAMMER_H

#include "bgp_types.h"
#include <vector>

using namespace std;


class RouteProgrammer {
public:
    RouteProgrammer();
    ~RouteProgrammer();

    bool open();
    void close();

    ProgramResult add_route(const Route& route);
    ProgramResult delete_route(const Route& route);
    vector<Route> read_kernel_routes();

    bool is_dry_run() const;
    static string platform_name();

private:
    int sock_fd;
    int seq;
    bool dry_run;

    uint32_t ip_to_uint32(const string& ip) const;
    void fill_sockaddr_in(void* sa, uint32_t ip) const;
};

#endif
