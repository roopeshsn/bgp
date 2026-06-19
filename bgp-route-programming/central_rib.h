#ifndef CENTRAL_RIB_H
#define CENTRAL_RIB_H

#include "bgp_types.h"
#include <vector>
#include <map>

using namespace std;


class CentralRIB {
public:
    bool add_route(const Route& route);
    void withdraw_route(const Prefix& prefix, RouteProtocol protocol);

    vector<Route> get_best_routes() const;
    vector<Route> get_candidates(const Prefix& prefix) const;
    vector<string> get_all_prefix_keys() const;

    static uint8_t default_admin_distance(RouteProtocol protocol);
    static string protocol_name(RouteProtocol protocol);

private:
    map<string, vector<Route>> candidates;
    map<string, Route> best_routes;

    string make_key(const Prefix& prefix) const;
    void reselect(const string& key);
};

#endif
