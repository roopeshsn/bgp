#include "central_rib.h"
#include <algorithm>

using namespace std;


string CentralRIB::make_key(const Prefix& prefix) const {
    return prefix.to_string();
}

uint8_t CentralRIB::default_admin_distance(RouteProtocol protocol) {
    switch (protocol) {
        case RouteProtocol::CONNECTED: return 0;
        case RouteProtocol::STATIC:    return 1;
        case RouteProtocol::OSPF:      return 110;
        case RouteProtocol::BGP:       return 200;
    }
    return 255;
}

string CentralRIB::protocol_name(RouteProtocol protocol) {
    switch (protocol) {
        case RouteProtocol::CONNECTED: return "Connected";
        case RouteProtocol::STATIC:    return "Static";
        case RouteProtocol::OSPF:      return "OSPF";
        case RouteProtocol::BGP:       return "BGP";
    }
    return "Unknown";
}

bool CentralRIB::add_route(const Route& route) {
    string key = make_key(route.prefix);

    auto& routes = candidates[key];

    for (auto& existing : routes) {
        if (existing.protocol == route.protocol) {
            existing = route;
            reselect(key);
            return true;
        }
    }

    routes.push_back(route);
    reselect(key);
    return true;
}

void CentralRIB::withdraw_route(const Prefix& prefix, RouteProtocol protocol) {
    string key = make_key(prefix);

    auto it = candidates.find(key);
    if (it == candidates.end()) return;

    auto& routes = it->second;
    routes.erase(
        remove_if(routes.begin(), routes.end(),
            [protocol](const Route& r) { return r.protocol == protocol; }),
        routes.end()
    );

    if (routes.empty()) {
        candidates.erase(it);
        best_routes.erase(key);
    } else {
        reselect(key);
    }
}

void CentralRIB::reselect(const string& key) {
    auto it = candidates.find(key);
    if (it == candidates.end() || it->second.empty()) {
        best_routes.erase(key);
        return;
    }

    const Route* best = &it->second[0];
    for (size_t i = 1; i < it->second.size(); i++) {
        const Route& candidate = it->second[i];

        if (candidate.admin_distance < best->admin_distance) {
            best = &candidate;
        } else if (candidate.admin_distance == best->admin_distance) {
            if (candidate.metric < best->metric) {
                best = &candidate;
            }
        }
    }

    best_routes[key] = *best;
    best_routes[key].state = RouteState::PENDING;
}

vector<Route> CentralRIB::get_best_routes() const {
    vector<Route> result;
    for (auto& pair : best_routes) {
        result.push_back(pair.second);
    }
    return result;
}

vector<Route> CentralRIB::get_candidates(const Prefix& prefix) const {
    string key = make_key(prefix);
    auto it = candidates.find(key);
    if (it == candidates.end()) return {};
    return it->second;
}

vector<string> CentralRIB::get_all_prefix_keys() const {
    vector<string> keys;
    for (auto& pair : candidates) {
        keys.push_back(pair.first);
    }
    return keys;
}
