# BGP Speaker

A multi-peer BGP speaker in C++ that connects to multiple BGP peers, receives and advertises routes via UPDATE messages, runs best path selection across all peers, and programs the winning routes into the kernel routing table.

## Architecture

```
                    ┌─────────────────┐
                    │   BGPSpeaker    │
                    │                 │
                    │  LocRIB         │
                    │  RouteProgrammer│
                    │  Kernel Routes  │
                    └──┬──────────┬───┘
                       │          │
              ┌────────┘          └────────┐
              │                            │
    ┌─────────┴─────────┐       ┌─────────┴─────────┐
    │  PeerSession (T1) │       │  PeerSession (T2) │
    │                   │       │                   │
    │  FSM              │       │  FSM              │
    │  TCP Socket       │       │  TCP Socket       │
    │  Adj-RIB-In       │       │  Adj-RIB-In       │
    └───────────────────┘       └───────────────────┘
              │                            │
         GoBGP Peer 1                 GoBGP Peer 2
         AS 65002                     AS 65003
```

Each peer runs its own FSM in a separate thread. A shared LocRIB collects routes from all peers, selects the best path per prefix, and programs the kernel.

## Build

```bash
# Speaker daemon
g++ -std=c++17 -pthread -o bgp_speaker main.cpp peer_session.cpp speaker.cpp update_parser.cpp update_encoder.cpp config_parser.cpp rib.cpp route_programmer.cpp

# CLI client
g++ -std=c++17 -o bgp_cli bgp_cli.cpp
```

## Configuration

The speaker reads its configuration from a file (`bgp.conf` by default, or pass a custom path as an argument).

```bash
./bgp_speaker                   # uses bgp.conf
./bgp_speaker myconfig.conf     # custom config file
```

### Config File Format

```
# bgp.conf
local_as 65001
router_id 10.0.0.1
hold_time 90

# Peers: <ip> <port> <as>
peer 127.0.0.1 1790 65002
peer 127.0.0.1 1791 65003
```

Lines starting with `#` are comments. If no config file is found, defaults are used (AS 65001, router-id 10.0.0.1, hold-time 90, no peers).

### Dynamic Peer Management

Peers can also be added and removed at runtime via the CLI:

```bash
./bgp_cli add peer 127.0.0.1 1792 65004      # start a new peer session
./bgp_cli remove peer 127.0.0.1:1792         # tear down a peer session
```

## Getting Started

### Prerequisites

Install GoBGP (used as a test peer):

```bash
go install github.com/osrg/gobgp/v3/cmd/gobgpd@latest
go install github.com/osrg/gobgp/v3/cmd/gobgp@latest
```

### Single Peer

1. Start GoBGP:

```bash
~/go/bin/gobgpd -f gobgp.toml --api-hosts :50152 &
```

2. Start the speaker:

```bash
./bgp_speaker
```

3. Add routes from GoBGP (in another terminal):

```bash
~/go/bin/gobgp -p 50152 global rib add 10.100.0.0/24 -a ipv4
~/go/bin/gobgp -p 50152 global rib add 10.100.1.0/24 -a ipv4
~/go/bin/gobgp -p 50152 global rib add 172.16.0.0/16 -a ipv4
```

4. Withdraw a route:

```bash
~/go/bin/gobgp -p 50152 global rib del 10.100.0.0/24 -a ipv4
```

5. Stop: `Ctrl+C` on the speaker. It sends CEASE to all peers and cleans up programmed routes.

### Two Peers

1. Start both GoBGP instances:

```bash
~/go/bin/gobgpd -f gobgp.toml --api-hosts :50152 &
~/go/bin/gobgpd -f gobgp2.toml --api-hosts :50153 &
```

2. Start the speaker:

```bash
./bgp_speaker
```

3. Add routes from both peers:

```bash
# Unique routes from each peer
~/go/bin/gobgp -p 50152 global rib add 10.100.0.0/24 -a ipv4
~/go/bin/gobgp -p 50153 global rib add 172.16.0.0/16 -a ipv4

# Same prefix from both peers — triggers best path selection
~/go/bin/gobgp -p 50152 global rib add 10.200.0.0/24 -a ipv4
~/go/bin/gobgp -p 50153 global rib add 10.200.0.0/24 -a ipv4
```

4. Kill one peer to see failover — the surviving peer's routes take over:

```bash
pkill -f "gobgp2.toml"
```

## CLI

The CLI is a separate binary (`bgp_cli`) that connects to the running speaker via a Unix domain socket at `/tmp/bgp_speaker.sock`. This keeps the speaker's log output separate from CLI interaction — no interleaving.

### Usage

```bash
# Terminal 1: Start the speaker (logs appear here)
./bgp_speaker

# Terminal 2: Use the CLI (clean output here)
./bgp_cli                              # interactive mode
./bgp_cli show neighbors               # single command
./bgp_cli add route 10.0.0.0/24 10.0.0.1
```

### Show Commands

| Command | Description |
|---------|-------------|
| `show neighbors` | List all peers with state, AS, type, and route count |
| `show rib` | Show Loc-RIB best routes (prefix, next-hop, peer, AS path, decisive step) |
| `show rib <peer_ip>` | Show Adj-RIB-In for a specific peer |
| `show rib local` | Show locally injected static routes |
| `show routes` | Show routes programmed in the kernel |
| `show summary` | One-line stats (peers up, routes received/best/programmed) |

### Route Management

| Command | Description |
|---------|-------------|
| `add route <prefix> <next-hop>` | Inject a static route (locally originated, weight 32768) |
| `withdraw route <prefix>` | Remove a previously injected static route |

### Peer Management

| Command | Description |
|---------|-------------|
| `add peer <ip> <port> <as>` | Add a new peer and start its session |
| `remove peer <ip>:<port>` | Remove a peer and withdraw its routes |

Static routes are locally originated with weight 32768, so they are preferred over peer-learned routes in best path selection. When a route is added or withdrawn, the speaker automatically advertises the change to all established peers via BGP UPDATE messages.

Example:

```
$ ./bgp_cli show summary
  Peers: 2/2 established  Routes: 3 received, 3 best, 3 programmed

$ ./bgp_cli show neighbors

  Neighbor          AS      Type    State               Routes
  --------          --      ----    -----               ------
  127.0.0.1:1790    65002   eBGP    Established              2
  127.0.0.1:1791    65003   eBGP    Established              1

$ ./bgp_cli add route 192.168.1.0/24 10.0.0.1
  Added static route: 192.168.1.0/24 via 10.0.0.1

$ ./bgp_cli show rib

  Prefix                Next Hop          Peer            AS Path                 Decisive Step
  ------                --------          ----            -------                 -------------
  192.168.1.0/24        10.0.0.1          local           -                       Only path

$ ./bgp_cli withdraw route 192.168.1.0/24
  Withdrawn static route: 192.168.1.0/24
```

### Control

| Command | Description |
|---------|-------------|
| `help` | Show available commands |
| `exit` | Close the CLI connection |

## Kernel Route Programming

Without `sudo`, the speaker runs in **dry-run** mode — it logs route add/delete operations but doesn't modify the kernel routing table.

With `sudo`, it programs actual kernel routes:

```bash
sudo ./bgp_speaker
```

Verify with:
- macOS: `netstat -rn`
- Linux: `ip route`

## Route Advertisement

When the LocRIB changes (from a peer UPDATE, static route injection, or peer going down), the speaker automatically advertises the changes to all established peers:

- **New/changed routes** are sent as UPDATE messages with NLRI
- **Removed routes** are sent as UPDATE messages with withdrawn prefixes
- **Split horizon** is applied — routes are not sent back to the peer they were learned from
- **AS_PATH prepend** — the speaker's own AS is prepended before advertising

To verify route advertisement:

```bash
# Inject a static route
./bgp_cli add route 192.168.1.0/24 10.0.0.1

# Check if the peer received it
~/go/bin/gobgp -p 50152 global rib
```

The speaker logs will show `SENT: UPDATE 1 prefixes` when advertising to a peer.

## Pipeline

```
Receiving:
  Peer sends UPDATE
    → PeerSession thread parses UPDATE (update_parser)
    → Logs NLRI/withdrawals
    → Calls speaker.apply_update() (mutex locked)
        → Updates this peer's Adj-RIB-In
        → Runs best path selection across ALL peers (LocRIB)
        → Diffs old vs new best routes
        → Programs kernel (add new, delete removed, update changed)
        → Advertises changes to other peers (split horizon)
    → Logs RIB summary

Advertising:
  LocRIB changes (new route, withdrawal, or next-hop change)
    → For each established peer:
        → Skip routes learned from this peer (split horizon)
        → Prepend local AS to AS_PATH
        → Encode UPDATE message (update_encoder)
        → Send via peer's TCP socket
```

## Testing you can perform

1. Start two gobgp speakers,
```bash
~/go/bin/gobgpd -f gobgp.toml --api-hosts :50152
~/go/bin/gobgpd -f gobgp2.toml --api-hosts :50153
```

2. Start bgp_speaker,
```bash
./bgp_speaker
```

3. Advertise routes from gobgp speakers:
```bash
~/go/bin/gobgp -p 50152 global rib add 10.100.0.0/24 -a ipv4
~/go/bin/gobgp -p 50153 global rib add 10.100.0.0/24 -a ipv4
```

4. Verify:
```bash
~/go/bin/gobgp global rib -p 50152
~/go/bin/gobgp global rib -p 50153
```

5. Similary advertise from bgp_speaker:
```bash
./bgp_cli add route 1.1.1.1/32 2.2.2.2
```

```bash
./bgp_cli show brib
./bgp_cli show rib
```