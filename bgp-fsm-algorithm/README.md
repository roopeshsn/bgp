# BGP FSM

## BGP FSM States

- Idle
- Connect
- Active
- OpenConfirm
- OpenSent
- Established

## Getting Started

### To compile and run:

```
g++ -std=c++17 -o bgp_fsm main.cpp fsm.cpp && ./bgp_fsm
```

#### For Testing

##### To start Gobgpd:

```
~/go/bin/gobgpd -f gobgp.toml --api-hosts :50152
```

##### Otherwise Exabgp (for testing):

```
pip3 install exabgp
exabgp exabgp.conf
```