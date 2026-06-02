# PMTU Probe

To compile and run:

```
g++ -std=c++17 -o pmtu_probe main.cpp pmtu_probe.cpp
```

```
./pmtu_probe <target_ip> [max_mtu]
```

For Mac:

```
cp pmtu_probe /tmp/ && /tmp/pmtu_probe <target>
```