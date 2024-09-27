# DHCP-communication-monitoring-tool

**Author**: Vladislav Khrisanov

*This file contains a brief description of the application and its implementation.*

# Description

Tool to get utilization statistics on DHCP server for specified pools of addresses.

The output of the program depends on the chosen mode. When it reads from a file, it prints the statistics to the standard output. If it is in live capture mode, the displayed statistics are dynamically updated as the packets are processed.

Supports untagged, 802.1Q-tagged, and double-tagged Ethernet frames. 

Refer to manual.pdf for more precise specification.

# Usage
```shell
./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [<ip-prefix> [ ... ]]
```

```shell
./dhcp-stats --help
```

# Example

#### Run:
```shell
./dhcp-stats -i eth0 192.168.1.0/24 172.16.32.0/24 192.168.0.0/22
```

#### Output:
```shell
IP-Prefix Max-hosts Allocated addresses Utilization
192.168.0.0/22 1022 123 12.04%
192.168.1.0/24 254 123 48.43%
172.16.32.0/24 254 15 5.9%
```
