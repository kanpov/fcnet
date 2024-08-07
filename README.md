## fcnet

`fcnet` is a simple and automatable CLI tool aimed at setting up and tearing down Firecracker microVM networks. `fcnet` has 3 operations you can invoke via appropriate CLI flags:

- `--add` (`-A`) to create the given network configuration
- `--del` (`-D`) to tear down the given network configuration
- `--check` (`-C`) to check whether the given network configuration was set up correctly

`fcnet` aims to have sane defaults (for example, defaulting to IPs used by the Ubuntu 22.04 rootfs used in Firecracker CI) and, as such, working with it is easy. Two types of networks are supported:

- `simple`, making a tap device in the default netns and connecting it to the Internet (performant, recommended for most use cases)
- `netns`, making a netns with a veth pair and a tap device inside, by default connecting to the guest will be possible only in the netns, or you can use `--forwarded-guest-ip` flag to expose the guest IP in the default netns (requires more rules, but is better for clones and snapshotting)

Examples:

1. Create a simple network with defaults, assuming `wlp1s0` is the name of your host network interface (Wi-Fi card or Ethernet port):
`fcnet --iface wlp1s0 --add simple` (analogously with `--check` and `--del`)

2. Create a netns network without guest IP forwarding and guest having IP `172.16.0.2`, assuming `wlp1s0` is the name of your host network interface:
`fcnet --iface wlp1s0 --add netns --guest-ip 172.16.0.2`

3. Create a netns network with the guest IP `172.16.0.2` being accessible at `192.168.0.3` on the default netns:
`fcnet --iface wlp1s0 --add netns --guest-ip 172.16.0.2 --forwarded-guest-ip 192.168.0.3`
