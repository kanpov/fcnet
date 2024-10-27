## fcnet-types

The `fcnet-types` crate provides a stable set of configuration types for a Firecracker microVM network:

- `FirecrackerNetwork`
- `FirecrackerNetworkType`
- `FirecrackerIpStack` (IPv4, IPv6, dual-stack)
- `FirecrackerNetworkOperation` (add, delete, check)

In order to actually perform `FirecrackerNetworkOperation`s over a `FirecrackerNetwork`, you'll need a concrete
implementation that depends on `fcnet-types`:

- `fcnet` is a lib-crate that is a full implementation and is linked into your binary and functions within your
application process at the **downside of your application needing root permissions**.
- `fcnetd-client` is a lib-crate connects to a rootful process running the `fcnetd` bin-crate, which is a daemon
that wraps `fcnet` behind either a Unix or TCP/IP socket that can be connected to in order to perform requests.
