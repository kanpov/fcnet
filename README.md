## fcnet

- `fcnet-types`: Types shared between fcnet implementations.
- `fcnet`: The "standard" implementation that is linked into your binary and operates in-process at the cost of having your process be run at root to function properly.
- `fcnet-cli`: A thin CLI wrapper over the `fcnet` implementation for testing purposes and non-automated usage.
- `fcnetd`: A Unix-socket-daemon based on the `fcnet` implementation that runs as its own process, allowing the non-networking-related process to be rootless.
- `fcnetd-client`: An implementation that connects to sockets created by running `fcnetd`.
