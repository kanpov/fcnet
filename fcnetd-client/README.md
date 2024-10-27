## fcnetd-client

`fcnetd-client` is a concrete implementation that works on `fcnet-types` definitions and allows applying operations on Firecracker microVM networks.

Unlike the `fcnet` crate, which links itself into your application and requires it to run as root, `fcnetd-client` can be used rootlessly and connects
to a rootful separate `fcnetd` process.
