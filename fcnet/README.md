## fcnet

The `fcnet` crate provides core types to perform Firecracker networking within your application. In order to actually apply `fcnet` operations, you'll need an implementation of `fcnet` in a separate crate.

These implementations currently include:
- `fcnet-use-integrated`, which links the full networking code into your application process and allows you to run it without any indirection. This, however, requires your entire application process to
have `root` privileges, which is often undesirable, so in that case one should look into a different implementation.
- `fcnet-use-cli`, which spawns an auxiliary `fcnet-serve-cli` process separately, this process is escalated to `root` and performs the needed operation while your application, without `root`, waits for
it to complete execution and picks up the result.
- `fcnet-use-daemon`, which connects to a previously started `fcnet-serve-daemon` process (that runs as `root`) over a Unix or TCP/IP socket and issues the operation over that transport and receives
the result.
