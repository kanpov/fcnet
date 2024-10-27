## fcnetd

`fcnetd` is a binary daemon that runs as root and receives I/O connections by listening asynchronously on a Unix socket with Tokio.
While `fcnetd` runs as root, the socket is `chown()`-ed to a rootless user so that a rootless application process can connect to
`fcnetd`, thus proxying its networking needs into a separate process without running the whole application as `root`.

Examples:
- `fcnetd /tmp/fcnetd.sock` - listen on `/tmp/fcnetd.sock` and make available only to `root`.
- `fcnetd --uid 1000 --gid 100 /tmp/fcnetd.sock` - listen on `/tmp/fcnetd.sock` and make available to UID 1000 and GID 100.
- `fcnetd --password abcde --uid 1000 /tmp/fcnetd.sock` - listen on `/tmp/fcnetd.sock` accessible by UID 1000, additionally authenticate connections with the `abcde` password.
