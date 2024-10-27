## fcnet

`fcnet` is a concrete implementation of `FirecrackerNetworkOperation`s on `FirecrackerNetwork`s that is linked
into your application and works in-process. This achieves marginally better performance than introducing indirection
like `fcnetd`+`fcnetd-client`, at the cost of **requiring your application process to run as root**.
