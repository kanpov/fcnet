## `fcnet-serve-cli`

`fcnet-serve-cli` is a `clap` CLI utility that wraps the `fcnet-use-integrated` implementation of `fcnet` inside a separate CLI process.

To use this, you need the `fcnet-use-cli` implementation which requires a compiled `fcnet-serve-cli` binary that it spawns and awaits.
