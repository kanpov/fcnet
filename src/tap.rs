use std::future::Future;

use netns_rs::NetNs;
use tokio_tun::TunBuilder;

use crate::{netns::AsyncNetnsRun, Args};

pub async fn add_tap(args: &Args) {
    maybe_in_netns(args, || async {
        TunBuilder::new()
            .name(&args.tap_name)
            .tap(true)
            .address(args.tap_ip.address())
            .persist()
            .up()
            .try_build()
            .expect("Could not build tap device");
    })
    .await;
}

async fn maybe_in_netns<F, Fut>(args: &Args, closure: F)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    match args.netns {
        Some(ref netns) => {
            NetNs::get(netns)
                .expect("Could not get netns")
                .run_async(closure)
                .await;
        }
        None => {
            closure().await;
        }
    }
}
