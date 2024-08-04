use std::future::Future;

use netns_rs::NetNs;

trait AsyncNetnsRun {
    fn run_async<F, Fut>(&self, closure: F) -> impl Future<Output = ()>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ()>;
}

impl AsyncNetnsRun for NetNs {
    fn run_async<F, Fut>(&self, closure: F) -> impl Future<Output = ()>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ()>,
    {
        async move {
            let prev_netns = netns_rs::get_from_current_thread().expect("Could not get prev netns");
            self.enter().expect("Could not enter new netns");
            closure().await;
            prev_netns.enter().expect("Could not enter prev netns");
        }
    }
}
