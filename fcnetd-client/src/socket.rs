use std::{future::Future, path::Path};

pub trait Socket: Send + Sync + Sized + Unpin {
    fn connect(socket_path: &Path) -> impl Future<Output = Result<Self, std::io::Error>> + Send;

    fn write_line(&mut self, line: String) -> impl Future<Output = Result<(), std::io::Error>> + Send;

    fn read_line(&mut self) -> impl Future<Output = Result<Option<String>, std::io::Error>> + Send;
}
