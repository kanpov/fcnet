/// Code originating from https://github.com/openanolis/netns-rs, was vendored in
/// to update nix crate and remove unnecessary functionality in the scope of this library.
use std::fs::File;
use std::os::unix::io::IntoRawFd;
use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};

use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{setns, unshare, CloneFlags};
use nix::unistd::gettid;

/// An error that can occur in the network namespace backend.
#[derive(Debug)]
pub enum NetNsError {
    CreateNsDirError(std::io::Error),
    CreateNsError(std::io::Error),
    OpenNsError(std::path::PathBuf, std::io::Error),
    CloseNsError(nix::Error),
    MountError(String, nix::Error),
    UnmountError(std::path::PathBuf, nix::Error),
    UnshareError(nix::Error),
    JoinThreadError(String),
    SetnsError(nix::Error),
}

impl std::error::Error for NetNsError {}

impl std::fmt::Display for NetNsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetNsError::CreateNsDirError(err) => write!(f, "Cannot create netns directory: {err}"),
            NetNsError::CreateNsError(err) => write!(f, "Cannot create netns: {err}"),
            NetNsError::OpenNsError(path, err) => write!(f, "Cannot open netns {}: {err}", path.display()),
            NetNsError::CloseNsError(err) => write!(f, "Cannot close netns: {err}"),
            NetNsError::MountError(mount, err) => write!(f, "Failed to mount {mount}: {err}"),
            NetNsError::UnmountError(path, err) => write!(f, "Failed to unmount {}: {err}", path.display()),
            NetNsError::UnshareError(err) => write!(f, "Failed to unshare: {err}"),
            NetNsError::JoinThreadError(detail) => write!(f, "Failed to join thread: {detail}"),
            NetNsError::SetnsError(err) => write!(f, "Cannot setns: {err}"),
        }
    }
}

pub trait NetNsEnvironment {
    fn persist_dir(&self) -> PathBuf;

    fn contains<P: AsRef<Path>>(&self, p: P) -> bool {
        p.as_ref().starts_with(self.persist_dir())
    }

    fn init(&self) -> Result<(), NetNsError> {
        // Create the directory for mounting network namespaces.
        // This needs to be a shared mountpoint in case it is mounted in to
        // other namespaces (containers)
        let persist_dir = self.persist_dir();
        std::fs::create_dir_all(&persist_dir).map_err(NetNsError::CreateNsDirError)?;

        // Remount the namespace directory shared. This will fail if it is not
        // already a mountpoint, so bind-mount it on to itself to "upgrade" it
        // to a mountpoint.
        let mut made_netns_persist_dir_mount: bool = false;
        while let Err(e) = mount(
            Some(""),
            &persist_dir,
            Some("none"),
            MsFlags::MS_SHARED | MsFlags::MS_REC,
            Some(""),
        ) {
            // Fail unless we need to make the mount point
            if e != nix::errno::Errno::EINVAL || made_netns_persist_dir_mount {
                return Err(NetNsError::MountError(format!("--make-rshared {}", persist_dir.display()), e));
            }
            // Recursively remount /var/persist/netns on itself. The recursive flag is
            // so that any existing netns bindmounts are carried over.
            mount(
                Some(&persist_dir),
                &persist_dir,
                Some("none"),
                MsFlags::MS_BIND | MsFlags::MS_REC,
                Some(""),
            )
            .map_err(|e| NetNsError::MountError(format!("-rbind {} to {}", persist_dir.display(), persist_dir.display()), e))?;
            made_netns_persist_dir_mount = true;
        }

        Ok(())
    }
}

#[derive(Copy, Clone, Default, Debug)]
pub struct DefaultNetNsEnvironment;

impl NetNsEnvironment for DefaultNetNsEnvironment {
    fn persist_dir(&self) -> PathBuf {
        PathBuf::from("/var/run/netns")
    }
}

#[derive(Debug)]
pub struct NetNs<E: NetNsEnvironment = DefaultNetNsEnvironment> {
    file: File,
    path: PathBuf,
    env: Option<E>,
}

impl<E: NetNsEnvironment> NetNs<E> {
    pub fn new_with_env<S: AsRef<str>>(ns_name: S, env: E) -> Result<Self, NetNsError> {
        env.init()?;

        // create an empty file at the mount point
        let ns_path = env.persist_dir().join(ns_name.as_ref());
        let _ = File::create(&ns_path).map_err(NetNsError::CreateNsError)?;
        Self::persistent(&ns_path, true).map_err(|e| {
            // Ensure the mount point is cleaned up on errors; if the namespace was successfully
            // mounted this will have no effect because the file is in-use
            std::fs::remove_file(&ns_path).ok();
            e
        })?;
        Self::get_from_env(ns_name, env)
    }

    fn persistent<P: AsRef<Path>>(ns_path: &P, new_thread: bool) -> Result<(), NetNsError> {
        if new_thread {
            let ns_path_clone = ns_path.as_ref().to_path_buf();
            let new_thread: JoinHandle<Result<(), NetNsError>> = thread::spawn(move || Self::persistent(&ns_path_clone, false));
            match new_thread.join() {
                Ok(t) => {
                    if let Err(e) = t {
                        return Err(e);
                    }
                }
                Err(e) => {
                    return Err(NetNsError::JoinThreadError(format!("{:?}", e)));
                }
            };
        } else {
            // Create a new netns for the current thread.
            unshare(CloneFlags::CLONE_NEWNET).map_err(NetNsError::UnshareError)?;
            // bind mount the netns from the current thread (from /proc) onto the mount point.
            // This persists the namespace, even when there are no threads in the ns.
            let src = get_current_thread_netns_path();
            mount(
                Some(src.as_path()),
                ns_path.as_ref(),
                Some("none"),
                MsFlags::MS_BIND,
                Some(""),
            )
            .map_err(|e| NetNsError::MountError(format!("rbind {} to {}", src.display(), ns_path.as_ref().display()), e))?;
        }

        Ok(())
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn enter(&self) -> Result<(), NetNsError> {
        setns(&self.file, CloneFlags::CLONE_NEWNET).map_err(NetNsError::SetnsError)
    }

    pub fn get_from_env<S: AsRef<str>>(ns_name: S, env: E) -> Result<Self, NetNsError> {
        let ns_path = env.persist_dir().join(ns_name.as_ref());
        let file = File::open(&ns_path).map_err(|e| NetNsError::OpenNsError(ns_path.clone(), e))?;

        Ok(Self {
            file,
            path: ns_path,
            env: Some(env),
        })
    }

    pub fn remove(self) -> Result<(), NetNsError> {
        // need close first
        nix::unistd::close(self.file.into_raw_fd()).map_err(NetNsError::CloseNsError)?;
        // Only unmount if it's been bind-mounted (don't touch namespaces in /proc...)
        if let Some(env) = &self.env {
            if env.contains(&self.path) {
                Self::umount_ns(&self.path)?;
            }
        }
        Ok(())
    }

    fn umount_ns<P: AsRef<Path>>(path: P) -> Result<(), NetNsError> {
        let path = path.as_ref();
        umount2(path, MntFlags::MNT_DETACH).map_err(|e| NetNsError::UnmountError(path.to_owned(), e))?;
        // Do not return error.
        std::fs::remove_file(path).ok();
        Ok(())
    }
}

impl NetNs {
    pub fn new<S: AsRef<str>>(ns_name: S) -> Result<Self, NetNsError> {
        Self::new_with_env(ns_name, DefaultNetNsEnvironment)
    }

    pub fn get<S: AsRef<str>>(ns_name: S) -> Result<Self, NetNsError> {
        Self::get_from_env(ns_name, DefaultNetNsEnvironment)
    }
}

#[inline(always)]
fn get_current_thread_netns_path() -> PathBuf {
    PathBuf::from(format!("/proc/self/task/{}/ns/net", gettid()))
}
