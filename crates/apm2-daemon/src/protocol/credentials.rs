use std::io;
use tokio::net::UnixStream;

/// Peer credentials extracted from the Unix socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCredentials {
    /// User ID of the peer process.
    pub uid: u32,
    /// Group ID of the peer process.
    pub gid: u32,
    /// Process ID of the peer process (optional on some platforms, but usually available on Linux).
    pub pid: Option<i32>,
}

impl PeerCredentials {
    /// Extracts credentials from a Unix stream via `SO_PEERCRED`.
    pub fn from_stream(stream: &UnixStream) -> io::Result<Self> {
        let creds = stream.peer_cred()?;
        Ok(Self {
            uid: creds.uid(),
            gid: creds.gid(),
            pid: creds.pid(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream as StdUnixStream;
    use tokio::net::UnixStream as TokioUnixStream;
    use nix::unistd::{getuid, getgid};

    #[tokio::test]
    async fn test_peer_credentials_extraction() {
        let (s1, s2) = StdUnixStream::pair().unwrap();
        s1.set_nonblocking(true).unwrap();
        s2.set_nonblocking(true).unwrap();
        let ts1 = TokioUnixStream::from_std(s1).unwrap();
        let _ts2 = TokioUnixStream::from_std(s2).unwrap();

        let creds = PeerCredentials::from_stream(&ts1).expect("Failed to get credentials");
        
        // On Linux, pair sockets should have same UID/GID as current process
        let current_uid = getuid().as_raw();
        let current_gid = getgid().as_raw();
        
        assert_eq!(creds.uid, current_uid);
        assert_eq!(creds.gid, current_gid);
        // PID might vary if extracted from kernel perspective but usually current PID or None for pair?
        // Actually socketpair doesn't always populate credentials correctly on all platforms or versions
        // but typically it does. We'll assert it's present if we expect it.
        assert!(creds.pid.is_some());
    }
}
