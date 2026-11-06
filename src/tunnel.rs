//! The only inherited-descriptor boundary. Packet processing uses safe Rust.
use std::{
    io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    os::unix::net::UnixDatagram,
};

/// Duplicate and validate OpenConnect's connected AF_UNIX/SOCK_DGRAM descriptor.
///
/// The caller keeps ownership of the original. The duplicate has CLOEXEC set.
/// Nonblocking mode is shared with the original descriptor's open file description.
pub fn from_inherited_fd(fd: RawFd) -> io::Result<tokio::net::UnixDatagram> {
    if fd < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "VPNFD must be >= 3",
        ));
    }
    // SAFETY: fcntl validates the numeric descriptor. On success it returns a new,
    // independently owned descriptor; F_DUPFD_CLOEXEC requires an integer minimum.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: duplicate is a fresh descriptor from the successful fcntl above.
    let owned = unsafe { OwnedFd::from_raw_fd(duplicate) };
    let mut kind: libc::c_int = 0;
    let mut length = mem::size_of_val(&kind) as libc::socklen_t;
    // SAFETY: owned is live, and both pointers refer to writable objects with the
    // exact size expected by getsockopt(SO_TYPE). It does not retain the pointers.
    let status = unsafe {
        libc::getsockopt(
            owned.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    if kind != libc::SOCK_DGRAM {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "VPNFD must be a connected UNIX datagram socket (OpenConnect --script-tun)",
        ));
    }
    // Validate the address family before constructing the UnixDatagram wrapper.
    // SAFETY: a zeroed sockaddr_storage is valid writable storage for getsockname.
    let mut address: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut length = mem::size_of_val(&address) as libc::socklen_t;
    // SAFETY: owned is live; sockaddr_storage is sufficiently large and aligned.
    let status = unsafe {
        libc::getsockname(
            owned.as_raw_fd(),
            (&mut address as *mut libc::sockaddr_storage).cast(),
            &mut length,
        )
    };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    if address.ss_family as libc::c_int != libc::AF_UNIX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "VPNFD must use AF_UNIX, not a host network socket",
        ));
    }
    let socket = UnixDatagram::from(owned);
    socket
        .peer_addr()
        .map_err(|e| io::Error::new(e.kind(), format!("VPNFD must be connected: {e}")))?;
    socket.set_nonblocking(true)?;
    tokio::net::UnixDatagram::from_std(socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    #[tokio::test]
    async fn preserves_datagrams_and_does_not_take_original_ownership() {
        let (original, peer) = UnixDatagram::pair().unwrap();
        let tunnel = from_inherited_fd(original.as_raw_fd()).unwrap();
        peer.send(&[0x45, 1, 2, 3]).unwrap();
        peer.send(&[0x60, 4, 5]).unwrap();
        let mut data = [0; 20];
        assert_eq!(tunnel.recv(&mut data).await.unwrap(), 4);
        assert_eq!(&data[..4], &[0x45, 1, 2, 3]);
        assert_eq!(tunnel.recv(&mut data).await.unwrap(), 3);
        assert_eq!(&data[..3], &[0x60, 4, 5]);
        drop(tunnel);
        original.send(&[42]).unwrap();
        assert_eq!(peer.recv(&mut data).unwrap(), 1);
        assert_eq!(data[0], 42);
    }
    #[tokio::test]
    async fn rejects_wrong_socket_type_family_and_invalid_descriptors() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        assert!(from_inherited_fd(stream.as_raw_fd()).is_err());
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(from_inherited_fd(udp.as_raw_fd()).is_err());
        let file = std::fs::File::open("/dev/null").unwrap();
        assert!(from_inherited_fd(file.as_raw_fd()).is_err());
        assert!(from_inherited_fd(i32::MAX).is_err());
        assert!(from_inherited_fd(-1).is_err());
        assert!(from_inherited_fd(0).is_err());
    }
    #[tokio::test]
    async fn rejects_unconnected_socket() {
        let unconnected = UnixDatagram::unbound().unwrap();
        assert!(from_inherited_fd(unconnected.as_raw_fd()).is_err());
    }
    #[tokio::test]
    async fn duplicate_is_close_on_exec() {
        let (original, _peer) = UnixDatagram::pair().unwrap();
        let tunnel = from_inherited_fd(original.as_raw_fd()).unwrap();
        // SAFETY: tunnel owns this live descriptor; F_GETFD does not use a pointer.
        let flags = unsafe { libc::fcntl(tunnel.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }
}
