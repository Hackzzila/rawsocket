use std::{io::ErrorKind, ops::Deref};

use rustix::fs::OFlags;
use std::io;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

use super::sync::{self, PacketIter};

pub struct BpfSocket {
  fd: AsyncFd<sync::BpfSocket>,
}

impl Deref for BpfSocket {
  type Target = sync::BpfSocket;
  fn deref(&self) -> &Self::Target {
    self.fd.get_ref()
  }
}

impl BpfSocket {
  pub fn open(interface: &str, buffer_len: Option<u32>) -> io::Result<Self> {
    Self::open_with_flags(interface, buffer_len, OFlags::RDWR | OFlags::NONBLOCK)
  }

  pub fn open_with_flags(interface: &str, buffer_len: Option<u32>, flags: OFlags) -> io::Result<Self> {
    let sock = sync::BpfSocket::open_with_flags(interface, buffer_len, flags)?;
    Ok(Self {
      fd: AsyncFd::with_interest(sock, Interest::READABLE)?,
    })
  }

  pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
    self
      .fd
      .async_io(Interest::READABLE, |fd| fd.read(buf).map_err(Into::into))
      .await
  }

  pub fn try_read(&self, buf: &mut [u8]) -> io::Result<usize> {
    self.fd.get_ref().read(buf).map_err(Into::into)
  }

  pub async fn read_iter<'a>(&self, buf: &'a mut [u8]) -> io::Result<PacketIter<'a>> {
    loop {
      let mut guard = self.fd.readable().await?;

      match guard.get_inner().read(buf) {
        Ok(size) => return Ok(PacketIter { buf: &buf[..size] }),
        Err(e) if e.kind() == ErrorKind::WouldBlock => {
          guard.clear_ready();
          continue;
        }
        Err(e) => return Err(e.into()),
      }
    }
  }

  pub fn try_read_iter<'a>(&self, buf: &'a mut [u8]) -> io::Result<PacketIter<'a>> {
    self.fd.get_ref().read_iter(buf).map_err(Into::into)
  }
}
