use crate::bpf::{bpf_program, bpf_stat};
use std::os::{fd::AsRawFd, unix::prelude::RawFd};

use super::{ioctl::*, DataLinkLayer};
use rustix::{
  fd::OwnedFd,
  fs::{open, Mode, OFlags},
  io::{self, read},
};

fn open_device(flags: OFlags) -> io::Result<OwnedFd> {
  let mut err = io::Errno::NODEV;
  for i in 0..100 {
    let res = open(format!("/dev/bpf{i:02}"), flags, Mode::empty());
    match res {
      Ok(x) => return Ok(x),
      Err(e) => err = e,
    }
  }

  Err(err)
}

pub struct BpfSocket {
  fd: OwnedFd,
}

impl AsRawFd for BpfSocket {
  fn as_raw_fd(&self) -> RawFd {
    self.fd.as_raw_fd()
  }
}

impl BpfSocket {
  pub fn open_with_flags(interface: &str, buffer_len: Option<u32>, flags: OFlags) -> io::Result<Self> {
    let fd = open_device(flags)?;

    if let Some(buffer_len) = buffer_len {
      ioctl_biocslen(&fd, buffer_len)?;
    }

    ioctl_biocsetif(&fd, interface)?;

    Ok(Self { fd })
  }

  pub fn open(interface: &str, buffer_len: Option<u32>) -> io::Result<Self> {
    Self::open_with_flags(interface, buffer_len, OFlags::RDWR)
  }

  pub fn get_buffer_len(&self) -> io::Result<u32> {
    ioctl_biocglen(&self.fd)
  }

  pub fn get_interface_name(&self) -> io::Result<String> {
    ioctl_biocgetif(&self.fd)
  }

  pub fn get_data_link_layer(&self) -> io::Result<DataLinkLayer> {
    ioctl_biocgdlt(&self.fd)
  }

  pub fn set_data_link_layer(&self, value: DataLinkLayer) -> io::Result<()> {
    ioctl_biocsdlt(&self.fd, value)
  }

  pub fn set_immediate(&self, value: bool) -> io::Result<()> {
    ioctl_biocimmediate(&self.fd, value)
  }

  pub fn set_promiscuous(&self) -> io::Result<()> {
    ioctl_biocpromisc(&self.fd)
  }

  pub fn set_read_filter(&self, program: bpf_program) -> io::Result<()> {
    ioctl_biocsetf(&self.fd, program)
  }

  pub fn get_read_timeout(&self) -> io::Result<Timeval> {
    ioctl_biocgrtimeout(&self.fd)
  }

  pub fn set_read_timeout(&self, value: Timeval) -> io::Result<()> {
    ioctl_biocsrtimeout(&self.fd, value)
  }

  pub fn flush(&self) -> io::Result<()> {
    ioctl_biocflush(&self.fd)
  }

  pub fn get_stats(&self) -> io::Result<bpf_stat> {
    ioctl_biocgstats(&self.fd)
  }

  pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
    read(&self.fd, buf)
  }
}
