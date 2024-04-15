use crate::bpf::{bpf_program, bpf_stat};
use std::os::{fd::AsRawFd, unix::prelude::RawFd};

use super::{ioctl::*, BpfDirection, DataLinkLayer};
use libc::bpf_hdr;
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

  pub fn get_direction(&self) -> io::Result<BpfDirection> {
    ioctl_biocgdirection(&self.fd)
  }

  pub fn set_direction(&self, value: BpfDirection) -> io::Result<()> {
    ioctl_biocsdirection(&self.fd, value)
  }

  pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
    read(&self.fd, buf)
  }

  pub fn read_iter<'a>(&self, buf: &'a mut [u8]) -> io::Result<PacketIter<'a>> {
    let bytes = read(&self.fd, buf)?;
    Ok(PacketIter { buf: &buf[0..bytes] })
  }
}

#[derive(Debug)]
pub struct Packet<'a> {
  pub timestamp: libc::timeval32,
  pub original_length: u32,
  pub capture: &'a [u8],
}

pub struct PacketIter<'a> {
  pub(crate) buf: &'a [u8],
}

impl<'a> Iterator for PacketIter<'a> {
  type Item = Packet<'a>;
  fn next(&mut self) -> Option<Self::Item> {
    if self.buf.len() < std::mem::size_of::<bpf_hdr>() {
      return None;
    }

    let hdr: libc::bpf_hdr = unsafe { std::ptr::read(self.buf.as_ptr() as *const _) };

    if self.buf.len() < hdr.bh_caplen as _ {
      return None;
    }

    let (capture, rest) = self.buf[hdr.bh_hdrlen as _..].split_at(hdr.bh_caplen as _);

    self.buf = rest;

    Some(Packet {
      timestamp: hdr.bh_tstamp,
      original_length: hdr.bh_datalen,
      capture,
    })
  }
}
