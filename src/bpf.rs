use rustix::{
  fd::OwnedFd,
  fs::{open, Mode, OFlags},
  io::{self, read},
};

use crate::ioctl::*;

#[repr(C)]
pub struct bpf_insn {
  pub code: u16,
  pub jt: u8,
  pub jf: u8,
  pub k: u32,
}

#[repr(C)]
pub struct bpf_program {
  pub bf_len: u32,
  pub bf_insns: *const bpf_insn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct bpf_stat {
  bs_recv: u32,
  bs_drop: u32,
}

#[macro_export]
macro_rules! bpf_filter {
  ($({ $a:literal, $b:literal, $c:literal, $d:literal }),+ $(,)?) => {
    {
      let instructions = vec![
        $(
          $crate::bpf::bpf_insn {
            code: $a,
            jt: $b,
            jf: $c,
            k: $d,
          }
        ),*,
      ];

      let program = $crate::bpf::bpf_program {
        bf_len: instructions.len() as u32,
        bf_insns: instructions.as_ptr(),
      };

      std::mem::forget(instructions);

      program
    }
  };
}

pub type RawDataLinkLayer = libc::c_uint;
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct DataLinkLayer(pub(crate) RawDataLinkLayer);

#[allow(non_upper_case_globals)]
impl DataLinkLayer {
  /// `DLT_NULL`
  pub const NULL: Self = Self(libc::DLT_NULL as _);

  /// `DLT_EN10MB`
  pub const EN10MB: Self = Self(libc::DLT_EN10MB as _);

  /// `DLT_EN3MB`
  pub const EN3MB: Self = Self(libc::DLT_EN3MB as _);

  /// `DLT_AX25`
  pub const AX25: Self = Self(libc::DLT_AX25 as _);

  /// `DLT_PRONET`
  pub const PRONET: Self = Self(libc::DLT_PRONET as _);

  /// `DLT_CHAOS`
  pub const CHAOS: Self = Self(libc::DLT_CHAOS as _);

  /// `DLT_IEEE802`
  pub const IEEE802: Self = Self(libc::DLT_IEEE802 as _);

  /// `DLT_ARCNET`
  pub const ARCNET: Self = Self(libc::DLT_ARCNET as _);

  /// `DLT_SLIP`
  pub const SLIP: Self = Self(libc::DLT_SLIP as _);

  /// `DLT_PPP`
  pub const PPP: Self = Self(libc::DLT_PPP as _);

  /// `DLT_FDDI`
  pub const FDDI: Self = Self(libc::DLT_FDDI as _);

  /// `DLT_ATM_RFC1483`
  pub const ATM_RFC148: Self = Self(libc::DLT_ATM_RFC1483 as _);

  /// `DLT_RAW`
  pub const RAW: Self = Self(libc::DLT_RAW as _);

  /// `DLT_LOOP`
  pub const LOOP: Self = Self(libc::DLT_LOOP as _);

  /// Constructs a `DataLinkLayer` from a raw integer.
  #[inline]
  pub const fn from_raw(raw: RawDataLinkLayer) -> Self {
    Self(raw)
  }

  /// Returns the raw integer for this `DataLinkLayer`.
  #[inline]
  pub const fn as_raw(self) -> RawDataLinkLayer {
    self.0
  }
}

pub fn open_device() -> io::Result<OwnedFd> {
  let mut err = io::Errno::NODEV;
  for i in 0..100 {
    let res = open(format!("/dev/bpf{i:02}"), OFlags::RDWR, Mode::empty());
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

impl BpfSocket {
  pub fn open(interface: &str, buffer_len: Option<u32>) -> io::Result<Self> {
    let fd = open_device()?;

    if let Some(buffer_len) = buffer_len {
      ioctl_biocslen(&fd, buffer_len)?;
    }

    ioctl_biocsetif(&fd, interface)?;

    Ok(Self { fd })
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
