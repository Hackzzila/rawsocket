use libc::{
  c_ulong, ifreq, BIOCGBLEN, BIOCGDLT, BIOCGETIF, BIOCGRTIMEOUT, BIOCGSTATS, BIOCIMMEDIATE, BIOCSBLEN, BIOCSDLT,
  BIOCSETF, BIOCSETIF, BIOCSRTIMEOUT, IFNAMSIZ,
};
use rustix::{io, ioctl};

use crate::bpf::{bpf_program, bpf_stat, DataLinkLayer, RawDataLinkLayer};

#[inline]
#[doc(alias = "BIOCSBLEN")]
pub fn ioctl_biocslen<Fd: rustix::fd::AsFd>(fd: Fd, value: u32) -> io::Result<()> {
  unsafe {
    let ctl = ioctl::Setter::<ioctl::BadOpcode<{ BIOCSBLEN }>, u32>::new(value);
    ioctl::ioctl(fd, ctl)
  }
}

#[inline]
#[doc(alias = "BIOCGBLEN")]
pub fn ioctl_biocglen<Fd: rustix::fd::AsFd>(fd: Fd) -> io::Result<u32> {
  unsafe {
    let ctl = ioctl::Getter::<ioctl::BadOpcode<{ BIOCGBLEN }>, u32>::new();
    ioctl::ioctl(fd, ctl)
  }
}

#[inline]
#[doc(alias = "BIOCSETF")]
pub fn ioctl_biocsetf<Fd: rustix::fd::AsFd>(fd: Fd, value: bpf_program) -> io::Result<()> {
  unsafe {
    let ctl = ioctl::Setter::<ioctl::BadOpcode<{ BIOCSETF }>, bpf_program>::new(value);
    ioctl::ioctl(fd, ctl)
  }
}

#[inline]
#[doc(alias = "BIOCGDLT")]
pub fn ioctl_biocgdlt<Fd: rustix::fd::AsFd>(fd: Fd) -> io::Result<DataLinkLayer> {
  unsafe {
    let ctl = ioctl::Getter::<ioctl::BadOpcode<{ BIOCGDLT }>, RawDataLinkLayer>::new();
    ioctl::ioctl(fd, ctl).map(DataLinkLayer)
  }
}

#[inline]
#[doc(alias = "BIOCSDLT")]
pub fn ioctl_biocsdlt<Fd: rustix::fd::AsFd>(fd: Fd, value: DataLinkLayer) -> io::Result<()> {
  unsafe {
    let ctl = ioctl::Setter::<ioctl::BadOpcode<{ BIOCSDLT }>, u32>::new(value.0);
    ioctl::ioctl(fd, ctl)
  }
}

#[inline]
#[doc(alias = "BIOCSETIF")]
pub fn ioctl_biocsetif<Fd: rustix::fd::AsFd>(fd: Fd, value: &str) -> io::Result<()> {
  unsafe {
    let if_name_bytes = value.as_bytes();
    if if_name_bytes.len() >= IFNAMSIZ {
      return Err(io::Errno::NODEV);
    }

    let mut ifreq = ifreq {
      ifr_name: [0; 16],
      ifr_ifru: std::mem::zeroed(),
    };

    let mut if_name_c_char_iter = if_name_bytes.iter().map(|byte| *byte as libc::c_char);
    ifreq.ifr_name[..if_name_bytes.len()].fill_with(|| if_name_c_char_iter.next().unwrap());

    let ctl = ioctl::Setter::<ioctl::BadOpcode<{ BIOCSETIF }>, ifreq>::new(ifreq);
    ioctl::ioctl(fd, ctl)
  }
}

#[inline]
#[doc(alias = "BIOCGETIF")]
pub fn ioctl_biocgetif<Fd: rustix::fd::AsFd>(fd: Fd) -> io::Result<String> {
  unsafe {
    let ctl = ioctl::Getter::<ioctl::BadOpcode<{ BIOCGETIF }>, ifreq>::new();
    let ifreq = ioctl::ioctl(fd, ctl)?;

    if let Some(nul_byte) = ifreq.ifr_name.iter().position(|char| *char == 0) {
      let name: String = ifreq.ifr_name[..nul_byte].iter().map(|v| *v as u8 as char).collect();

      Ok(name)
    } else {
      Err(io::Errno::INVAL)
    }
  }
}

#[inline]
#[doc(alias = "BIOCIMMEDIATE")]
pub fn ioctl_biocimmediate<Fd: rustix::fd::AsFd>(fd: Fd, value: bool) -> io::Result<()> {
  unsafe {
    let value = if value { 1 } else { 0 };
    let ctl = ioctl::Setter::<ioctl::BadOpcode<{ BIOCIMMEDIATE }>, u32>::new(value);
    ioctl::ioctl(fd, ctl)
  }
}

#[inline]
#[doc(alias = "BIOCPROMISC")]
pub fn ioctl_biocpromisc<Fd: rustix::fd::AsFd>(fd: Fd) -> io::Result<()> {
  unsafe {
    const BIOCPROMISC: c_ulong = 0x20004269;
    let ctl = ioctl::NoArg::<ioctl::BadOpcode<{ BIOCPROMISC }>>::new();
    ioctl::ioctl(fd, ctl)
  }
}

#[inline]
#[doc(alias = "BIOCFLUSH")]
pub fn ioctl_biocflush<Fd: rustix::fd::AsFd>(fd: Fd) -> io::Result<()> {
  unsafe {
    const BIOCFLUSH: c_ulong = 0x20004268;
    let ctl = ioctl::NoArg::<ioctl::BadOpcode<{ BIOCFLUSH }>>::new();
    ioctl::ioctl(fd, ctl)
  }
}

pub type Timeval = libc::timeval;

#[inline]
#[doc(alias = "BIOCSRTIMEOUT")]
pub fn ioctl_biocsrtimeout<Fd: rustix::fd::AsFd>(fd: Fd, value: Timeval) -> io::Result<()> {
  unsafe {
    let ctl = ioctl::Setter::<ioctl::BadOpcode<{ BIOCSRTIMEOUT }>, Timeval>::new(value);
    ioctl::ioctl(fd, ctl)
  }
}

#[inline]
#[doc(alias = "BIOCGRTIMEOUT")]
pub fn ioctl_biocgrtimeout<Fd: rustix::fd::AsFd>(fd: Fd) -> io::Result<Timeval> {
  unsafe {
    let ctl = ioctl::Getter::<ioctl::BadOpcode<{ BIOCGRTIMEOUT }>, Timeval>::new();
    ioctl::ioctl(fd, ctl)
  }
}

#[inline]
#[doc(alias = "BIOCGSTATS")]
pub fn ioctl_biocgstats<Fd: rustix::fd::AsFd>(fd: Fd) -> io::Result<bpf_stat> {
  unsafe {
    let ctl = ioctl::Getter::<ioctl::BadOpcode<{ BIOCGSTATS }>, bpf_stat>::new();
    ioctl::ioctl(fd, ctl)
  }
}
