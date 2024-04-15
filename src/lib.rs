use std::fmt::Debug;
use std::fmt::Display;

pub mod bpf;
#[cfg(any(
  doc,
  target_os = "macos",
  target_os = "freebsd",
  target_os = "dragonfly",
  target_os = "openbsd",
  target_os = "netbsd",
))]
pub mod bsd;

// macro_rules! syscall {
//     ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
//         let res = unsafe { libc::$fn($($arg, )*) };
//         if res < 0 {
//             Err(std::io::Error::last_os_error())
//         } else {
//             Ok(res)
//         }
//     }};
// }

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct MacAddress(pub [u8; 6]);

impl Display for MacAddress {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
      self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
    )
  }
}

impl Debug for MacAddress {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    Display::fmt(self, f)
  }
}

#[derive(Debug)]
#[repr(C)]
pub struct EthernetHeader {
  pub destination_mac: MacAddress,
  pub source_mac: MacAddress,
  pub ether_type: u16,
}

impl EthernetHeader {
  pub fn try_decode(buf: &[u8]) -> Option<Self> {
    if buf.len() < std::mem::size_of::<Self>() {
      None
    } else {
      unsafe { Some(std::ptr::read(buf.as_ptr() as *const _)) }
    }
  }
}

#[derive(Debug)]
pub struct EthernetPacket<'a> {
  pub header: EthernetHeader,
  pub payload: &'a [u8],
}

impl<'a> EthernetPacket<'a> {
  pub fn try_decode(buf: &'a [u8]) -> Option<Self> {
    let header = EthernetHeader::try_decode(buf)?;
    let payload = &buf[std::mem::size_of::<EthernetHeader>()..];

    Some(Self { header, payload })
  }
}
