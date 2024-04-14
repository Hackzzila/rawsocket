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

#[repr(C)]
#[derive(Debug)]
pub struct MacHeader {
  pub destination_mac: MacAddress,
  pub source_mac: MacAddress,
  pub ether_type: u16,
}
