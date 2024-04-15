mod ioctl;
pub mod sync;
#[cfg(feature = "tokio")]
pub mod tokio;

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

pub type RawBpfDirection = libc::c_uint;
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct BpfDirection(pub(crate) RawBpfDirection);

#[allow(non_upper_case_globals)]
impl BpfDirection {
  /// `BPF_D_IN`
  pub const IN: Self = Self(0);

  /// `BPF_D_INOUT`
  pub const IN_OUT: Self = Self(1);

  /// `BPF_D_OUT`
  pub const OUT: Self = Self(2);

  /// Constructs a `DataLinkLayer` from a raw integer.
  #[inline]
  pub const fn from_raw(raw: RawBpfDirection) -> Self {
    Self(raw)
  }

  /// Returns the raw integer for this `DataLinkLayer`.
  #[inline]
  pub const fn as_raw(self) -> RawBpfDirection {
    self.0
  }
}
