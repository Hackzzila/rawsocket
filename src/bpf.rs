#![allow(non_camel_case_types)]

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
