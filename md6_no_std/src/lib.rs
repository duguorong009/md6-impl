#![no_std]

pub use digest::{self, Digest};

use core::{fmt, num::Wrapping as W};
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    typenum::{Unsigned, U16, U64},
    HashMarker, Output,
};

#[cfg(feature = "oid")]
use digest::const_oid::{AssociatedOid, ObjectIdentifier};
#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

#[macro_use]
mod macros;
mod state;


/// MD6 core hasher state
#[derive(Clone)]
pub struct Md6Core {
    state: crate::state::MD6State,
}

/// MD6 hasher state
pub type Md6 = CoreWrapper<Md6Core>;

impl HashMarker for Md6Core {}

impl BlockSizeUser for Md6Core {
    type BlockSize = U64;
}

impl BufferKindUser for Md6Core {
    type BufferKind = Eager;
}

// impl OutputSizeUser for Md6Core {
//     type OutputSize = ;
// }

impl UpdateCore for Md6Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            self.state.update(block, block.len() * 8);
        }
    }
}

// impl FixedOutputCore for Md6Core {
//     #[inline]
//     fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
//         todo!()
//     }
// }

// impl Default for Md6Core {
//     #[inline]
//     fn default() -> Self {
//         Self {
//             state: MD6State::init(d)
//         }
//     }
// }
