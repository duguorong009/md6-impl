#![no_std]

pub use digest::{self, Digest};

use core::fmt;
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    typenum::{U128, U224, U256, U384, U512, U64},
    HashMarker, Output,
};

#[cfg(feature = "oid")]
use digest::const_oid::{AssociatedOid, ObjectIdentifier};
#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

#[macro_use]
mod macros;
mod state;

use crate::state::MD6State;

impl_md6!(Md664Core, Md664, U64, U64, 64);
impl_md6!(Md6128Core, Md6128, U128, U64, 128);
impl_md6!(Md6224Core, Md6224, U224, U64, 224);
impl_md6!(Md6256Core, Md6256, U256, U64, 256);
impl_md6!(Md6384Core, Md6384, U384, U64, 384);
impl_md6!(Md6512Core, Md6512, U512, U64, 512);
