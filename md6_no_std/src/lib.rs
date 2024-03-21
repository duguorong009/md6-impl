#![no_std]

pub use digest::{self, Digest};

use core::fmt;
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    consts::{U128, U224, U256, U384, U512, U64},
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

impl_md6!(Md6_64Core, Md6_64, U64, U64, 64);
impl_md6!(Md6_128Core, Md6_128, U128, U64, 128);
impl_md6!(Md6_224Core, Md6_224, U224, U64, 224);
impl_md6!(Md6_256Core, Md6_256, U256, U64, 256);
impl_md6!(Md6_384Core, Md6_384, U384, U64, 384);
impl_md6!(Md6_512Core, Md6_512, U512, U64, 512);
